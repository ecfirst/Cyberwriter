"""Ephemeral "Scan Processing" workspace.

Runs the same Nexpose XML and Burp XML processing a project workbook does, but without
a project: results live in the Django cache (Redis in production and local dev) under a
per-browser-session token with a TTL, and nothing is written to the database. The only
disk write is the raw Nexpose XML parked on the shared media volume while the Django-Q
worker parses it (see ``process_scan_processing_upload`` in ``rolodex/tasks.py``), which
the worker deletes when it finishes.

Everything here reuses the pure parser/metric builders in ``data_parsers`` and the
workbook derivation in ``workbook_metrics``; nothing in ``build_project_artifacts`` or
``Project.rebuild_data_artifacts`` is touched.
"""

from __future__ import annotations

# Standard Libraries
import base64
import copy
import datetime
import logging
import os
import secrets
import uuid
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Django Imports
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.utils import timezone

# Ghostwriter Libraries
from ghostwriter.rolodex.data_parsers import (
    _build_nexpose_metrics_payload,
    _build_web_metrics_payload,
    load_vulnerability_matrix,
    load_web_issue_matrix,
    parse_burp_xml_report,
    parse_nexpose_xml_report,
)
from ghostwriter.rolodex.workbook_defaults import WORKBOOK_DEFAULTS
from ghostwriter.rolodex.workbook_metrics import (
    derive_nexpose_workbook_section,
    derive_web_workbook_section,
    safe_int,
)

logger = logging.getLogger(__name__)

SCAN_PROCESSING_TTL = 60 * 60 * 24
SESSION_TOKEN_KEY = "scan_processing_token"
CACHE_PREFIX = "scan_processing"

SLOT_NEXPOSE = "nexpose"
SLOT_WEB = "web"
SLOTS = (SLOT_NEXPOSE, SLOT_WEB)

UPLOAD_FIELD_NEXPOSE = "nexpose_xml"
UPLOAD_FIELD_BURP = "burp_xml"
UPLOAD_FIELD_SLOTS = {UPLOAD_FIELD_NEXPOSE: SLOT_NEXPOSE, UPLOAD_FIELD_BURP: SLOT_WEB}
SLOT_UPLOAD_FIELDS = {slot: field for field, slot in UPLOAD_FIELD_SLOTS.items()}

# Mirrors the project's data_artifacts keys so ``summarize_nexpose_matrix_gaps`` and
# ``summarize_web_issue_matrix_gaps`` (data_parsers.py) work on the assembled view.
NEXPOSE_ARTIFACT_KEY = "external_nexpose_findings"
NEXPOSE_METRICS_KEY = "external_nexpose_metrics"
NEXPOSE_FILE_NAME_KEY = "external_nexpose_file_name"
WEB_METRICS_KEY = "web_metrics"
WEB_FILE_NAME_KEY = "burp_xml_file_name"

NEXPOSE_DEFAULT_XLSX_FILENAME = "nexpose_data.xlsx"
WEB_DEFAULT_XLSX_FILENAME = "burp_data.xlsx"

TEMP_UPLOAD_DIR = "scan_processing"
STALE_UPLOAD_MAX_AGE = datetime.timedelta(hours=6)

# Copy of ``_DROP_DUPLICATE_ISSUE_LISTS`` in Project.rebuild_data_artifacts (models.py):
# the per-finding lists duplicate ``unique_issues`` and only bloat storage.
_TRIMMED_METRICS_KEYS = (
    "all_issues",
    "high_issues",
    "med_issues",
    "low_issues",
    "majority_unique",
    "majority_subset",
)

_NEXPOSE_MISSING_COLUMNS = (
    "Vulnerability",
    "Action Required",
    "Remediation Impact",
    "Vulnerability Threat",
    "Category",
    "CVE",
)


# ---------------------------------------------------------------------------
# Cache keys and session token
# ---------------------------------------------------------------------------


def _meta_key(token: str) -> str:
    return f"{CACHE_PREFIX}:{token}"


def _result_key(token: str, slot: str) -> str:
    return f"{CACHE_PREFIX}:{token}:{slot}"


def _xlsx_key(token: str, slot: str) -> str:
    return f"{CACHE_PREFIX}:{token}:{slot}:xlsx"


def _processing_key(token: str, slot: str) -> str:
    return f"{CACHE_PREFIX}:{token}:{slot}:processing"


def _error_key(token: str, slot: str) -> str:
    return f"{CACHE_PREFIX}:{token}:{slot}:error"


def new_token(request) -> str:
    """Create a fresh workspace token for ``request.user`` and store it in the session."""
    token = secrets.token_urlsafe(24)
    cache.set(
        _meta_key(token),
        {
            "owner_id": request.user.pk,
            "owner_username": request.user.get_username(),
            "created_at": timezone.now().isoformat(),
        },
        SCAN_PROCESSING_TTL,
    )
    request.session[SESSION_TOKEN_KEY] = token
    return token


def get_or_create_token(request) -> str:
    """Return the caller's workspace token, rotating it when it is missing or foreign."""
    token = request.session.get(SESSION_TOKEN_KEY)
    if token:
        meta = cache.get(_meta_key(token))
        if isinstance(meta, dict) and meta.get("owner_id") == request.user.pk:
            return token
    return new_token(request)


def clear_workspace(request) -> str:
    """Delete every cached value for the current workspace and start a new one."""
    old_token = request.session.get(SESSION_TOKEN_KEY)
    if old_token:
        delete_all(old_token)
    return new_token(request)


def touch_meta(token: str) -> None:
    """Extend the workspace TTL so the meta record outlives its slot results."""
    cache.touch(_meta_key(token), SCAN_PROCESSING_TTL)


# ---------------------------------------------------------------------------
# Store API
# ---------------------------------------------------------------------------


def set_processing(
    token: str, slot: str, *, filename: str, task_id: Optional[str] = None
) -> None:
    marker = cache.get(_processing_key(token, slot))
    marker = dict(marker) if isinstance(marker, dict) else {}
    marker.setdefault("started", timezone.now().isoformat())
    marker["filename"] = filename
    if task_id is not None:
        marker["task_id"] = task_id
    cache.set(_processing_key(token, slot), marker, SCAN_PROCESSING_TTL)
    touch_meta(token)


def clear_processing(token: str, slot: str) -> None:
    cache.delete(_processing_key(token, slot))


def get_processing_uploads(token: str) -> Dict[str, Dict[str, Any]]:
    """Return active processing markers keyed by upload field (project-shaped)."""
    processing: Dict[str, Dict[str, Any]] = {}
    for slot in SLOTS:
        marker = cache.get(_processing_key(token, slot))
        if isinstance(marker, dict):
            processing[SLOT_UPLOAD_FIELDS[slot]] = marker
    return processing


def set_last_error(token: str, slot: str, message: str) -> None:
    cache.set(_error_key(token, slot), {"message": message}, SCAN_PROCESSING_TTL)


def get_errors(token: str) -> Dict[str, str]:
    """Return the last error message per upload field."""
    errors: Dict[str, str] = {}
    for slot in SLOTS:
        payload = cache.get(_error_key(token, slot))
        if isinstance(payload, dict) and payload.get("message"):
            errors[SLOT_UPLOAD_FIELDS[slot]] = str(payload["message"])
    return errors


def write_result(
    token: str, slot: str, payload: Mapping[str, Any], xlsx_bytes: Optional[bytes]
) -> bool:
    """Store a slot result and its workbook bytes.

    Returns ``False`` when the result cannot be read back, which is how a silently
    failed ``set`` (production's ``IGNORE_EXCEPTIONS`` Redis option) surfaces.
    """
    cache.set(_result_key(token, slot), dict(payload), SCAN_PROCESSING_TTL)
    if xlsx_bytes:
        cache.set(_xlsx_key(token, slot), bytes(xlsx_bytes), SCAN_PROCESSING_TTL)
    else:
        cache.delete(_xlsx_key(token, slot))
    cache.delete(_error_key(token, slot))
    touch_meta(token)
    return cache.get(_result_key(token, slot)) is not None


def read_result(token: str, slot: str) -> Optional[Dict[str, Any]]:
    payload = cache.get(_result_key(token, slot))
    return payload if isinstance(payload, dict) else None


def read_xlsx(token: str, slot: str) -> Optional[bytes]:
    payload = cache.get(_xlsx_key(token, slot))
    return payload if isinstance(payload, (bytes, bytearray)) else None


def delete_result(token: str, slot: str) -> None:
    cache.delete_many(
        [
            _result_key(token, slot),
            _xlsx_key(token, slot),
            _processing_key(token, slot),
            _error_key(token, slot),
        ]
    )


def delete_all(token: str) -> None:
    for slot in SLOTS:
        delete_result(token, slot)
    cache.delete(_meta_key(token))


# ---------------------------------------------------------------------------
# Temporary upload files (shared media volume, worker-side cleanup)
# ---------------------------------------------------------------------------


def save_temp_upload(upload) -> str:
    """Stream an uploaded file to the shared media volume and return its storage path."""
    requested = f"{TEMP_UPLOAD_DIR}/{uuid.uuid4().hex}.xml"
    return default_storage.save(requested, upload)


def delete_temp_upload(storage_path: Optional[str]) -> None:
    if not storage_path:
        return
    try:
        default_storage.delete(storage_path)
    except OSError:  # pragma: no cover - defensive, nothing useful to do
        logger.warning("Could not delete Scan Processing upload %s", storage_path, exc_info=True)


def cleanup_stale_uploads(max_age: datetime.timedelta = STALE_UPLOAD_MAX_AGE) -> int:
    """Delete parked uploads older than ``max_age`` (a worker that crashed before its
    ``finally`` block never deletes its file). Returns the number removed."""
    try:
        _directories, files = default_storage.listdir(TEMP_UPLOAD_DIR)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return 0
    cutoff = timezone.now() - max_age
    removed = 0
    for name in files:
        path = f"{TEMP_UPLOAD_DIR}/{name}"
        try:
            modified = default_storage.get_modified_time(path)
        except (OSError, NotImplementedError):
            continue
        if timezone.is_naive(modified):
            modified = timezone.make_aware(modified)
        if modified < cutoff:
            delete_temp_upload(path)
            removed += 1
    return removed


# ---------------------------------------------------------------------------
# Processing pipeline
# ---------------------------------------------------------------------------


def _finalize_metrics(
    metrics: Dict[str, Any], xlsx_bytes: Optional[bytes], default_filename: str
) -> None:
    """Trim bloat (after the workbook section has been derived) and record the XLSX ref."""
    for key in _TRIMMED_METRICS_KEYS:
        metrics.pop(key, None)
    metrics.pop("_xlsx_temp_path", None)
    metrics.pop("xlsx_base64", None)
    if xlsx_bytes:
        metrics["xlsx"] = {
            "filename": metrics.get("xlsx_filename") or default_filename,
            "byte_size": len(xlsx_bytes),
            "generated_at": timezone.now().isoformat(),
        }


def _consume_nexpose_workbook(metrics: Dict[str, Any]) -> Optional[bytes]:
    """Read and remove the temp XLSX ``_build_nexpose_metrics_payload`` hands off."""
    temp_path = metrics.pop("_xlsx_temp_path", None)
    if not temp_path:
        return None
    try:
        with open(temp_path, "rb") as handle:
            return handle.read()
    except OSError:
        logger.warning("Generated Nexpose workbook %s could not be read", temp_path, exc_info=True)
        return None
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def _normalize_nexpose_missing_entries(rows: Any) -> List[Dict[str, str]]:
    """Dedupe and order missing matrix rows exactly like ``build_project_artifacts``."""
    tracker: Dict[str, Dict[str, str]] = {}
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            title = (row.get("Vulnerability") or "").strip()
            if not title:
                continue
            entry = {column: row.get(column, "") for column in _NEXPOSE_MISSING_COLUMNS}
            entry["Vulnerability"] = title
            tracker[title.lower()] = entry
    return sorted(tracker.values(), key=lambda row: (row.get("Vulnerability") or "").lower())


def _normalize_web_missing_entries(rows: Any) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            issue = (row.get("issue") or "").strip()
            if not issue:
                continue
            entries.append(
                {"issue": issue, "impact": row.get("impact", ""), "fix": row.get("fix", "")}
            )
    return entries


def _summary_total(metrics: Mapping[str, Any]) -> int:
    summary = metrics.get("summary")
    if not isinstance(summary, dict):
        return 0
    return safe_int(summary.get("total"))


def process_nexpose_upload(
    file_obj, *, vulnerability_matrix: Optional[Dict[str, Dict[str, str]]] = None
) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Parse a Nexpose XML file and return ``(slot payload, xlsx bytes)``."""
    matrix = vulnerability_matrix if vulnerability_matrix is not None else load_vulnerability_matrix()
    parsed = parse_nexpose_xml_report(file_obj, vulnerability_matrix=matrix)
    parsed = parsed if isinstance(parsed, dict) else {}
    findings = parsed.get("findings")
    findings = findings if isinstance(findings, list) else []
    missing = _normalize_nexpose_missing_entries(parsed.get("missing_matrix_entries"))

    metrics = _build_nexpose_metrics_payload(findings)
    xlsx_bytes = _consume_nexpose_workbook(metrics)
    workbook = derive_nexpose_workbook_section(
        metrics, copy.deepcopy(WORKBOOK_DEFAULTS["external_nexpose"])
    )
    _finalize_metrics(metrics, xlsx_bytes, NEXPOSE_DEFAULT_XLSX_FILENAME)

    payload = {
        "metrics": metrics,
        "missing_matrix_entries": missing,
        "workbook": workbook,
        "total_findings": _summary_total(metrics),
    }
    return payload, xlsx_bytes


def process_burp_upload(
    file_obj, *, web_issue_matrix: Optional[Dict[str, Dict[str, str]]] = None
) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Parse a Burp XML file and return ``(slot payload, xlsx bytes)``.

    Deliberately skips ``_build_web_summary_from_findings`` (the project's OpenAI
    call-site) and the CAP builder: the page shows metrics, the workbook, and the
    missing-matrix list only.
    """
    matrix = web_issue_matrix if web_issue_matrix is not None else load_web_issue_matrix()
    parsed = parse_burp_xml_report(file_obj, matrix)
    # parse_burp_xml_report returns [] (not a dict) on malformed XML.
    parsed = parsed if isinstance(parsed, dict) else {}
    findings = parsed.get("findings")
    findings = findings if isinstance(findings, list) else []
    missing = _normalize_web_missing_entries(parsed.get("missing_matrix_entries"))

    metrics = _build_web_metrics_payload(findings)
    metrics = metrics if isinstance(metrics, dict) else {}
    xlsx_bytes: Optional[bytes] = None
    encoded = metrics.pop("xlsx_base64", None)
    if isinstance(encoded, str) and encoded:
        try:
            xlsx_bytes = base64.b64decode(encoded)
        except (ValueError, TypeError):  # pragma: no cover - builder output is trusted
            xlsx_bytes = None
    workbook = derive_web_workbook_section(metrics, copy.deepcopy(WORKBOOK_DEFAULTS["web"]))
    _finalize_metrics(metrics, xlsx_bytes, WEB_DEFAULT_XLSX_FILENAME)

    payload = {
        "metrics": metrics,
        "missing_matrix_entries": missing,
        "workbook": workbook,
        "total_findings": _summary_total(metrics),
    }
    return payload, xlsx_bytes


# ---------------------------------------------------------------------------
# Assembled view for templates and JSON endpoints
# ---------------------------------------------------------------------------


def build_artifacts_view(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return project-shaped ``(data_artifacts, workbook_data)`` dicts for ``token``.

    Neither contains workbook bytes; the XLSX files are read separately with
    :func:`read_xlsx`.
    """
    artifacts: Dict[str, Any] = {}
    workbook: Dict[str, Any] = {
        "external_nexpose": copy.deepcopy(WORKBOOK_DEFAULTS["external_nexpose"]),
        "web": copy.deepcopy(WORKBOOK_DEFAULTS["web"]),
    }

    nexpose = read_result(token, SLOT_NEXPOSE)
    if nexpose:
        artifacts[NEXPOSE_FILE_NAME_KEY] = nexpose.get("file_name") or ""
        metrics = nexpose.get("metrics")
        artifacts[NEXPOSE_METRICS_KEY] = metrics if isinstance(metrics, dict) else {}
        missing = nexpose.get("missing_matrix_entries")
        if isinstance(missing, list) and missing:
            artifacts["nexpose_matrix_gaps"] = {
                "missing_by_artifact": {NEXPOSE_ARTIFACT_KEY: {"entries": missing}}
            }
        if isinstance(nexpose.get("workbook"), dict):
            workbook["external_nexpose"].update(nexpose["workbook"])

    web = read_result(token, SLOT_WEB)
    if web:
        artifacts[WEB_FILE_NAME_KEY] = web.get("file_name") or ""
        metrics = web.get("metrics")
        artifacts[WEB_METRICS_KEY] = metrics if isinstance(metrics, dict) else {}
        missing = web.get("missing_matrix_entries")
        if isinstance(missing, list) and missing:
            artifacts["web_issue_matrix_gaps"] = {"entries": missing}
        if isinstance(web.get("workbook"), dict):
            workbook["web"].update(web["workbook"])

    processing = get_processing_uploads(token)
    if processing:
        artifacts["processing_uploads"] = processing
    errors = get_errors(token)
    if errors:
        artifacts["scan_processing_errors"] = errors

    return artifacts, workbook
