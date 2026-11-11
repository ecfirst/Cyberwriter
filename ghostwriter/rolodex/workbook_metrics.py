"""Derive workbook area sections from parsed scanner metrics payloads.

These helpers were lifted out of :meth:`ghostwriter.rolodex.models.Project.rebuild_data_artifacts`
so the same derivation can run for a saved project and for the ephemeral Scan Processing page
(:mod:`ghostwriter.rolodex.scan_processing`). Keep them free of model imports; ``data_parsers``
must never import this module back.
"""

# Standard Libraries
from typing import Any, Dict, List, Mapping, Optional

# Ghostwriter Libraries
from ghostwriter.rolodex.data_parsers import NEXPOSE_CATEGORY_LABELS

_MAJORITY_SUMMARY_MAP = {
    "OOD": "total_ood",
    "ISC": "total_isc",
    "IWC": "total_iwc",
}


def safe_int(value: Any) -> int:
    """Coerce workbook counts to ``int`` the same way the project rebuild does."""
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(float(text))
        except ValueError:
            return 0
    return 0


def derive_nexpose_workbook_section(
    metrics_payload: Mapping[str, Any],
    area_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the workbook section for a Nexpose area from its metrics payload.

    ``area_payload`` is the existing workbook section (if any); a copy is updated and
    returned so the caller's dict is never mutated.
    """
    summary = metrics_payload.get("summary")
    summary = summary if isinstance(summary, dict) else {}

    majority_type_raw = (metrics_payload.get("majority_type") or "").strip().upper()
    minority_type_raw = (metrics_payload.get("minority_type") or "").strip().upper()
    majority_label = NEXPOSE_CATEGORY_LABELS.get(majority_type_raw)
    minority_label = NEXPOSE_CATEGORY_LABELS.get(minority_type_raw)

    area: Dict[str, Any] = dict(area_payload) if isinstance(area_payload, Mapping) else {}

    area.update(
        {
            "total": safe_int(summary.get("total")),
            "total_high": safe_int(summary.get("total_high")),
            "total_med": safe_int(summary.get("total_med")),
            "total_low": safe_int(summary.get("total_low")),
            "unique": safe_int(summary.get("unique")),
            "unique_high_med": safe_int(summary.get("unique_high_med")),
        }
    )

    host_counts = metrics_payload.get("host_counts")
    if isinstance(host_counts, list):
        area["host_counts"] = list(host_counts)

    top_hosts = metrics_payload.get("top_hosts")
    if isinstance(top_hosts, list):
        area["top_hosts"] = list(top_hosts)

    for key in ("top_hosts_high", "top_hosts_med", "top_hosts_low", "top_hosts_total"):
        if key in metrics_payload:
            area[key] = safe_int(metrics_payload.get(key))

    if majority_label:
        area["majority_type"] = majority_label
        summary_key = _MAJORITY_SUMMARY_MAP.get(majority_type_raw)
        if summary_key:
            area["unique_majority"] = safe_int(summary.get(summary_key))
        elif majority_type_raw == "EVEN":
            area["unique_majority"] = safe_int(summary.get("majority_count"))

    if minority_label:
        area["minority_type"] = minority_label
        minority_summary_key = _MAJORITY_SUMMARY_MAP.get(minority_type_raw)
        if minority_summary_key:
            area["unique_minority"] = safe_int(summary.get(minority_summary_key))
        elif minority_type_raw == "EVEN":
            area["unique_minority"] = safe_int(summary.get("minority_count"))

    return area


def derive_web_workbook_section(
    metrics_payload: Mapping[str, Any],
    web_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the workbook ``web`` section from a web metrics payload.

    Mirrors the project rebuild: when the payload has no ``summary`` dict the existing
    section is returned unchanged (as a copy).
    """
    web: Dict[str, Any] = dict(web_payload) if isinstance(web_payload, Mapping) else {}

    summary = metrics_payload.get("summary")
    if not isinstance(summary, dict):
        return web

    web.update(
        {
            "combined_unique": safe_int(summary.get("unique")),
            "combined_unique_high": safe_int(summary.get("unique_high")),
            "combined_unique_med": safe_int(summary.get("unique_med")),
            "combined_unique_low": safe_int(summary.get("unique_low")),
        }
    )

    host_counts = summary.get("host_risk_counts")
    sites: List[Dict[str, Any]] = []
    if isinstance(host_counts, list):
        for entry in host_counts:
            if not isinstance(entry, dict):
                continue
            url_value = (entry.get("host") or "").strip()
            if not url_value:
                continue
            sites.append(
                {
                    "url": url_value,
                    "unique_high": safe_int(entry.get("high")),
                    "unique_med": safe_int(entry.get("medium")),
                    "unique_low": safe_int(entry.get("low")),
                }
            )

    web["sites"] = sites
    return web
