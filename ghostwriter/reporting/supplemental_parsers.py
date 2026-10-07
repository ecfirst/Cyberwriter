"""
Parsers for the supplemental XLSX workbooks (Web/Burp and Nexpose) that analysts upload to a
report. Each parser converts a workbook produced by Cyberwriter's data pipeline into a list of
normalized Corrective Action Plan (CAP) entries that the CAP exporter can write without any
further interpretation.

A normalized CAP entry is a plain dictionary with these keys::

    {
        "source": "web" | "nexpose",
        "issue": "...",      # Unique issue title
        "systems": "...",    # Affected systems or hosts, newline separated
        "action": "...",     # Recommended remediation
        "risk": "High" | "Medium" | "Low" | None,
        "score": float | None,
    }

Hard failures (not an XLSX, missing sheet, missing column, zero usable rows) raise
``SupplementalParseError``. Soft issues are collected as warnings and the file is still accepted.
"""

# Standard Libraries
import logging
import zipfile
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import date, datetime
from io import BytesIO
from typing import Any, Dict, Iterator, List, Optional, Sequence

# 3rd Party Libraries
import openpyxl
from openpyxl.utils.exceptions import InvalidFileException

logger = logging.getLogger(__name__)

# Excel's hard limit on the number of characters in a single cell
EXCEL_CELL_CHARACTER_LIMIT = 32766

# Uploads above this size are rejected before parsing
MAX_SUPPLEMENTAL_UPLOAD_BYTES = 50 * 1024 * 1024

# Ordering used when merging duplicate issues and when sorting CAP rows
RISK_RANK = {"High": 3, "Medium": 2, "Low": 1}

KIND_WEB = "web"
KIND_NEXPOSE = "nexpose"


class SupplementalParseError(Exception):
    """Raised when a supplemental workbook cannot be parsed into CAP entries."""


@dataclass
class ParseResult:
    """CAP entries parsed from a workbook plus any non-fatal warnings."""

    entries: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def truncate_excel_text(
    value: Optional[str], limit: int = EXCEL_CELL_CHARACTER_LIMIT
) -> str:
    """Ensure ``value`` fits within an Excel cell by truncating when needed."""
    text = value or ""
    if len(text) <= limit:
        return text
    ellipsis = "…"
    return text[: max(0, limit - len(ellipsis))] + ellipsis


def normalize_risk(raw: Any) -> Optional[str]:
    """
    Normalize a risk label (or numeric score) to ``High``, ``Medium``, or ``Low``.

    Returns ``None`` when the value is empty or unrecognized.
    """
    text = _cell_text(raw)
    if not text:
        return None

    normalized = text.upper().replace("-", " ")
    if "(" in normalized:
        normalized = normalized.split("(", 1)[0]
    normalized = " ".join(normalized.split())

    if normalized in {"CRITICAL", "HIGH"}:
        return "High"
    if normalized in {"MEDIUM", "MODERATE"}:
        return "Medium"
    if normalized in {"LOW", "INFO", "INFORMATION", "INFORMATIONAL"}:
        return "Low"

    try:
        score = float(text)
    except (TypeError, ValueError):
        return None

    if score >= 8:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 0:
        return "Low"
    return None


def _cell_text(value: Any) -> str:
    """Convert a cell value to stripped text, rendering integral floats without a trailing ``.0``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value).strip()


def _normalize_header(value: Any) -> str:
    return " ".join(_cell_text(value).split()).lower()


def _issue_key(value: Any) -> str:
    """Key used to join rows across sheets and to detect duplicate issues."""
    return " ".join(_cell_text(value).split()).lower()


def _is_blank_row(row: Sequence[Any]) -> bool:
    return all(
        cell is None or (isinstance(cell, str) and not cell.strip()) for cell in row
    )


def _coerce_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = _cell_text(value)
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _load_workbook(data: bytes):
    try:
        return openpyxl.load_workbook(BytesIO(data), read_only=True, data_only=True)
    except (
        zipfile.BadZipFile,
        InvalidFileException,
        KeyError,
        ValueError,
        OSError,
    ) as exc:
        raise SupplementalParseError("The file is not a valid XLSX workbook.") from exc


def _find_sheet(workbook, name: str):
    """Look up a worksheet by name, ignoring case and surrounding whitespace."""
    wanted = _normalize_header(name)
    for worksheet in workbook.worksheets:
        if _normalize_header(worksheet.title) == wanted:
            return worksheet
    present = ", ".join(ws.title for ws in workbook.worksheets) or "none"
    raise SupplementalParseError(
        f"Required sheet '{name}' was not found. Sheets present: {present}."
    )


class _SheetReader:
    """
    Reads a worksheet whose first row holds column headers. Header matching ignores case and
    whitespace. Rows shorter than the header (which ``read_only`` mode can produce) are padded
    with empty values, and fully blank rows are skipped.
    """

    def __init__(self, worksheet, required: Sequence[str], optional: Sequence[str] = ()):
        self.title = worksheet.title
        self._rows = worksheet.iter_rows(values_only=True)
        header = next(self._rows, None)
        if header is None or _is_blank_row(header):
            raise SupplementalParseError(f"Sheet '{self.title}' is empty.")

        self.columns: Dict[str, int] = {}
        for index, value in enumerate(header):
            key = _normalize_header(value)
            if key and key not in self.columns:
                self.columns[key] = index

        missing = [name for name in required if not self.has(name)]
        if missing:
            raise SupplementalParseError(
                f"Sheet '{self.title}' is missing required column(s): {', '.join(missing)}."
            )
        self.optional = [name for name in optional if self.has(name)]

    def has(self, name: str) -> bool:
        return _normalize_header(name) in self.columns

    def raw(self, row: Sequence[Any], name: str) -> Any:
        index = self.columns.get(_normalize_header(name))
        if index is None or index >= len(row):
            return None
        return row[index]

    def get(self, row: Sequence[Any], name: str) -> str:
        return _cell_text(self.raw(row, name))

    def rows(self) -> Iterator[Sequence[Any]]:
        for row in self._rows:
            if row is None or _is_blank_row(row):
                continue
            yield row


def _extract_score(reader: _SheetReader, row: Sequence[Any]) -> Optional[float]:
    """Use an optional numeric ``Score`` (or ``Severity``) column when an analyst added one."""
    for name in ("Score", "Severity"):
        if reader.has(name):
            score = _coerce_float(reader.raw(row, name))
            if score is not None:
                return score
    return None


def _merge_unique(existing: Dict[str, Any], new: Dict[str, Any]) -> None:
    """Merge a duplicate unique-issue row: highest risk, first non-empty action, highest score."""
    if RISK_RANK.get(new["risk"], 0) > RISK_RANK.get(existing["risk"], 0):
        existing["risk"] = new["risk"]
    if not existing["action"] and new["action"]:
        existing["action"] = new["action"]
    if new["score"] is not None and (
        existing["score"] is None or new["score"] > existing["score"]
    ):
        existing["score"] = new["score"]


def _collect_unique_issues(
    reader: _SheetReader, action_column: str, warnings: List[str]
) -> "OrderedDict[str, Dict[str, Any]]":
    """Read the ``Unique Issues`` sheet into an ordered mapping of issue key to record."""
    issues: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for row in reader.rows():
        issue = reader.get(row, "Issue")
        if not issue:
            continue
        key = _issue_key(issue)

        raw_risk = reader.get(row, "Risk")
        risk = normalize_risk(raw_risk)
        if raw_risk and risk is None:
            warnings.append(f"Unrecognized Risk '{raw_risk}' for issue '{issue}'.")
        elif not raw_risk:
            warnings.append(f"Issue '{issue}' has no Risk value.")

        record = {
            "issue": issue,
            "risk": risk,
            "action": reader.get(row, action_column),
            "score": _extract_score(reader, row),
        }
        existing = issues.get(key)
        if existing is None:
            issues[key] = record
        else:
            _merge_unique(existing, record)
            warnings.append(f"Duplicate issue '{issue}' in Unique Issues was merged.")
    return issues


def _make_entry(
    source: str,
    issue: str,
    systems: str,
    action: str,
    risk: Optional[str],
    score: Optional[float],
) -> Dict[str, Any]:
    return {
        "source": source,
        "issue": truncate_excel_text(issue),
        "systems": truncate_excel_text(systems),
        "action": truncate_excel_text(action),
        "risk": risk,
        "score": score,
    }


def _parse_nexpose(workbook) -> ParseResult:
    """
    Nexpose workbook: one CAP row per unique issue. Systems are the deduplicated
    ``IP Address [Hostname(s)]`` labels for that issue from ``All Issues``; the action is the
    issue's ``Remediation``.
    """
    warnings: List[str] = []

    all_reader = _SheetReader(
        _find_sheet(workbook, "All Issues"),
        required=["IP Address", "Hostname(s)", "Issue"],
    )
    # Dict used as an insertion-ordered set of system labels per issue
    systems_by_key: Dict[str, Dict[str, None]] = {}
    for row in all_reader.rows():
        issue = all_reader.get(row, "Issue")
        if not issue:
            continue
        ip_address = all_reader.get(row, "IP Address")
        hostnames = all_reader.get(row, "Hostname(s)")
        if ip_address and hostnames:
            label = f"{ip_address} [{hostnames}]"
        else:
            label = ip_address or hostnames
        if not label:
            continue
        systems_by_key.setdefault(_issue_key(issue), {})[label] = None

    unique_reader = _SheetReader(
        _find_sheet(workbook, "Unique Issues"),
        required=["Risk", "Issue", "Remediation"],
        optional=["Score", "Severity"],
    )
    unique_issues = _collect_unique_issues(unique_reader, "Remediation", warnings)

    entries: List[Dict[str, Any]] = []
    for key, record in unique_issues.items():
        labels = list(systems_by_key.get(key, {}))
        if not labels:
            warnings.append(f"Issue '{record['issue']}' has no systems in All Issues.")
        entries.append(
            _make_entry(
                KIND_NEXPOSE,
                record["issue"],
                "\n".join(labels),
                record["action"],
                record["risk"],
                record["score"],
            )
        )

    orphans = len(set(systems_by_key) - set(unique_issues))
    if orphans:
        warnings.append(
            f"{orphans} issue(s) appear in All Issues but not in Unique Issues and were skipped."
        )
    if not entries:
        raise SupplementalParseError("No usable rows found in 'Unique Issues'.")
    return ParseResult(entries, warnings)


def _parse_web(workbook) -> ParseResult:
    """
    Web (Burp) workbook: one CAP row per unique issue. Hosts are the sorted ``Host + Path``
    values for that issue from ``All Issues``; the action is the issue's ``Fix``.
    """
    warnings: List[str] = []

    all_reader = _SheetReader(
        _find_sheet(workbook, "All Issues"), required=["Issue", "Host", "Path"]
    )
    hosts_by_key: Dict[str, set] = {}
    for row in all_reader.rows():
        issue = all_reader.get(row, "Issue")
        if not issue:
            continue
        host_path = f"{all_reader.get(row, 'Host')}{all_reader.get(row, 'Path')}".strip()
        if not host_path:
            continue
        hosts_by_key.setdefault(_issue_key(issue), set()).add(host_path)

    unique_reader = _SheetReader(
        _find_sheet(workbook, "Unique Issues"),
        required=["Issue", "Fix", "Risk"],
        optional=["Score", "Severity"],
    )
    unique_issues = _collect_unique_issues(unique_reader, "Fix", warnings)

    entries: List[Dict[str, Any]] = []
    for key, record in unique_issues.items():
        hosts = sorted(hosts_by_key.get(key, set()))
        if not hosts:
            warnings.append(f"Issue '{record['issue']}' has no hosts in All Issues.")
        entries.append(
            _make_entry(
                KIND_WEB,
                record["issue"],
                "\n".join(hosts),
                record["action"],
                record["risk"],
                record["score"],
            )
        )

    orphans = len(set(hosts_by_key) - set(unique_issues))
    if orphans:
        warnings.append(
            f"{orphans} issue(s) appear in All Issues but not in Unique Issues and were skipped."
        )
    if not entries:
        raise SupplementalParseError("No usable rows found in 'Unique Issues'.")
    return ParseResult(entries, warnings)


_PARSERS = {
    KIND_WEB: _parse_web,
    KIND_NEXPOSE: _parse_nexpose,
}


def parse_supplemental(kind: str, data: bytes) -> ParseResult:
    """
    Parse the uploaded workbook bytes for the given supplemental ``kind`` (``"web"`` or
    ``"nexpose"``) into normalized CAP entries.

    Raises ``SupplementalParseError`` for anything that should block saving the upload.
    """
    parser = _PARSERS.get(kind)
    if parser is None:
        raise SupplementalParseError(f"Unknown supplemental kind '{kind}'.")
    if len(data) > MAX_SUPPLEMENTAL_UPLOAD_BYTES:
        raise SupplementalParseError(
            f"The file is larger than {MAX_SUPPLEMENTAL_UPLOAD_BYTES // (1024 * 1024)} MB."
        )

    workbook = _load_workbook(data)
    try:
        return parser(workbook)
    finally:
        workbook.close()
