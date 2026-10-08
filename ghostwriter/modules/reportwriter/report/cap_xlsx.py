"""
Corrective Action Plan (CAP) workbook export for a :model:`reporting.Report`.

The workbook has three tabs (High / Med / Lower Priority) with identical columns. Rows come
from two sources, in this order:

1. The report's findings (``ReportFindingLink``), bucketed by severity name with a CVSS
   fallback for severities that are not one of the standard names. The Sev cell shows the
   severity name; the CVSS score only orders rows within a tab.
2. The CAP entries parsed from the report's uploaded supplemental workbooks
   (``ReportSupplementalFile``), Web first and then Nexpose, bucketed by their risk label
   with a numeric-score fallback.

Supplemental rows take precedence: a finding whose title matches the issue of any
supplemental entry (ignoring case and surrounding/repeated whitespace) is left out so the
scanner's row, with its per-host system list and remediation, is the one in the CAP.

Styling, headers, and sheet configuration mirror Cyberwriter's CAP export so the output is
interchangeable with the workbook analysts already know.
"""

# Standard Libraries
import io
import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Ghostwriter Libraries
from ghostwriter.modules.reportwriter.base.xlsx import ExportXlsxBase
from ghostwriter.modules.reportwriter.report.base import ExportReportBase
from ghostwriter.reporting.models import ReportSupplementalFile
from ghostwriter.reporting.supplemental_parsers import RISK_RANK, truncate_excel_text

logger = logging.getLogger(__name__)

HIGH_PRIORITY = "High Priority"
MED_PRIORITY = "Med Priority"
LOWER_PRIORITY = "Lower Priority"


class ExportReportCapXlsx(ExportXlsxBase, ExportReportBase):
    """Build the three-tab CAP workbook from a report's findings and supplemental workbooks."""

    FILENAME_TEMPLATE = "{{ now }} - {{ client.name }} Cybersecurity Report Corrective Action Plan {{ project.end_year }}"

    HEADERS = [
        "Sev",
        "Issue",
        "System(s)/Resource",
        "Recommendation",
        "Status",
        "Owner",
        "Due Date",
        "Start Date",
        "End Date",
        "Validation Metric",
        "Review Date",
        "Notes",
    ]

    SHEET_CONFIGS = [
        {
            "name": HIGH_PRIORITY,
            "tab_color": "#FF0000",
            "header_fill": "#800000",
            "header_font": "#FFFFFF",
            "banded_fill": "#FF8080",
        },
        {
            "name": MED_PRIORITY,
            "tab_color": "#FF6600",
            "header_fill": "#FF9900",
            "banded_fill": "#FFCC99",
        },
        {
            "name": LOWER_PRIORITY,
            "tab_color": "#008000",
            "header_fill": "#339966",
            "banded_fill": "#CCFFCC",
        },
    ]

    PRIORITY_RANK = {HIGH_PRIORITY: 3, MED_PRIORITY: 2, LOWER_PRIORITY: 1}
    PRIORITY_BY_RISK = {
        "High": HIGH_PRIORITY,
        "Medium": MED_PRIORITY,
        "Low": LOWER_PRIORITY,
    }

    # Finding severity names are free text in Ghostwriter. These are the conventional names;
    # anything else falls back to the CVSS thresholds below. Informational rolls up into Low.
    SEVERITY_TO_RISK = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "informational": "Low",
        "info": "Low",
        "information": "Low",
    }
    FINDING_CVSS_RULES = {"high": 7.0, "med": 4.0}

    # Score thresholds for supplemental entries that carry a number but no risk label
    DEFAULT_PRIORITY_RULES = {"high": 8.0, "med": 4.0}
    PRIORITY_OVERRIDES = {
        "web": {"high": 8.0, "med": 5.0},
    }

    KIND_ORDER = [kind.value for kind in ReportSupplementalFile.Kind]

    def __init__(self, object, **kwargs):
        super().__init__(object, **kwargs)
        self.report = object
        self._rows: Optional[Dict[str, List[Dict[str, Any]]]] = None
        # Titles of findings left out because a supplemental row has the same title
        self.shadowed_findings: List[str] = []

    # ------------------------------------------------------------------ row collection

    def collect_rows(self) -> Dict[str, List[Dict[str, Any]]]:
        """Rows keyed by sheet name. Computed once; ``has_rows`` and ``run`` share the result."""
        if self._rows is None:
            rows: Dict[str, List[Dict[str, Any]]] = {
                config["name"]: [] for config in self.SHEET_CONFIGS
            }
            entries = self._supplemental_entries()
            shadowed = {
                key
                for key in (self._match_key(entry.get("issue")) for _, entry in entries)
                if key
            }
            self._append_finding_rows(rows, shadowed)
            self._append_supplemental_rows(rows, entries)
            self._rows = rows
        return self._rows

    def has_rows(self) -> bool:
        return any(self.collect_rows().values())

    def _append_finding_rows(
        self, rows: Dict[str, List[Dict[str, Any]]], shadowed: Set[str]
    ) -> None:
        context = self.map_rich_texts()
        self.shadowed_findings = []
        for finding in context.get("findings", []):
            title = finding.get("title")
            if self._match_key(title) in shadowed:
                self.shadowed_findings.append(self._stringify(title))
                logger.info(
                    "CAP export omitted finding %r for report %s because a supplemental row has the same title",
                    title,
                    self.report.pk,
                )
                continue

            severity_name = self._stringify(finding.get("severity"))
            cvss = self._coerce_score(finding.get("cvss_score"))
            if cvss is not None and cvss <= 0:
                # The serializer emits 0.0 when no score was entered
                cvss = None

            risk = self.SEVERITY_TO_RISK.get(severity_name.lower())
            if risk:
                priority = self.PRIORITY_BY_RISK[risk]
            else:
                priority = self._threshold_priority(cvss, self.FINDING_CVSS_RULES)

            # Sev shows the severity name; CVSS only orders rows within a tab
            sev = severity_name

            systems = self._render_finding_field(finding, "affected_entities")
            recommendation = self._render_finding_field(finding, "mitigation")
            self._add_row(rows, priority, sev, title, systems, recommendation, cvss)

    def _render_finding_field(self, finding: Dict[str, Any], field: str) -> str:
        """Render a finding's rich text field to plain text, or ``""`` when it is empty."""
        if not finding.get(field):
            return ""
        rich_text = finding.get(f"{field}_rt")
        if rich_text is None:
            return ""
        return self.render_rich_text_xlsx(rich_text)

    def _supplemental_entries(
        self,
    ) -> List[Tuple[ReportSupplementalFile, Dict[str, Any]]]:
        """Every well-formed CAP entry across the report's supplemental files, Web first."""
        files = sorted(
            self.report.supplemental_files.all(),
            key=lambda f: self.KIND_ORDER.index(f.kind)
            if f.kind in self.KIND_ORDER
            else len(self.KIND_ORDER),
        )
        pairs: List[Tuple[ReportSupplementalFile, Dict[str, Any]]] = []
        for supplemental in files:
            entries = (
                supplemental.cap_entries
                if isinstance(supplemental.cap_entries, list)
                else []
            )
            pairs.extend(
                (supplemental, entry) for entry in entries if isinstance(entry, dict)
            )
        return pairs

    def _append_supplemental_rows(
        self,
        rows: Dict[str, List[Dict[str, Any]]],
        entries: Iterable[Tuple[ReportSupplementalFile, Dict[str, Any]]],
    ) -> None:
        for supplemental, entry in entries:
            risk = entry.get("risk")
            if risk not in RISK_RANK:
                risk = None
            score = self._coerce_score(entry.get("score"))
            source = entry.get("source") or supplemental.kind

            if risk:
                priority = self.PRIORITY_BY_RISK[risk]
            else:
                rules = self.PRIORITY_OVERRIDES.get(source, self.DEFAULT_PRIORITY_RULES)
                priority = self._threshold_priority(score, rules)

            if score is not None:
                sev = self._format_score(score)
            else:
                sev = risk or ""

            self._add_row(
                rows,
                priority,
                sev,
                entry.get("issue"),
                entry.get("systems"),
                entry.get("action"),
                score,
            )

    def _add_row(
        self,
        rows: Dict[str, List[Dict[str, Any]]],
        priority: str,
        sev: Any,
        issue: Any,
        systems: Any,
        recommendation: Any,
        score: Optional[float],
    ) -> None:
        rows.setdefault(priority, []).append(
            {
                "Sev": truncate_excel_text(self._stringify(sev)),
                "Issue": truncate_excel_text(self._stringify(issue)),
                "System(s)/Resource": truncate_excel_text(self._stringify(systems)),
                "Recommendation": truncate_excel_text(self._stringify(recommendation)),
                "_rank": self.PRIORITY_RANK[priority],
                "_score": score,
            }
        )

    # ------------------------------------------------------------------ helpers

    def _threshold_priority(self, score: Optional[float], rules: Dict[str, float]) -> str:
        if score is None:
            return LOWER_PRIORITY
        if score >= rules["high"]:
            return HIGH_PRIORITY
        if score >= rules["med"]:
            return MED_PRIORITY
        return LOWER_PRIORITY

    @staticmethod
    def _row_sort_key(row: Dict[str, Any]):
        score = row.get("_score")
        numeric = float(score) if isinstance(score, (int, float)) else float("-inf")
        return (row["_rank"], numeric)

    @staticmethod
    def _coerce_score(score: Any) -> Optional[float]:
        if isinstance(score, bool):
            return None
        if isinstance(score, (int, float)):
            return float(score)
        if isinstance(score, str):
            text = score.strip()
            if not text:
                return None
            try:
                return float(text)
            except ValueError:
                return None
        return None

    @staticmethod
    def _format_score(score: float) -> str:
        return str(int(score)) if float(score).is_integer() else str(score)

    @classmethod
    def _match_key(cls, value: Any) -> str:
        """Normalize a title/issue for duplicate detection: trimmed, single-spaced, casefolded."""
        return " ".join(cls._stringify(value).split()).casefold()

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            parts = [str(item).strip() for item in value if item not in (None, "")]
            return ", ".join(part for part in parts if part)
        return str(value).strip()

    # ------------------------------------------------------------------ workbook

    def run(self) -> io.BytesIO:
        rows_by_priority = self.collect_rows()
        workbook = self.workbook
        base_font = {"font_name": "Arial", "font_size": 12}

        for sheet_config in self.SHEET_CONFIGS:
            worksheet = workbook.add_worksheet(sheet_config["name"])
            worksheet.set_tab_color(sheet_config["tab_color"])

            header_format = workbook.add_format(
                {
                    **base_font,
                    "bold": True,
                    "bg_color": sheet_config["header_fill"],
                    "font_color": sheet_config.get("header_font", "#000000"),
                    "align": "center",
                    "valign": "vcenter",
                    "text_wrap": True,
                    "border": 1,
                }
            )
            default_row_format = workbook.add_format(
                {**base_font, "text_wrap": True, "valign": "top", "border": 1}
            )
            banded_row_format = workbook.add_format(
                {
                    **base_font,
                    "text_wrap": True,
                    "valign": "top",
                    "bg_color": sheet_config["banded_fill"],
                    "border": 1,
                }
            )

            for col_idx, title in enumerate(self.HEADERS):
                worksheet.write_string(0, col_idx, title, header_format)

            worksheet.set_column(0, 0, 8)
            worksheet.set_column(1, 1, 40)
            worksheet.set_column(2, 2, 30)
            worksheet.set_column(3, 3, 50)
            worksheet.set_column(4, len(self.HEADERS) - 1, 18)
            worksheet.freeze_panes(1, 0)

            data_rows = sorted(
                rows_by_priority.get(sheet_config["name"], []),
                key=self._row_sort_key,
                reverse=True,
            )
            for row_idx, row in enumerate(data_rows, start=1):
                row_format = banded_row_format if row_idx % 2 == 0 else default_row_format
                worksheet.write_string(row_idx, 0, row["Sev"], row_format)
                worksheet.write_string(row_idx, 1, row["Issue"], row_format)
                worksheet.write_string(row_idx, 2, row["System(s)/Resource"], row_format)
                worksheet.write_string(row_idx, 3, row["Recommendation"], row_format)
                for col_idx in range(4, len(self.HEADERS)):
                    worksheet.write_blank(row_idx, col_idx, None, row_format)

        return super().run()
