import io

from typing import Any, Callable, Dict, List, Optional

from ghostwriter.modules.reportwriter.base.xlsx import ExportXlsxBase
from ghostwriter.modules.reportwriter.report.base import ExportReportBase


class ExportReportXlsx(ExportXlsxBase, ExportReportBase):
    FILENAME_TEMPLATE = (
        "{{ now }} - {{ client.name }} Cybersecurity Report Corrective Action Plan {{ project.end_year }}"
    )
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
            "name": "High Priority",
            "tab_color": "#FF0000",
            "header_fill": "#800000",
            "header_font": "#FFFFFF",
            "banded_fill": "#FF8080",
        },
        {
            "name": "Med Priority",
            "tab_color": "#FF6600",
            "header_fill": "#FF9900",
            "banded_fill": "#FFCC99",
        },
        {
            "name": "Lower Priority",
            "tab_color": "#008000",
            "header_fill": "#339966",
            "banded_fill": "#CCFFCC",
        },
    ]

    DEFAULT_PRIORITY_RULES = {"high": 8.0, "med": 4.0}
    PRIORITY_OVERRIDES = {
        "firewall": {"high": 7.0, "med": 4.0},
        "web": {"high": 8.0, "med": 5.0},
    }

    def run(self) -> io.BytesIO:
        cap_data = self._get_project_cap_data()
        rows_by_priority = self._collect_cap_entries(cap_data)

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
                }
            )
            default_row_format = workbook.add_format({**base_font, "text_wrap": True, "valign": "top"})
            banded_row_format = workbook.add_format(
                {**base_font, "text_wrap": True, "valign": "top", "bg_color": sheet_config["banded_fill"]}
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

    def _get_project_cap_data(self) -> Dict[str, Any]:
        project = self.data.get("project") if isinstance(self.data, dict) else {}
        if not isinstance(project, dict):
            return {}
        cap_data = project.get("cap")
        return cap_data if isinstance(cap_data, dict) else {}

    def _collect_cap_entries(self, cap_data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
        rows = {config["name"]: [] for config in self.SHEET_CONFIGS}
        if not cap_data:
            return rows

        self._append_dns_rows(cap_data, rows)
        self._append_osint_rows(cap_data, rows)
        self._append_sql_rows(cap_data, rows)
        self._append_snmp_rows(cap_data, rows)
        self._append_password_rows(cap_data, rows)
        self._append_ad_rows(cap_data, rows)
        self._append_endpoint_rows(cap_data, rows)
        self._append_wireless_rows(cap_data, rows)
        self._append_nexpose_rows(cap_data, rows)
        self._append_firewall_rows(cap_data, rows)
        self._append_web_rows(cap_data, rows)

        return rows

    def _append_dns_rows(self, cap_data: Dict[str, Any], rows: Dict[str, List[Dict[str, str]]]):
        dns_section = cap_data.get("dns")
        if not isinstance(dns_section, dict):
            return
        self._append_domain_issue_map(rows, "dns", dns_section.get("dns_cap_map"))

    def _append_osint_rows(self, cap_data: Dict[str, Any], rows):
        osint_section = cap_data.get("osint")
        if not isinstance(osint_section, dict):
            return
        self._append_issue_entries(
            rows,
            "osint",
            osint_section.get("osint_cap_map"),
            lambda _issue: "Various Systems",
        )

    def _append_sql_rows(self, cap_data: Dict[str, Any], rows):
        sql_section = cap_data.get("sql")
        if not isinstance(sql_section, dict):
            return
        self._append_issue_entries(
            rows,
            "sql",
            sql_section.get("sql_cap_map"),
            lambda _issue: "Various Systems",
        )

    def _append_snmp_rows(self, cap_data: Dict[str, Any], rows):
        snmp_section = cap_data.get("snmp")
        if not isinstance(snmp_section, dict):
            return
        self._append_issue_entries(
            rows,
            "snmp",
            snmp_section.get("snmp_cap_map"),
            lambda _issue: "Various Systems",
        )

    def _append_password_rows(self, cap_data: Dict[str, Any], rows):
        password_section = cap_data.get("password")
        if not isinstance(password_section, dict):
            return

        policy_map = password_section.get("policy_cap_map")
        if isinstance(policy_map, dict):
            for domain, details in policy_map.items():
                if not isinstance(details, dict):
                    continue
                policy_details = details.get("policy")
                if isinstance(policy_details, dict):
                    recommendation = self._build_policy_recommendation(policy_details)
                    score = policy_details.get("score")
                    self._add_row(
                        rows,
                        "password",
                        score,
                        self._stringify(domain),
                        "Password policy doesn't follow best practice",
                        recommendation,
                    )
                fgpp_details = details.get("fgpp")
                if isinstance(fgpp_details, dict):
                    for fgpp_name, fgpp_policy in fgpp_details.items():
                        if not isinstance(fgpp_policy, dict):
                            continue
                        recommendation = self._build_policy_recommendation(fgpp_policy)
                        score = fgpp_policy.get("score")
                        system_label = self._combine_labels(domain, fgpp_name)
                        self._add_row(
                            rows,
                            "password",
                            score,
                            system_label,
                            "Password policy doesn't follow best practice",
                            recommendation,
                        )

        badpass_map = password_section.get("badpass_cap_map")
        if isinstance(badpass_map, dict):
            for system, issues in badpass_map.items():
                if system == "global":
                    continue
                self._append_issue_entries(
                    rows,
                    "password",
                    issues,
                    lambda _issue, label=self._stringify(system): label,
                )

    def _append_ad_rows(self, cap_data: Dict[str, Any], rows):
        ad_section = cap_data.get("ad")
        if not isinstance(ad_section, dict):
            return
        self._append_domain_issue_map(rows, "ad", ad_section.get("ad_cap_map"))

    def _append_endpoint_rows(self, cap_data: Dict[str, Any], rows):
        endpoint_section = cap_data.get("endpoint")
        if not isinstance(endpoint_section, dict):
            return
        self._append_domain_issue_map(rows, "endpoint", endpoint_section.get("endpoint_cap_map"))

    def _append_wireless_rows(self, cap_data: Dict[str, Any], rows):
        wireless_section = cap_data.get("wireless")
        if not isinstance(wireless_section, dict):
            return
        cap_map = wireless_section.get("wireless_cap_map")
        if not isinstance(cap_map, dict):
            return
        for key, value in cap_map.items():
            if not isinstance(value, dict):
                continue
            if "score" in value or "recommendation" in value:
                self._append_issue_entry(rows, "wireless", key, "Wireless", value)
            else:
                self._append_issue_entries(rows, "wireless", value, lambda _issue: "Wireless")

    def _append_nexpose_rows(self, cap_data: Dict[str, Any], rows):
        nexpose_section = cap_data.get("nexpose")
        if not isinstance(nexpose_section, dict):
            return
        entries = nexpose_section.get("nexpose_cap_map")
        if not isinstance(entries, list):
            return
        distilled = bool(nexpose_section.get("distilled"))
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            action_text = self._stringify(entry.get("action"))
            issue_text = self._stringify(entry.get("issue"))
            if distilled and action_text:
                issue_text = f"Action needed: {action_text}"
            elif not issue_text and action_text:
                issue_text = action_text
            self._add_row(
                rows,
                "nexpose",
                entry.get("score"),
                self._stringify(entry.get("systems")),
                issue_text,
                action_text,
            )

    def _append_firewall_rows(self, cap_data: Dict[str, Any], rows):
        firewall_section = cap_data.get("firewall")
        if not isinstance(firewall_section, dict):
            return
        cap_entries = firewall_section.get("firewall_cap_map")
        if isinstance(cap_entries, list):
            for entry in cap_entries:
                if not isinstance(entry, dict):
                    continue
                recommendation = self._stringify(entry.get("solution"))
                if not recommendation:
                    recommendation = self._stringify(entry.get("recommendation"))
                self._add_row(
                    rows,
                    "firewall",
                    entry.get("score"),
                    self._stringify(entry.get("devices")),
                    self._stringify(entry.get("issue")),
                    recommendation,
                )
        global_entries = firewall_section.get("global")
        if isinstance(global_entries, dict):
            self._append_issue_entries(rows, "firewall", global_entries, lambda _issue: "Firewall(s)")

    def _append_web_rows(self, cap_data: Dict[str, Any], rows):
        web_section = cap_data.get("web")
        if not isinstance(web_section, dict):
            return
        entries = web_section.get("web_cap_map")
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            self._add_row(
                rows,
                "web",
                entry.get("score"),
                self._stringify(entry.get("hosts")),
                self._stringify(entry.get("issue")),
                self._stringify(entry.get("action")),
            )

    def _append_domain_issue_map(self, rows, section_name: str, domain_map: Dict[str, Any]):
        if not isinstance(domain_map, dict):
            return
        for domain, issues in domain_map.items():
            if not isinstance(issues, dict):
                continue
            label = self._stringify(domain)
            self._append_issue_entries(rows, section_name, issues, lambda _issue, label=label: label)

    def _append_issue_entries(
        self,
        rows: Dict[str, List[Dict[str, str]]],
        section_name: str,
        issue_map: Dict[str, Any],
        system_func: Callable[[str], str],
    ):
        if not isinstance(issue_map, dict):
            return
        for issue_name, entry in issue_map.items():
            self._append_issue_entry(rows, section_name, issue_name, system_func(issue_name), entry)

    def _append_issue_entry(
        self,
        rows: Dict[str, List[Dict[str, str]]],
        section_name: str,
        issue_name: str,
        system_value: str,
        entry: Dict[str, Any],
    ):
        if not isinstance(entry, dict):
            return
        self._add_row(
            rows,
            section_name,
            entry.get("score"),
            self._stringify(system_value),
            self._stringify(issue_name),
            self._stringify(entry.get("recommendation")),
        )

    def _build_policy_recommendation(self, policy_details: Dict[str, Any]) -> str:
        lines: List[str] = []
        for key, value in policy_details.items():
            if key == "score" or value in (None, ""):
                continue
            text = self._stringify(value)
            if text:
                lines.append(text)
        return "\n".join(lines)

    def _combine_labels(self, first: Any, second: Any) -> str:
        first_text = self._stringify(first)
        second_text = self._stringify(second)
        if first_text and second_text:
            return f"{first_text}: {second_text}"
        return first_text or second_text

    def _stringify(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            parts = [self._stringify(item) for item in value if item not in (None, "")]
            return ", ".join(part for part in parts if part)
        text = str(value).strip()
        return text

    def _add_row(
        self,
        rows: Dict[str, List[Dict[str, str]]],
        section_name: str,
        score,
        system_value: str,
        issue_text: str,
        recommendation: str,
    ):
        numeric_score = self._coerce_score(score)
        priority = self._determine_priority(section_name, numeric_score)
        rows.setdefault(priority, []).append(
            {
                "Sev": self._format_severity(score),
                "Issue": issue_text,
                "System(s)/Resource": system_value,
                "Recommendation": recommendation,
                "_score": numeric_score,
            }
        )

    def _determine_priority(self, section_name: str, numeric_score: Optional[float]) -> str:
        if numeric_score is None:
            return "Lower Priority"
        rules = self.PRIORITY_OVERRIDES.get(section_name, self.DEFAULT_PRIORITY_RULES)
        if numeric_score >= rules["high"]:
            return "High Priority"
        if numeric_score >= rules["med"]:
            return "Med Priority"
        return "Lower Priority"

    def _row_sort_key(self, row: Dict[str, Any]) -> float:
        score = row.get("_score")
        if isinstance(score, (int, float)):
            return float(score)
        return float("-inf")

    def _coerce_score(self, score) -> Optional[float]:
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

    def _format_severity(self, score) -> str:
        if score in (None, ""):
            return ""
        return str(score)
