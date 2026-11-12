# Standard Libraries
import logging
from unittest import mock

# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.reporting import supplemental_parsers
from ghostwriter.reporting.supplemental_parsers import (
    EXCEL_CELL_CHARACTER_LIMIT,
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_SAMPLES,
    iter_supplemental_entries,
    SupplementalParseError,
    normalize_risk,
    parse_supplemental,
    truncate_excel_text,
)
from ghostwriter.reporting.tests.supplemental_fixtures import (
    NEXPOSE_ALL_HEADERS,
    NEXPOSE_UNIQUE_HEADERS,
    WEB_ALL_HEADERS,
    WEB_UNIQUE_HEADERS,
    build_workbook,
    nexpose_workbook,
    row,
    web_workbook,
)

logging.disable(logging.CRITICAL)


class NormalizeRiskTests(SimpleTestCase):
    """Tests for :func:`reporting.supplemental_parsers.normalize_risk`."""

    def test_labels(self):
        cases = {
            "Critical": "High",
            "high": "High",
            "HIGH": "High",
            "Medium": "Medium",
            "moderate": "Medium",
            "Low": "Low",
            "Info": "Low",
            "Information": "Low",
            "Informational": "Low",
            " low ": "Low",
            "High (confirmed)": "High",
            "medium-risk": None,
            "Purple": None,
            "": None,
            None: None,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_risk(raw), expected)

    def test_numeric_values(self):
        self.assertEqual(normalize_risk("9"), "High")
        self.assertEqual(normalize_risk(8.0), "High")
        self.assertEqual(normalize_risk("5.5"), "Medium")
        self.assertEqual(normalize_risk(4), "Medium")
        self.assertEqual(normalize_risk("0"), "Low")
        self.assertEqual(normalize_risk("3.9"), "Low")
        self.assertIsNone(normalize_risk("-1"))


class TruncateExcelTextTests(SimpleTestCase):
    def test_short_text_unchanged(self):
        self.assertEqual(truncate_excel_text("abc"), "abc")
        self.assertEqual(truncate_excel_text(None), "")

    def test_long_text_truncated_with_ellipsis(self):
        text = "x" * (EXCEL_CELL_CHARACTER_LIMIT + 1000)
        result = truncate_excel_text(text)
        self.assertEqual(len(result), EXCEL_CELL_CHARACTER_LIMIT)
        self.assertTrue(result.endswith("…"))


class NexposeParserTests(SimpleTestCase):
    """Tests for the Nexpose branch of :func:`reporting.supplemental_parsers.parse_supplemental`."""

    def test_happy_path(self):
        result = parse_supplemental("nexpose", nexpose_workbook())
        by_issue = {entry["issue"]: entry for entry in result.entries}

        self.assertEqual(
            [entry["issue"] for entry in result.entries],
            ["Outdated OpenSSL", "SMB Signing Disabled", "ICMP Timestamp"],
            "Entries keep first-seen order from Unique Issues",
        )
        openssl = by_issue["Outdated OpenSSL"]
        self.assertEqual(openssl["source"], "nexpose")
        self.assertEqual(
            openssl["systems"],
            "10.0.0.1 [host-a]\n10.0.0.2",
            "Labels are deduped, first-seen order",
        )
        self.assertEqual(
            openssl["risk"], "High", "Highest risk wins for duplicate issues"
        )
        self.assertEqual(
            openssl["action"], "Upgrade OpenSSL", "First non-empty remediation wins"
        )
        self.assertIsNone(openssl["score"])

        smb = by_issue["SMB Signing Disabled"]
        self.assertEqual(smb["systems"], "host-c", "Hostname only when IP is blank")
        self.assertEqual(smb["risk"], "Medium")

        icmp = by_issue["ICMP Timestamp"]
        self.assertEqual(icmp["systems"], "")
        self.assertEqual(icmp["risk"], "Low")

        self.assertIn(
            "Issue 'ICMP Timestamp' has no systems in All Issues.", result.warnings
        )
        self.assertTrue(
            any("Duplicate issue 'Outdated OpenSSL'" in w for w in result.warnings)
        )

    def test_sheet_and_header_tolerance(self):
        data = nexpose_workbook(
            unique_sheet="  unique ISSUES ",
            all_sheet="ALL issues",
            unique_headers=[" risk", "ISSUE ", "Impact", "remediation", "Category"],
            all_headers=[
                "ip address",
                "HOSTNAME(S)",
                "Port",
                " Issue",
                "Impact",
                "Issue Details",
                "Evidence",
                "Remediation",
                "Risk",
                "Category",
            ],
        )
        result = parse_supplemental("nexpose", data)
        self.assertEqual(len(result.entries), 3)
        self.assertEqual(result.entries[0]["systems"], "10.0.0.1 [host-a]\n10.0.0.2")

    def test_issue_join_ignores_case_and_whitespace(self):
        all_rows = [
            row(
                NEXPOSE_ALL_HEADERS,
                ipaddress="10.9.9.9",
                hostnames="h",
                issue="  outdated   openssl ",
            )
        ]
        unique_rows = [
            row(
                NEXPOSE_UNIQUE_HEADERS,
                risk="High",
                issue="Outdated OpenSSL",
                remediation="Fix",
            )
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=all_rows)
        )
        self.assertEqual(result.entries[0]["systems"], "10.9.9.9 [h]")
        self.assertEqual(
            result.entries[0]["issue"],
            "Outdated OpenSSL",
            "Display text comes from Unique Issues",
        )

    def test_missing_sheet_raises(self):
        data = build_workbook(
            {
                "Unique Issues": [NEXPOSE_UNIQUE_HEADERS]
                + [row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="X", remediation="Y")]
            }
        )
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("nexpose", data)
        self.assertIn("All Issues", str(ctx.exception))
        self.assertIn(
            "Unique Issues", str(ctx.exception), "Error lists the sheets present"
        )

    def test_missing_header_raises(self):
        headers = [h for h in NEXPOSE_UNIQUE_HEADERS if h != "Remediation"]
        data = nexpose_workbook(
            unique_headers=headers, unique_rows=[row(headers, risk="High", issue="X")]
        )
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("nexpose", data)
        self.assertIn("Remediation", str(ctx.exception))
        self.assertIn("Unique Issues", str(ctx.exception))

    def test_zero_rows_raises(self):
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("nexpose", nexpose_workbook(unique_rows=[], all_rows=[]))
        self.assertIn("No usable rows", str(ctx.exception))

    def test_empty_sheet_raises(self):
        data = build_workbook({"Unique Issues": [], "All Issues": [NEXPOSE_ALL_HEADERS]})
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("nexpose", data)
        self.assertIn("empty", str(ctx.exception))

    def test_invalid_file_raises(self):
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("nexpose", b"this is not a workbook")
        self.assertIn("not a valid XLSX", str(ctx.exception))

    def test_unknown_or_empty_risk_warns(self):
        unique_rows = [
            row(NEXPOSE_UNIQUE_HEADERS, risk="Purple", issue="A", remediation="Fix A"),
            row(NEXPOSE_UNIQUE_HEADERS, risk="", issue="B", remediation="Fix B"),
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=[])
        )
        self.assertIsNone(result.entries[0]["risk"])
        self.assertIsNone(result.entries[1]["risk"])
        self.assertIn("Unrecognized Risk 'Purple' for issue 'A'.", result.warnings)
        self.assertIn("Issue 'B' has no Risk value.", result.warnings)

    def test_optional_score_and_severity_columns(self):
        headers = NEXPOSE_UNIQUE_HEADERS + ["Score"]
        unique_rows = [
            row(headers, risk="High", issue="A", remediation="Fix", score=7.5),
            row(headers, risk="High", issue="B", remediation="Fix", score="n/a"),
            row(headers, risk="High", issue="C", remediation="Fix", score="9"),
        ]
        result = parse_supplemental(
            "nexpose",
            nexpose_workbook(
                unique_headers=headers, unique_rows=unique_rows, all_rows=[]
            ),
        )
        scores = {e["issue"]: e["score"] for e in result.entries}
        self.assertEqual(scores, {"A": 7.5, "B": None, "C": 9.0})

        headers = NEXPOSE_UNIQUE_HEADERS + ["Severity"]
        unique_rows = [
            row(headers, risk="High", issue="A", remediation="Fix", severity=8)
        ]
        result = parse_supplemental(
            "nexpose",
            nexpose_workbook(
                unique_headers=headers, unique_rows=unique_rows, all_rows=[]
            ),
        )
        self.assertEqual(result.entries[0]["score"], 8.0)

    def test_duplicate_keeps_highest_score(self):
        headers = NEXPOSE_UNIQUE_HEADERS + ["Score"]
        unique_rows = [
            row(headers, risk="Low", issue="A", remediation="", score=2),
            row(headers, risk="High", issue="A", remediation="Fix A", score=9),
        ]
        result = parse_supplemental(
            "nexpose",
            nexpose_workbook(
                unique_headers=headers, unique_rows=unique_rows, all_rows=[]
            ),
        )
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0]["risk"], "High")
        self.assertEqual(result.entries[0]["score"], 9.0)
        self.assertEqual(result.entries[0]["action"], "Fix A")

    def test_blank_rows_and_numeric_cells_are_tolerated(self):
        unique_rows = [
            row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="A", remediation="Fix"),
            [None] * len(NEXPOSE_UNIQUE_HEADERS),
            ["", "", "", "", ""],
            row(
                NEXPOSE_UNIQUE_HEADERS,
                risk="Low",
                issue=12345,
                remediation="Numeric issue title",
            ),
        ]
        all_rows = [
            row(
                NEXPOSE_ALL_HEADERS,
                ipaddress="10.0.0.1",
                hostnames="",
                port=443,
                issue="A",
            ),
            row(
                NEXPOSE_ALL_HEADERS,
                ipaddress="10.0.0.5",
                hostnames="",
                port=22,
                issue=12345,
            ),
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=all_rows)
        )
        self.assertEqual([e["issue"] for e in result.entries], ["A", "12345"])
        self.assertEqual(result.entries[1]["systems"], "10.0.0.5")

    def test_rows_without_issue_are_skipped(self):
        unique_rows = [
            row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="", remediation="orphan"),
            row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="A", remediation="Fix"),
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=[])
        )
        self.assertEqual(len(result.entries), 1)

    def test_all_issues_only_issues_produce_warning(self):
        all_rows = [
            row(NEXPOSE_ALL_HEADERS, ipaddress="10.0.0.1", issue="Only in All Issues")
        ]
        unique_rows = [
            row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="A", remediation="Fix")
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=all_rows)
        )
        self.assertTrue(
            any(
                "1 issue(s) appear in All Issues but not in Unique Issues" in w
                for w in result.warnings
            )
        )

    def test_text_is_truncated_to_excel_limit(self):
        long_text = "r" * (EXCEL_CELL_CHARACTER_LIMIT + 5000)
        unique_rows = [
            row(NEXPOSE_UNIQUE_HEADERS, risk="High", issue="A", remediation=long_text)
        ]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(unique_rows=unique_rows, all_rows=[])
        )
        self.assertEqual(len(result.entries[0]["action"]), EXCEL_CELL_CHARACTER_LIMIT)
        self.assertTrue(result.entries[0]["action"].endswith("…"))

    def test_extra_sheets_are_ignored(self):
        data = nexpose_workbook(
            extra_sheets={
                "High Risk Issues": [["Issue"], ["Something"]],
                "Subset of Majority Issues": [],
            }
        )
        result = parse_supplemental("nexpose", data)
        self.assertEqual(len(result.entries), 3)


class WebParserTests(SimpleTestCase):
    """Tests for the Web/Burp branch of :func:`reporting.supplemental_parsers.parse_supplemental`."""

    def test_happy_path(self):
        result = parse_supplemental("web", web_workbook())
        self.assertEqual(len(result.entries), 2)

        xss = result.entries[0]
        self.assertEqual(xss["source"], "web")
        self.assertEqual(xss["issue"], "Cross-site scripting (reflected)")
        self.assertEqual(
            xss["systems"],
            "https://a.example/login\nhttps://b.example/search",
            "Sorted Host+Path, deduped",
        )
        self.assertEqual(xss["action"], "Encode output")
        self.assertEqual(xss["risk"], "High")
        self.assertIsNone(xss["score"])

        cookie = result.entries[1]
        self.assertEqual(cookie["systems"], "https://a.example/")
        self.assertEqual(cookie["risk"], "Low")
        self.assertEqual(result.warnings, [])

    def test_missing_header_raises(self):
        headers = [h for h in WEB_UNIQUE_HEADERS if h != "Fix"]
        data = web_workbook(
            unique_headers=headers, unique_rows=[row(headers, issue="X", risk="High")]
        )
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("web", data)
        self.assertIn("Fix", str(ctx.exception))

    def test_missing_all_issues_sheet_raises(self):
        data = build_workbook(
            {
                "Unique Issues": [WEB_UNIQUE_HEADERS]
                + [row(WEB_UNIQUE_HEADERS, issue="X", fix="F", risk="High")]
            }
        )
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("web", data)
        self.assertIn("All Issues", str(ctx.exception))

    def test_no_hosts_warns(self):
        unique_rows = [row(WEB_UNIQUE_HEADERS, issue="Lonely", fix="F", risk="Medium")]
        result = parse_supplemental(
            "web", web_workbook(unique_rows=unique_rows, all_rows=[])
        )
        self.assertEqual(result.entries[0]["systems"], "")
        self.assertIn("Issue 'Lonely' has no hosts in All Issues.", result.warnings)

    def test_blank_host_and_path_rows_are_skipped(self):
        all_rows = [
            row(WEB_ALL_HEADERS, issue="A", host="", path=""),
            row(WEB_ALL_HEADERS, issue="A", host="https://x.example", path="/p"),
        ]
        unique_rows = [row(WEB_UNIQUE_HEADERS, issue="A", fix="F", risk="High")]
        result = parse_supplemental(
            "web", web_workbook(unique_rows=unique_rows, all_rows=all_rows)
        )
        self.assertEqual(result.entries[0]["systems"], "https://x.example/p")

    def test_score_column_honored(self):
        headers = WEB_UNIQUE_HEADERS + ["Score"]
        unique_rows = [row(headers, issue="A", fix="F", risk="High", score=6.4)]
        result = parse_supplemental(
            "web",
            web_workbook(unique_headers=headers, unique_rows=unique_rows, all_rows=[]),
        )
        self.assertEqual(result.entries[0]["score"], 6.4)


class ParseSupplementalTests(SimpleTestCase):
    def test_unknown_kind_raises(self):
        with self.assertRaises(SupplementalParseError) as ctx:
            parse_supplemental("firewall", nexpose_workbook())
        self.assertIn("Unknown supplemental kind", str(ctx.exception))

    def test_oversize_file_raises(self):
        with mock.patch.object(supplemental_parsers, "MAX_SUPPLEMENTAL_UPLOAD_BYTES", 10):
            with self.assertRaises(SupplementalParseError) as ctx:
                parse_supplemental("nexpose", nexpose_workbook())
        self.assertIn("larger than", str(ctx.exception))


class IssueDetailTests(SimpleTestCase):
    """Impact and Evidence from ``All Issues`` are kept per unique issue for the AI review."""

    def test_nexpose_collects_first_impact_and_distinct_evidence(self):
        h = NEXPOSE_ALL_HEADERS
        rows = [
            row(h, ipaddress="10.0.0.1", issue="Outdated OpenSSL", impact="", evidence="banner one"),
            row(h, ipaddress="10.0.0.2", issue="Outdated OpenSSL", impact="Impact A", evidence="banner one"),
            row(h, ipaddress="10.0.0.3", issue="Outdated OpenSSL", impact="Impact ignored", evidence="banner two"),
            row(h, ipaddress="10.0.0.4", issue="Outdated OpenSSL", evidence="banner three"),
            row(h, ipaddress="10.0.0.5", issue="Outdated OpenSSL", evidence="banner four"),
            row(h, hostnames="host-c", issue="SMB Signing Disabled"),
        ]
        result = parse_supplemental("nexpose", nexpose_workbook(all_rows=rows))
        by_issue = {entry["issue"]: entry for entry in result.entries}

        openssl = by_issue["Outdated OpenSSL"]
        self.assertEqual(openssl["impact"], "Impact A", "First non-empty Impact wins")
        self.assertEqual(openssl["evidence"], ["banner one", "banner two", "banner three"])
        self.assertEqual(len(openssl["evidence"]), MAX_EVIDENCE_SAMPLES)

        smb = by_issue["SMB Signing Disabled"]
        self.assertEqual(smb["impact"], "")
        self.assertEqual(smb["evidence"], [])

        # Issues with no All Issues rows still carry the keys
        self.assertEqual(by_issue["ICMP Timestamp"]["impact"], "")
        self.assertEqual(by_issue["ICMP Timestamp"]["evidence"], [])

    def test_web_collects_impact_and_evidence(self):
        h = WEB_ALL_HEADERS
        rows = [
            row(h, issue="Cross-site scripting (reflected)", host="https://a.example", path="/x",
                impact="Script runs in victim browser", evidence="<script>alert(1)</script>"),
            row(h, issue="Cross-site scripting (reflected)", host="https://b.example", path="/y",
                evidence="<script>alert(1)</script>"),
            row(h, issue="Cookie without HttpOnly flag set", host="https://a.example", path="/"),
        ]
        result = parse_supplemental("web", web_workbook(all_rows=rows))
        by_issue = {entry["issue"]: entry for entry in result.entries}

        xss = by_issue["Cross-site scripting (reflected)"]
        self.assertEqual(xss["impact"], "Script runs in victim browser")
        self.assertEqual(xss["evidence"], ["<script>alert(1)</script>"], "Duplicate evidence is kept once")
        self.assertEqual(by_issue["Cookie without HttpOnly flag set"]["evidence"], [])

    def test_evidence_is_truncated(self):
        h = WEB_ALL_HEADERS
        rows = [
            row(h, issue="Cross-site scripting (reflected)", host="https://a.example", path="/x",
                evidence="e" * (MAX_EVIDENCE_CHARS + 500)),
            row(h, issue="Cookie without HttpOnly flag set", host="https://a.example", path="/"),
        ]
        result = parse_supplemental("web", web_workbook(all_rows=rows))
        evidence = result.entries[0]["evidence"]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(len(evidence[0]), MAX_EVIDENCE_CHARS)
        self.assertTrue(evidence[0].endswith("…"))

    def test_placeholder_evidence_is_ignored(self):
        h = WEB_ALL_HEADERS
        rows = [
            row(h, issue="Cross-site scripting (reflected)", host="https://a.example", path="/x",
                evidence="See response(s)"),
            row(h, issue="Cross-site scripting (reflected)", host="https://b.example", path="/y",
                evidence=" see  Response(S) "),
            row(h, issue="Cross-site scripting (reflected)", host="https://c.example", path="/z",
                evidence="Real evidence"),
            row(h, issue="Cookie without HttpOnly flag set", host="https://a.example", path="/",
                evidence="N/A"),
        ]
        result = parse_supplemental("web", web_workbook(all_rows=rows))
        by_issue = {entry["issue"]: entry for entry in result.entries}
        self.assertEqual(by_issue["Cross-site scripting (reflected)"]["evidence"], ["Real evidence"])
        self.assertEqual(by_issue["Cookie without HttpOnly flag set"]["evidence"], [])

    def test_nexpose_issue_details_fill_in_blank_impact(self):
        h = NEXPOSE_ALL_HEADERS
        rows = [
            row(h, ipaddress="10.0.0.1", issue="Outdated OpenSSL", impact="", issuedetails="Detail one"),
            row(h, ipaddress="10.0.0.2", issue="Outdated OpenSSL", impact="Impact A", issuedetails="Detail two"),
            row(h, hostnames="host-c", issue="SMB Signing Disabled", issuedetails="SMB detail"),
        ]
        result = parse_supplemental("nexpose", nexpose_workbook(all_rows=rows))
        by_issue = {entry["issue"]: entry for entry in result.entries}
        self.assertEqual(by_issue["Outdated OpenSSL"]["impact"], "Impact A", "A real Impact beats the fallback")
        self.assertEqual(by_issue["SMB Signing Disabled"]["impact"], "SMB detail")
        self.assertEqual(by_issue["ICMP Timestamp"]["impact"], "")
        for entry in result.entries:
            self.assertNotIn("_fallback", entry)

    def test_missing_detail_columns_are_tolerated(self):
        headers = ["IP Address", "Hostname(s)", "Issue"]
        rows = [row(headers, ipaddress="10.0.0.1", issue="Outdated OpenSSL")]
        result = parse_supplemental(
            "nexpose", nexpose_workbook(all_rows=rows, all_headers=headers)
        )
        self.assertEqual(result.entries[0]["impact"], "")
        self.assertEqual(result.entries[0]["evidence"], [])

        headers = ["Issue", "Host", "Path"]
        rows = [row(headers, issue="Cross-site scripting (reflected)", host="https://a.example", path="/")]
        result = parse_supplemental("web", web_workbook(all_rows=rows, all_headers=headers))
        self.assertEqual(result.entries[0]["impact"], "")
        self.assertEqual(result.entries[0]["evidence"], [])


class IterSupplementalEntriesTests(SimpleTestCase):
    """Tests for :func:`reporting.supplemental_parsers.iter_supplemental_entries`."""

    def test_orders_web_first_and_skips_malformed_entries(self):
        from types import SimpleNamespace

        nexpose = SimpleNamespace(kind="nexpose", cap_entries=[{"issue": "N1"}, "junk", {"issue": "N2"}])
        web = SimpleNamespace(kind="web", cap_entries=[{"issue": "W1"}])
        broken = SimpleNamespace(kind="web", cap_entries=None)
        unknown = SimpleNamespace(kind="other", cap_entries=[{"issue": "O1"}])

        pairs = iter_supplemental_entries([nexpose, unknown, broken, web])
        self.assertEqual([entry["issue"] for _, entry in pairs], ["W1", "N1", "N2", "O1"])
        self.assertIs(pairs[0][0], web)
