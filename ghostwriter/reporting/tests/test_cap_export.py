# Standard Libraries
import logging
import shutil
import tempfile

# Django Imports
from django.test import TestCase, override_settings

# Ghostwriter Libraries
from ghostwriter.factories import ReportFactory, ReportFindingLinkFactory, SeverityFactory
from ghostwriter.modules.reportwriter.report.cap_xlsx import ExportReportCapXlsx
from ghostwriter.reporting.models import ReportSupplementalFile
from ghostwriter.reporting.tests.supplemental_fixtures import (
    nexpose_workbook,
    read_workbook,
    sheet_rows,
    uploaded,
    web_workbook,
)

logging.disable(logging.CRITICAL)

MEDIA_ROOT = tempfile.mkdtemp(prefix="gw-cap-export-")


def tearDownModule():
    shutil.rmtree(MEDIA_ROOT, ignore_errors=True)


def entry(source, issue, risk=None, score=None, systems="sys", action="act"):
    return {
        "source": source,
        "issue": issue,
        "systems": systems,
        "action": action,
        "risk": risk,
        "score": score,
    }


def export(report):
    exporter = ExportReportCapXlsx(report, include_bloodhound=False)
    output = exporter.run()
    return exporter, read_workbook(output.getvalue())


def issues(worksheet):
    """Issue column of all data rows, in sheet order."""
    return [row[1] for row in sheet_rows(worksheet)[1:]]


def sev_by_issue(worksheet):
    return {row[1]: row[0] for row in sheet_rows(worksheet)[1:]}


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class ExportReportCapXlsxTests(TestCase):
    """Tests for :class:`modules.reportwriter.report.cap_xlsx.ExportReportCapXlsx`."""

    @classmethod
    def setUpTestData(cls):
        cls.report = ReportFactory()
        critical = SeverityFactory(severity="Critical", weight=0)
        high = SeverityFactory(severity="High", weight=1)
        cls.high = high
        medium = SeverityFactory(severity="Medium", weight=2)
        low = SeverityFactory(severity="Low", weight=3)
        info = SeverityFactory(severity="Informational", weight=4)
        weird = SeverityFactory(severity="Weird", weight=5)

        def finding(title, severity, cvss, **kwargs):
            return ReportFindingLinkFactory(
                report=cls.report,
                title=title,
                severity=severity,
                cvss_score=cvss,
                affected_entities=kwargs.pop("affected_entities", "<p>host-1</p>"),
                mitigation=kwargs.pop("mitigation", "<p>Patch now</p>"),
                **kwargs,
            )

        finding("Crit", critical, 9.8)
        finding("High", high, 7.5)
        finding("Med", medium, 5.0)
        finding("Low", low, 2.0)
        finding("Info", info, 0.0, affected_entities="", mitigation="")
        finding("Weird-7.1", weird, 7.1)
        finding("Weird-4.0", weird, 4.0)
        finding("Weird-1.0", weird, 1.0)
        finding("Weird-none", weird, 0.0)
        # Shadowed by supplemental rows below: exact match, and a case/whitespace variant
        finding("W-Med", high, 9.0)
        finding("  n-high ", critical, 9.9)

        ReportSupplementalFile.objects.create(
            report=cls.report,
            kind="nexpose",
            document=uploaded("nexpose.xlsx", nexpose_workbook()),
            original_filename="nexpose.xlsx",
            cap_entries=[
                entry(
                    "nexpose",
                    "N-High",
                    risk="High",
                    systems="10.0.0.1 [host-a]",
                    action="Fix N",
                ),
                entry("nexpose", "N-5.5", score=5.5),
                entry("nexpose", "N-none"),
                entry("nexpose", "N-Low", risk="Low", score=3),
            ],
            row_count=4,
        )
        ReportSupplementalFile.objects.create(
            report=cls.report,
            kind="web",
            document=uploaded("web.xlsx", web_workbook()),
            original_filename="web.xlsx",
            cap_entries=[
                entry("web", "W-Med", risk="Medium"),
                entry("web", "W-5.5", score=5.5),
                entry("web", "W-4.5", score=4.5),
                entry("web", "W-8", score=8),
                "not a dict",
            ],
            row_count=4,
        )

    def test_sheet_names_and_headers(self):
        _, workbook = export(self.report)
        self.assertEqual(
            workbook.sheetnames, ["High Priority", "Med Priority", "Lower Priority"]
        )
        for name in workbook.sheetnames:
            self.assertEqual(sheet_rows(workbook[name])[0], ExportReportCapXlsx.HEADERS)

    def test_high_priority_rows_and_order(self):
        _, workbook = export(self.report)
        ws = workbook["High Priority"]
        # Rank is equal within a tab, so rows sort by score descending; unscored rows last
        self.assertEqual(issues(ws), ["Crit", "W-8", "High", "Weird-7.1", "N-High"])
        self.assertEqual(
            sev_by_issue(ws),
            {
                "Crit": "Critical",
                "W-8": "8",
                "High": "High",
                "Weird-7.1": "Weird",
                "N-High": "High",
            },
        )

    def test_med_priority_rows_and_tie_order(self):
        _, workbook = export(self.report)
        ws = workbook["Med Priority"]
        # Ties keep source order: findings, then web, then nexpose
        self.assertEqual(issues(ws), ["W-5.5", "N-5.5", "Med", "Weird-4.0", "W-Med"])
        sevs = sev_by_issue(ws)
        self.assertEqual(sevs["W-Med"], "Medium")
        self.assertEqual(sevs["N-5.5"], "5.5")
        self.assertEqual(sevs["Med"], "Medium")
        self.assertEqual(sevs["Weird-4.0"], "Weird")

    def test_lower_priority_rows(self):
        _, workbook = export(self.report)
        ws = workbook["Lower Priority"]
        self.assertEqual(
            issues(ws),
            ["W-4.5", "N-Low", "Low", "Weird-1.0", "Info", "Weird-none", "N-none"],
        )
        sevs = sev_by_issue(ws)
        self.assertEqual(
            sevs["Info"],
            "Informational",
            "Informational lands in Lower with its own name",
        )
        self.assertEqual(sevs["Low"], "Low")
        self.assertEqual(sevs["Weird-1.0"], "Weird")
        self.assertEqual(sevs["Weird-none"], "Weird")
        self.assertEqual(sevs["N-none"], "", "No risk and no score leaves Sev blank")
        self.assertEqual(sevs["N-Low"], "3")
        self.assertEqual(
            sevs["W-4.5"], "4.5", "Web score 4.5 is below the web medium threshold of 5"
        )

    def test_finding_rich_text_rendered_to_plain_text(self):
        _, workbook = export(self.report)
        rows = {row[1]: row for row in sheet_rows(workbook["High Priority"])[1:]}
        self.assertEqual(rows["Crit"][2], "host-1")
        self.assertEqual(rows["Crit"][3], "Patch now")
        rows = {row[1]: row for row in sheet_rows(workbook["Lower Priority"])[1:]}
        self.assertEqual(
            rows["Info"][2], "", "Empty affected entities render as an empty cell"
        )
        self.assertEqual(rows["Info"][3], "")
        self.assertEqual(rows["N-Low"][2], "sys")
        self.assertEqual(rows["N-Low"][3], "act")

    def test_tracking_columns_are_blank(self):
        _, workbook = export(self.report)
        for name in workbook.sheetnames:
            for row in sheet_rows(workbook[name])[1:]:
                self.assertEqual(len(row), len(ExportReportCapXlsx.HEADERS))
                self.assertTrue(all(value is None for value in row[4:]), row)

    def test_has_rows(self):
        exporter = ExportReportCapXlsx(self.report, include_bloodhound=False)
        self.assertTrue(exporter.has_rows())

        empty_report = ReportFactory()
        self.assertFalse(
            ExportReportCapXlsx(empty_report, include_bloodhound=False).has_rows()
        )

        ReportSupplementalFile.objects.create(
            report=empty_report,
            kind="web",
            document=uploaded("web.xlsx", web_workbook()),
            cap_entries=[entry("web", "Only", risk="High")],
            row_count=1,
        )
        exporter = ExportReportCapXlsx(empty_report, include_bloodhound=False)
        self.assertTrue(exporter.has_rows())
        _, workbook = export(empty_report)
        self.assertEqual(issues(workbook["High Priority"]), ["Only"])

    def test_supplemental_row_replaces_matching_finding(self):
        _, workbook = export(self.report)
        self.assertNotIn("W-Med", issues(workbook["High Priority"]))
        med = sheet_rows(workbook["Med Priority"])[1:]
        matches = [row for row in med if row[1] == "W-Med"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Medium", "The supplemental Sev wins, not High")
        self.assertEqual(matches[0][2], "sys")
        self.assertEqual(matches[0][3], "act")

    def test_title_match_ignores_case_and_whitespace(self):
        _, workbook = export(self.report)
        for name in workbook.sheetnames:
            self.assertNotIn(
                "n-high",
                [i.strip().lower() for i in issues(workbook[name]) if i != "N-High"],
            )
        rows = {row[1]: row for row in sheet_rows(workbook["High Priority"])[1:]}
        self.assertIn("N-High", rows)
        self.assertEqual(rows["N-High"][0], "High")
        self.assertEqual(rows["N-High"][2], "10.0.0.1 [host-a]")
        self.assertEqual(issues(workbook["High Priority"]).count("N-High"), 1)

    def test_shadowed_findings_recorded(self):
        exporter = ExportReportCapXlsx(self.report, include_bloodhound=False)
        exporter.collect_rows()
        # Findings are serialized in severity order, so the Critical one comes first
        self.assertEqual(exporter.shadowed_findings, ["n-high", "W-Med"])

    def test_both_supplementals_kept_when_both_match(self):
        report = ReportFactory()
        ReportFindingLinkFactory(
            report=report,
            title="Dup",
            severity=self.high,
            cvss_score=9.0,
        )
        ReportSupplementalFile.objects.create(
            report=report,
            kind="web",
            document=uploaded("web.xlsx", web_workbook()),
            cap_entries=[entry("web", "Dup", risk="High", systems="web-host")],
            row_count=1,
        )
        ReportSupplementalFile.objects.create(
            report=report,
            kind="nexpose",
            document=uploaded("nexpose.xlsx", nexpose_workbook()),
            cap_entries=[entry("nexpose", "dup", score=7.5, systems="10.0.0.9")],
            row_count=1,
        )
        exporter, workbook = export(report)
        self.assertEqual(exporter.shadowed_findings, ["Dup"])
        high = sheet_rows(workbook["High Priority"])[1:]
        self.assertEqual([row[1] for row in high], ["Dup"])
        self.assertEqual(high[0][2], "web-host")
        med = sheet_rows(workbook["Med Priority"])[1:]
        self.assertEqual(
            [(row[0], row[1], row[2]) for row in med], [("7.5", "dup", "10.0.0.9")]
        )
        self.assertEqual(issues(workbook["Lower Priority"]), [])

    def test_no_supplementals_leaves_findings_untouched(self):
        report = ReportFactory()
        ReportFindingLinkFactory(
            report=report, title="Alpha", severity=self.high, cvss_score=8.0
        )
        ReportFindingLinkFactory(
            report=report, title="Beta", severity=self.high, cvss_score=7.0
        )
        exporter, workbook = export(report)
        self.assertEqual(exporter.shadowed_findings, [])
        self.assertEqual(issues(workbook["High Priority"]), ["Alpha", "Beta"])
        self.assertEqual(
            sev_by_issue(workbook["High Priority"]), {"Alpha": "High", "Beta": "High"}
        )

    def test_collect_rows_is_memoized(self):
        exporter = ExportReportCapXlsx(self.report, include_bloodhound=False)
        self.assertIs(exporter.collect_rows(), exporter.collect_rows())

    def test_filename_renders(self):
        exporter = ExportReportCapXlsx(self.report, include_bloodhound=False)
        filename = exporter.render_filename(
            ExportReportCapXlsx.FILENAME_TEMPLATE, ext="xlsx"
        )
        self.assertIn("Cybersecurity Report Corrective Action Plan", filename)
        self.assertIn(self.report.project.client.name, filename)
        self.assertTrue(filename.endswith(".xlsx"))
