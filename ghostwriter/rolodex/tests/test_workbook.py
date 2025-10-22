"""Unit tests for workbook helper utilities."""

# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.rolodex.workbook import build_data_configuration, build_workbook_sections


class WorkbookHelpersTests(SimpleTestCase):
    """Validate workbook summary helpers."""

    def test_build_workbook_sections_returns_structured_output(self):
        workbook_data = {
            "client": {"name": "Example", "total": 3},
            "report_card": {"overall": "A"},
        }

        sections = build_workbook_sections(workbook_data)

        self.assertEqual(len(sections), 2)
        self.assertEqual(sections[0]["key"], "client")
        self.assertEqual(sections[0]["title"], "Client")
        self.assertEqual(sections[0]["slug"], "workbook-client")
        self.assertEqual(sections[0]["script_id"], "workbook-section-data-workbook-client")
        self.assertEqual(sections[0]["data"], {"name": "Example"})
        self.assertEqual(sections[0]["tree"]["type"], "dict")
        self.assertEqual(sections[0]["tree"]["items"][0]["label"], "Name")
        self.assertEqual(sections[0]["tree"]["items"][0]["value"]["type"], "value")
        items = sections[0]["tree"]["items"]
        self.assertEqual(items[0]["value"]["display"], "Example")
        self.assertEqual(items[1]["label"], "Total")
        self.assertEqual(items[1]["value"]["display"], "3")

    def test_non_mapping_returns_empty_sections(self):
        self.assertEqual(build_workbook_sections(None), [])
        self.assertEqual(build_workbook_sections([]), [])

    def test_sections_follow_display_order(self):
        workbook_data = {
            "wireless": {},
            "client": {},
            "general": {},
        }

        sections = build_workbook_sections(workbook_data)

        ordered_keys = [section["key"] for section in sections]
        self.assertEqual(ordered_keys[:3], ["client", "general", "wireless"])

    def test_required_files_include_slug(self):
        workbook_data = {
            "dns": {"records": [{"domain": "example.com"}]},
        }

        _, required_files = build_data_configuration(workbook_data)

        self.assertTrue(required_files)
        self.assertIn("slug", required_files[0])
        self.assertEqual(required_files[0]["slug"], "required_dns-report-csv_example-com")
