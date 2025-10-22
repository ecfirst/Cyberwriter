"""Unit tests for workbook helper utilities."""

# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.rolodex.workbook import build_workbook_sections


class WorkbookHelpersTests(SimpleTestCase):
    """Validate workbook summary helpers."""

    def test_build_workbook_sections_returns_structured_output(self):
        workbook_data = {
            "client": {"name": "Example"},
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
        self.assertEqual(sections[0]["tree"]["items"][0]["value"]["display"], "Example")

    def test_non_mapping_returns_empty_sections(self):
        self.assertEqual(build_workbook_sections(None), [])
        self.assertEqual(build_workbook_sections([]), [])
