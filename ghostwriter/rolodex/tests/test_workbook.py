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

    def test_firewall_requirement_included_when_unique_values_present(self):
        workbook_data = {
            "firewall": {"unique": 2},
        }

        _, required_files = build_data_configuration(workbook_data)

        labels = [entry["label"] for entry in required_files]
        self.assertIn("firewall_csv.csv", labels)

    def test_firewall_device_questions_include_type_field(self):
        workbook_data = {
            "firewall": {
                "devices": [
                    {"name": "FW-1"},
                    {"name": "Branch"},
                    "Unnamed Entry",
                ]
            }
        }

        questions, _ = build_data_configuration(workbook_data)

        firewall_questions = [q for q in questions if q["section"] == "Firewall"]
        self.assertEqual(len(firewall_questions), 3)
        first_question = firewall_questions[0]
        self.assertEqual(first_question["label"], "Firewall Type")
        self.assertEqual(first_question["subheading"], "FW-1")
        self.assertTrue(first_question["key"].startswith("firewall_"))
        self.assertTrue(first_question["key"].endswith("_type"))
        last_question = firewall_questions[-1]
        self.assertEqual(last_question["subheading"], "Unnamed Entry")

    def test_osint_risk_questions_added_when_counts_present(self):
        workbook_data = {
            "osint": {
                "total_squat": 1,
                "total_buckets": 2,
                "total_leaks": 3,
            }
        }

        questions, _ = build_data_configuration(workbook_data)

        intelligence_questions = [q for q in questions if q["section"] == "Intelligence"]
        keys = {question["key"] for question in intelligence_questions}

        self.assertIn("osint_squat_concern", keys)
        self.assertIn("osint_bucket_risk", keys)
        self.assertIn("osint_leaked_creds_risk", keys)

        bucket_question = next(q for q in intelligence_questions if q["key"] == "osint_bucket_risk")
        self.assertEqual(bucket_question["label"], "What is the risk you would assign to the exposed buckets found?")
        self.assertEqual(
            bucket_question["field_kwargs"]["choices"],
            (("High", "High"), ("Medium", "Medium"), ("Low", "Low")),
        )
