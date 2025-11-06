"""Unit tests for workbook helper utilities."""

# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.rolodex.forms_workbook import SummaryMultipleChoiceField
from ghostwriter.rolodex.workbook import (
    DNS_SOA_FIELD_CHOICES,
    SCOPE_CHOICES,
    WEAK_PSK_SUMMARY_MAP,
    YES_NO_CHOICES,
    build_data_configuration,
    build_scope_summary,
    build_workbook_sections,
    normalize_scope_selection,
)


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

    def test_scope_question_added_with_defaults(self):
        questions, _ = build_data_configuration({}, project_type="Gold")

        self.assertGreaterEqual(len(questions), 2)
        scope_question = questions[0]
        self.assertEqual(scope_question["key"], "assessment_scope")
        self.assertEqual(scope_question["field_kwargs"].get("choices"), SCOPE_CHOICES)
        self.assertEqual(
            scope_question["field_kwargs"].get("initial"),
            ["external", "internal", "firewall"],
        )

        followup = next((q for q in questions if q["key"] == "assessment_scope_cloud_on_prem"), None)
        self.assertIsNotNone(followup)
        assert followup is not None  # pragma: no cover - typing aid
        self.assertEqual(followup["field_kwargs"].get("choices"), YES_NO_CHOICES)

    def test_nexpose_csv_requirements_added_for_positive_totals(self):
        workbook_data = {
            "external_nexpose": {"total": 1},
            "internal_nexpose": {"total": 2},
            "iot_iomt_nexpose": {"total": 4},
        }

        _, required_files = build_data_configuration(workbook_data)

        labels = {entry["label"] for entry in required_files}
        self.assertIn("external_nexpose_csv.csv", labels)
        self.assertIn("internal_nexpose_csv.csv", labels)
        self.assertIn("iot_nexpose_csv.csv", labels)

    def test_iot_testing_question_added_when_iot_section_present(self):
        workbook_data = {
            "iot_iomt_nexpose": {"total": 0},
        }

        questions, _ = build_data_configuration(workbook_data)

        iot_question = next(
            (q for q in questions if q["key"] == "iot_testing_confirm"),
            None,
        )

        self.assertIsNotNone(iot_question)
        assert iot_question is not None  # pragma: no cover - clarify typing
        self.assertEqual(iot_question["label"], "Was Internal IoT/IoMT testing performed?")
        self.assertEqual(iot_question["section"], "IoT/IoMT")
        self.assertEqual(iot_question["field_kwargs"].get("choices"), YES_NO_CHOICES)
        self.assertEqual(iot_question["field_kwargs"].get("initial"), "no")

    def test_dns_soa_question_added_when_issue_present(self):
        data_artifacts = {
            "dns_issues": [
                {
                    "domain": "example.com",
                    "issues": [
                        {
                            "issue": "One or more SOA fields are outside recommended ranges",
                        }
                    ],
                }
            ]
        }

        questions, _ = build_data_configuration({}, data_artifacts=data_artifacts)

        dns_question = next(
            (q for q in questions if q["key"] == "dns_example-com_soa_fields"),
            None,
        )

        self.assertIsNotNone(dns_question)
        assert dns_question is not None  # pragma: no cover - clarify typing
        self.assertEqual(dns_question["section"], "DNS")
        self.assertEqual(dns_question["subheading"], "example.com")
        self.assertEqual(dns_question["field_kwargs"].get("choices"), DNS_SOA_FIELD_CHOICES)

    def test_nexpose_csv_requirements_skip_zero_totals(self):
        workbook_data = {
            "external_nexpose": {"total": 0},
            "internal_nexpose": {"total": 0},
            "iot_iomt_nexpose": {"total": 0},
        }

        _, required_files = build_data_configuration(workbook_data)

        labels = {entry["label"] for entry in required_files}
        self.assertNotIn("external_nexpose_csv.csv", labels)
        self.assertNotIn("internal_nexpose_csv.csv", labels)
        self.assertNotIn("iot_nexpose_csv.csv", labels)

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

    def test_wireless_psk_questions_include_summary_and_networks(self):
        workbook_data = {"wireless": {"weak_psks": "yes"}}

        questions, _ = build_data_configuration(workbook_data)

        keys = {question["key"] for question in questions}
        self.assertIn("wireless_psk_weak_reasons", keys)
        self.assertIn("wireless_psk_masterpass", keys)
        self.assertIn("wireless_psk_masterpass_ssids", keys)

        weak_reason = next(q for q in questions if q["key"] == "wireless_psk_weak_reasons")
        self.assertIs(weak_reason["field_class"], SummaryMultipleChoiceField)
        self.assertEqual(weak_reason["field_kwargs"].get("summary_map"), WEAK_PSK_SUMMARY_MAP)

    def test_scope_summary_generation(self):
        summary = build_scope_summary(["external", "internal", "firewall"], None)
        self.assertEqual(
            summary,
            "External network and systems, Internal network and systems and Firewall configuration(s) & rules",
        )

        cloud_on_prem = build_scope_summary(["external", "cloud"], "yes")
        self.assertEqual(
            cloud_on_prem,
            "External network and systems, Cloud/On-Prem network and systems and Cloud management configuration",
        )

        cloud_only = build_scope_summary(["external", "cloud"], "no")
        self.assertEqual(
            cloud_only,
            "External network and systems, Cloud systems and Cloud management configuration",
        )

    def test_scope_selection_normalization(self):
        ordered = normalize_scope_selection(["cloud", "external", "wireless"])
        self.assertEqual(ordered, ["external", "wireless", "cloud"])
        self.assertEqual(normalize_scope_selection("internal"), ["internal"])
