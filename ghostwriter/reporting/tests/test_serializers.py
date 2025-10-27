# Standard Libraries
import json
import logging
from datetime import date

# Django Imports
from django.conf import settings
from django.test import TestCase
from django.utils import dateformat

# 3rd Party Libraries
from rest_framework.renderers import JSONRenderer

# Ghostwriter Libraries
from ghostwriter.factories import GenerateMockProject, OplogEntryFactory, OplogFactory
from ghostwriter.modules.custom_serializers import FullProjectSerializer, ReportDataSerializer

logging.disable(logging.CRITICAL)


class ReportDataSerializerTests(TestCase):
    """Collection of tests for custom report serializer."""

    @classmethod
    def setUpTestData(cls):
        cls.num_of_contacts = 3
        cls.num_of_assignments = 3
        cls.num_of_findings = 10
        cls.num_of_scopes = 3
        cls.num_of_targets = 10
        cls.num_of_objectives = 3
        cls.num_of_subtasks = 5
        cls.num_of_domains = 6
        cls.num_of_servers = 3
        cls.num_of_deconflictions = 3

        cls.client, cls.project, cls.report = GenerateMockProject(
            cls.num_of_contacts,
            cls.num_of_assignments,
            cls.num_of_findings,
            cls.num_of_scopes,
            cls.num_of_targets,
            cls.num_of_objectives,
            cls.num_of_subtasks,
            cls.num_of_domains,
            cls.num_of_servers,
            cls.num_of_deconflictions,
        )

        # Create an object with a null value for later testing
        oplog = OplogFactory.create(project=cls.project)
        OplogEntryFactory.create(tool=None, oplog_id=oplog)

        cls.serializer = ReportDataSerializer(
            cls.report,
            exclude=[
                "id",
            ],
        )

    def setUp(self):
        pass

    def test_json_rendering(self):
        try:
            report_json = JSONRenderer().render(self.serializer.data)
            _ = json.loads(report_json)
        except Exception:
            self.fail("Failed to render report data as JSON")

    def test_expected_json_keys_exist(self):
        report_json = JSONRenderer().render(self.serializer.data)
        report_json = json.loads(report_json)

        # Check expected keys are present
        self.assertTrue("report_date" in report_json)
        self.assertTrue("project" in report_json)
        self.assertTrue("client" in report_json)
        self.assertTrue("team" in report_json)
        self.assertTrue("objectives" in report_json)
        self.assertTrue("targets" in report_json)
        self.assertTrue("scope" in report_json)
        self.assertTrue("deconflictions" in report_json)
        self.assertTrue("infrastructure" in report_json)
        self.assertTrue("findings" in report_json)
        self.assertTrue("docx_template" in report_json)
        self.assertTrue("pptx_template" in report_json)
        self.assertTrue("company" in report_json)
        self.assertTrue("totals" in report_json)

    def test_extra_values(self):
        report_json = JSONRenderer().render(self.serializer.data)
        report_json = json.loads(report_json)

        self.assertEqual(
            report_json["report_date"],
            dateformat.format(date.today(), settings.DATE_FORMAT),
        )

        totals = report_json["totals"]
        self.assertEqual(totals["findings"], self.num_of_findings)
        self.assertEqual(totals["targets"], self.num_of_targets)
        self.assertEqual(totals["team"], self.num_of_assignments)
        self.assertEqual(totals["objectives"], self.num_of_objectives)

        total_scope_lines = 0
        for scope in report_json["scope"]:
            total_scope_lines += scope["total"]

        self.assertEqual(totals["scope"], total_scope_lines)

        completed_objectives = 0
        for objective in report_json["objectives"]:
            if objective["complete"]:
                completed_objectives += 1

        self.assertEqual(totals["objectives_completed"], completed_objectives)

        for f in report_json["findings"]:
            self.assertTrue("ordering" in f)

    def test_values_are_not_empty(self):
        report_json = JSONRenderer().render(self.serializer.data)
        report_json = json.loads(report_json)

        for key in report_json:
            self.assertTrue(report_json[key] is not None)

        for log in report_json["logs"]:
            for entry in log["entries"]:
                print(entry["tool"])
                self.assertTrue(entry["tool"] is not None)


class ProjectSerializerDataResponsesTests(TestCase):
    """Ensure project data responses are reshaped for templating."""

    @classmethod
    def setUpTestData(cls):
        cls.client, cls.project, _ = GenerateMockProject()
        cls.workbook_data = {
            "ad": {
                "domains": [
                    {"domain": "corp.example.com"},
                ]
            },
            "password": {
                "policies": [
                    {"domain_name": "corp.example.com"},
                ]
            },
            "endpoint": {
                "domains": [
                    {
                        "domain": "corp.example.com",
                        "systems_ood": 25,
                        "open_wifi": 5,
                    },
                    {
                        "domain": "lab.example.com",
                        "systems_ood": 43,
                        "open_wifi": 12,
                    },
                ]
            },
            "firewall": {
                "devices": [
                    {"name": "Edge-FW01"},
                    {"name": "Core-FW02"},
                ]
            },
        }

        cls.legacy_responses = {
            "cloud_config_risk": "low",
            "wireless_psk_risk": "medium",
            "system_config_risk": "medium",
            "wireless_open_risk": "high",
            "osint_squat_concern": "example.com",
            "osint_bucket_risk": "High",
            "osint_leaked_creds_risk": "Medium",
            "wireless_rogue_risk": "medium",
            "wireless_hidden_risk": "low",
            "wireless_segmentation_ssids": ["Guest"],
            "wireless_segmentation_tested": True,
            "wireless_psk_rotation_concern": "yes",
            "password_corpexamplecom_risk": "medium",
            "endpoint_labexamplecom_av_gap": "high",
            "endpoint_corpexamplecom_av_gap": "medium",
            "ad_corpexamplecom_domain_admins": "high",
            "ad_corpexamplecom_old_passwords": "low",
            "ad_corpexamplecom_generic_logins": "medium",
            "endpoint_labexamplecom_open_wifi": "high",
            "endpoint_corpexamplecom_open_wifi": "low",
            "ad_corpexamplecom_generic_accounts": "high",
            "ad_corpexamplecom_disabled_accounts": "high",
            "ad_corpexamplecom_enterprise_admins": "medium",
            "ad_corpexamplecom_expired_passwords": "low",
            "ad_corpexamplecom_inactive_accounts": "medium",
            "ad_corpexamplecom_passwords_never_expire": "low",
            "firewall_edge-fw01_type": "Next-Gen",
            "firewall_core-fw02_type": "Appliance",
        }

    def setUp(self):
        self.project = self.__class__.project
        self.project.refresh_from_db()

    def test_legacy_responses_are_restructured(self):
        self.project.workbook_data = self.workbook_data
        self.project.data_responses = self.legacy_responses
        self.project.save(update_fields=["workbook_data", "data_responses"])

        serializer = FullProjectSerializer(self.project)
        project_data = serializer.data["project"]
        responses = project_data["data_responses"]

        self.assertEqual(responses["cloud_config_risk"], "low")
        self.assertEqual(responses["wireless_segmentation_ssids"], ["Guest"])
        self.assertEqual(responses["osint_bucket_risk"], "High")
        self.assertEqual(responses["osint_leaked_creds_risk"], "Medium")

        ad_entries = responses["ad"]
        self.assertIsInstance(ad_entries, list)
        self.assertEqual(len(ad_entries), 1)
        self.assertEqual(ad_entries[0]["domain"], "corp.example.com")
        self.assertEqual(ad_entries[0]["domain_admins"], "high")
        self.assertEqual(ad_entries[0]["inactive_accounts"], "medium")

        password_entries = responses["password"]
        self.assertEqual(password_entries, [{"domain": "corp.example.com", "risk": "medium"}])
        self.assertNotIn(
            "corpexamplecom", [entry["domain"] for entry in password_entries]
        )

        endpoint_summary = responses["endpoint"]
        self.assertIn("entries", endpoint_summary)
        endpoint_entries = endpoint_summary["entries"]
        self.assertEqual(len(endpoint_entries), 2)
        corp_endpoint = next(entry for entry in endpoint_entries if entry["domain"] == "corp.example.com")
        lab_endpoint = next(entry for entry in endpoint_entries if entry["domain"] == "lab.example.com")
        self.assertEqual(corp_endpoint["av_gap"], "medium")
        self.assertEqual(corp_endpoint["open_wifi"], "low")
        self.assertEqual(lab_endpoint["av_gap"], "high")
        self.assertEqual(lab_endpoint["open_wifi"], "high")
        self.assertNotIn(
            "corpexamplecom", [entry["domain"] for entry in endpoint_entries]
        )
        self.assertNotIn(
            "labexamplecom", [entry["domain"] for entry in endpoint_entries]
        )
        self.assertEqual(endpoint_summary["domains_str"], "corp.example.com/lab.example.com")
        self.assertEqual(endpoint_summary["ood_count_str"], "25/43")
        self.assertEqual(endpoint_summary["wifi_count_str"], "5/12")
        self.assertEqual(endpoint_summary["ood_risk_string"], "medium/high")
        self.assertEqual(endpoint_summary["wifi_risk_string"], "low/high")

        firewall_entries = responses["firewall"]
        self.assertEqual(len(firewall_entries), 2)
        edge_firewall = next(entry for entry in firewall_entries if entry["name"] == "Edge-FW01")
        core_firewall = next(entry for entry in firewall_entries if entry["name"] == "Core-FW02")
        self.assertEqual(edge_firewall["type"], "Next-Gen")
        self.assertEqual(core_firewall["type"], "Appliance")

        self.assertNotIn("password_corpexamplecom_risk", responses)
        self.assertNotIn("endpoint_corpexamplecom_av_gap", responses)
        self.assertNotIn("firewall_edge-fw01_type", responses)

    def test_new_structure_is_preserved(self):
        structured = {
            "cloud_config_risk": "low",
            "osint_bucket_risk": "High",
            "osint_leaked_creds_risk": "Medium",
            "ad": [{"domain": "corp.example.com", "domain_admins": "medium"}],
            "password": [{"domain": "corp.example.com", "risk": "low"}],
            "endpoint": {
                "entries": [
                    {"domain": "corp.example.com", "av_gap": "medium", "open_wifi": "low"},
                ],
                "domains_str": "corp.example.com",
                "ood_count_str": "25",
                "wifi_count_str": "5",
                "ood_risk_string": "medium",
                "wifi_risk_string": "low",
            },
            "firewall": [
                {"name": "Edge-FW01", "type": "Next-Gen"},
            ],
        }

        self.project.workbook_data = self.workbook_data
        self.project.data_responses = structured
        self.project.save(update_fields=["workbook_data", "data_responses"])

        serializer = FullProjectSerializer(self.project)
        responses = serializer.data["project"]["data_responses"]
        self.assertEqual(responses, structured)
