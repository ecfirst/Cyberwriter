"""Tests for project data file parsing helpers."""

# Standard Libraries
import csv
import io
from typing import Dict, Iterable

# Django Imports
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import GenerateMockProject
from ghostwriter.rolodex.data_parsers import (
    NEXPOSE_ARTIFACT_DEFINITIONS,
    normalize_nexpose_artifact_payload,
    normalize_nexpose_artifacts_map,
)
from ghostwriter.rolodex.models import ProjectDataFile


NEXPOSE_HEADERS: Iterable[str] = (
    "Asset IP Address",
    "Hostname(s)",
    "Service Port",
    "Protocol",
    "Vulnerability Test Result Code",
    "Vulnerability ID",
    "Vulnerability CVE IDs",
    "Vulnerability Severity Level",
    "Vulnerability Title",
    "Details",
    "Evidence",
    "Impact",
    "Solution",
    "References",
    "ecfirst can assist",
    "Detailed Remediation",
    "Category",
)


class NexposeDataParserTests(TestCase):
    """Validate Nexpose CSV parsing behaviour."""

    @classmethod
    def setUpTestData(cls):
        cls.client, cls.project, _ = GenerateMockProject()

    def _assert_default_nexpose_artifacts(self, artifacts):
        for definition in NEXPOSE_ARTIFACT_DEFINITIONS.values():
            artifact = artifacts.get(definition["artifact_key"])
            self.assertIsNotNone(
                artifact,
                msg=f"Missing Nexpose artifact for {definition['artifact_key']}",
            )
            normalized = normalize_nexpose_artifact_payload(artifact)
            self.assertEqual(normalized.get("label"), definition["label"])
            for severity_key in ("high", "med", "low"):
                group = normalized.get(severity_key)
                self.assertIsNotNone(group)
                self.assertEqual(group["total_unique"], 0)
                self.assertEqual(group["items"], [])

    def _build_csv_file(self, filename: str, rows: Iterable[Dict[str, str]]) -> SimpleUploadedFile:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=NEXPOSE_HEADERS)
        writer.writeheader()
        for row in rows:
            data = {header: "" for header in NEXPOSE_HEADERS}
            data.update(row)
            writer.writerow(data)
        content = buffer.getvalue().encode("utf-8")
        buffer.close()
        return SimpleUploadedFile(filename, content, content_type="text/csv")

    def test_external_nexpose_csv_updates_data_artifacts(self):
        def add_entries(collection, title, impact, severity, count):
            for _ in range(count):
                collection.append(
                    {
                        "Vulnerability Title": title,
                        "Impact": impact,
                        "Vulnerability Severity Level": severity,
                    }
                )

        rows = []
        add_entries(rows, "Zeta Exposure", "Impact Z", "9", 3)
        add_entries(rows, "Alpha Exposure", "Impact A", "8", 2)
        add_entries(rows, "Beta Exposure", "Impact B", "8", 2)
        add_entries(rows, "Delta Problem", "Impact D", "10", 1)
        add_entries(rows, "Epsilon Risk", "Impact E", "9", 1)
        add_entries(rows, "Gamma Concern", "Impact G", "9", 1)
        add_entries(rows, "Omega Danger", "Impact O", "High", 1)
        add_entries(rows, "Medium Alpha", "Impact M1", "6", 4)
        add_entries(rows, "Medium Beta", "Impact M2", "5", 2)
        add_entries(rows, "Low Alpha", "Impact L1", "2", 3)
        add_entries(rows, "Low Beta", "Impact L2", "1", 1)

        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=self._build_csv_file("external_nexpose_csv.csv", rows),
            requirement_label="external_nexpose_csv.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.data_responses = {"custom": "value"}
        self.project.save(update_fields=["data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertEqual(self.project.data_responses, {"custom": "value"})

    def test_normalize_web_issue_artifacts(self):
        payload = {
            "web_issues": {
                "sites": [
                    {
                        "site": "portal.example.com",
                        "high": {
                            "total_unique": 1,
                            "items": [],
                        },
                        "med": {"total_unique": 0, "items": []},
                        "low": {"total_unique": 0, "items": []},
                    }
                ],
                "low_sample_string": "'SQL'",
                "med_sample_string": "",
                "high": {
                    "total_unique": 1,
                    "items": [{"issue": "SQL", "impact": "", "count": 1}],
                },
                "med": {"total_unique": 0, "items": []},
                "low": {"total_unique": 0, "items": []},
            }
        }

        normalized = normalize_nexpose_artifacts_map(payload)
        self.assertIsInstance(normalized["web_issues"], dict)
        self.assertEqual(normalized["web_issues"]["low_sample_string"], "'SQL'")
        self.assertEqual(normalized["web_issues"]["med_sample_string"], "")
        self.assertEqual(normalized["web_issues"]["high"]["total_unique"], 1)
        self.assertEqual(
            normalized["web_issues"]["high"]["items"],
            [{"issue": "SQL", "impact": "", "count": 1}],
        )
        high_group = normalized["web_issues"]["high"]
        self.assertEqual(list(high_group.items), high_group["items"])

        legacy_payload = {
            "web_issues": {
                "legacy.example.com": {
                    "high": {"total_unique": 2, "items": []},
                }
            }
        }

        normalized_legacy = normalize_nexpose_artifacts_map(legacy_payload)
        self.assertIsInstance(normalized_legacy["web_issues"], dict)
        self.assertEqual(normalized_legacy["web_issues"].get("low_sample_string"), "")
        self.assertEqual(normalized_legacy["web_issues"].get("med_sample_string"), "")
        self.assertEqual(
            normalized_legacy["web_issues"]["high"]["total_unique"], 2
        )

    def test_normalize_iot_alias(self):
        payload = {
            "iot_nexpose_vulnerabilities": {
                "label": "Legacy IoT Nexpose Vulnerabilities",
                "high": {"total_unique": 1, "items": []},
                "med": {"total_unique": 0, "items": []},
                "low": {"total_unique": 0, "items": []},
            }
        }

        normalized = normalize_nexpose_artifacts_map(payload)
        self.assertIn("iot_iomt_nexpose_vulnerabilities", normalized)
        self.assertNotIn("iot_nexpose_vulnerabilities", normalized)
        self.assertEqual(
            normalized["iot_iomt_nexpose_vulnerabilities"]["label"],
            "Legacy IoT Nexpose Vulnerabilities",
        )

        artifact = self.project.data_artifacts.get("external_nexpose_vulnerabilities")
        artifact = normalize_nexpose_artifact_payload(artifact)
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact["label"], "External Nexpose Vulnerabilities")

        high_group = artifact.get("high")
        self.assertIsInstance(high_group, dict)
        self.assertEqual(high_group["total_unique"], 7)
        high_items = high_group["items"]
        self.assertEqual(len(high_items), 5)
        self.assertEqual(high_items[0]["title"], "Zeta Exposure")
        self.assertEqual(high_items[0]["count"], 3)
        self.assertEqual(high_items[1]["title"], "Alpha Exposure")
        self.assertEqual(high_items[1]["count"], 2)

        self.assertEqual(high_items[-1]["title"], "Epsilon Risk")
        self.assertEqual(list(high_group.items), high_items)

        medium_group = artifact.get("med")
        self.assertIsInstance(medium_group, dict)
        self.assertEqual(medium_group["total_unique"], 2)
        medium_items = medium_group["items"]
        self.assertEqual(len(medium_items), 2)
        self.assertEqual(medium_items[0]["title"], "Medium Alpha")
        self.assertEqual(medium_items[0]["count"], 4)
        self.assertEqual(list(medium_group.items), medium_items)

        low_group = artifact.get("low")
        self.assertIsInstance(low_group, dict)
        self.assertEqual(low_group["total_unique"], 2)
        low_items = low_group["items"]
        self.assertEqual(len(low_items), 2)
        self.assertEqual(low_items[0]["title"], "Low Alpha")
        self.assertEqual(low_items[0]["count"], 3)
        self.assertEqual(list(low_group.items), low_items)

        self.assertIn("external_nexpose_vulnerabilities", self.project.data_artifacts)

        upload.delete()
        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self._assert_default_nexpose_artifacts(self.project.data_artifacts)
        self.assertEqual(self.project.data_responses, {"custom": "value"})

    def test_workbook_populates_old_domain_artifact(self):
        workbook_payload = {
            "ad": {
                "domains": [
                    {
                        "domain": "legacy.local",
                        "functionality_level": "Windows Server 2003",
                        "total_accounts": 200,
                        "enabled_accounts": 150,
                        "old_passwords": 30,
                        "inactive_accounts": 25,
                    },
                    {
                        "domain": "modern.local",
                        "functionality_level": "Windows Server 2019",
                        "total_accounts": 100,
                        "enabled_accounts": 95,
                        "old_passwords": 5,
                        "inactive_accounts": 4,
                    },
                    {
                        "domain": "ancient.local",
                        "functionality_level": "Windows 2000 Mixed",
                        "total_accounts": 80,
                        "enabled_accounts": 60,
                        "old_passwords": 18,
                        "inactive_accounts": 12,
                    },
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.save(update_fields=["workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        artifact = self.project.data_artifacts.get("ad_issues")
        self.assertIsInstance(artifact, dict)
        self.assertEqual(artifact.get("old_domains_string"), "'legacy.local' and 'ancient.local'")
        self.assertEqual(artifact.get("old_domains_count"), 2)
        self.assertEqual(
            artifact.get("domain_metrics"),
            [
                {
                    "domain_name": "legacy.local",
                    "disabled_count": 50,
                    "disabled_pct": 25.0,
                    "old_pass_pct": 20.0,
                    "ia_pct": 16.7,
                },
                {
                    "domain_name": "modern.local",
                    "disabled_count": 5,
                    "disabled_pct": 5.0,
                    "old_pass_pct": 5.3,
                    "ia_pct": 4.2,
                },
                {
                    "domain_name": "ancient.local",
                    "disabled_count": 20,
                    "disabled_pct": 25.0,
                    "old_pass_pct": 30.0,
                    "ia_pct": 20.0,
                },
            ],
        )

    def test_nexpose_artifacts_present_without_uploads(self):
        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self._assert_default_nexpose_artifacts(self.project.data_artifacts)

    def test_web_issue_sample_strings(self):
        csv_lines = [
            "Host,Risk,Issue,Impact",
            "portal.example.com,High,SQL Injection,This may lead to full database compromise.",
            "portal.example.com,Medium,Cross-Site Scripting,This can result in credential theft.",
            "portal.example.com,Medium,Cross-Site Scripting,This can result in credential theft.",
            "portal.example.com,Medium,Session Fixation,This can lead to account takeover.",
            "portal.example.com,Medium,Session Fixation,This can lead to account takeover.",
            "portal.example.com,Medium,Session Fixation,This can lead to account takeover.",
            "intranet.example.com,Medium,Authentication Bypass,This may expose sensitive data.",
            "intranet.example.com,Medium,Authentication Bypass,This may expose sensitive data.",
            "intranet.example.com,Low,Directory Listing,This may expose directory structure.",
            "intranet.example.com,Low,Directory Listing,This may expose directory structure.",
            "portal.example.com,Low,Missing X-Frame-Options header,This may allow clickjacking.",
            "portal.example.com,Low,Missing X-Frame-Options header,This may allow clickjacking.",
            "portal.example.com,Low,Missing X-Frame-Options header,This may allow clickjacking.",
            "extranet.example.com,Informational,Banner Disclosure,This can reveal version information.",
            "extranet.example.com,Informational,Banner Disclosure,This can reveal version information.",
        ]
        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=SimpleUploadedFile(
                "burp_csv.csv",
                "\n".join(csv_lines).encode("utf-8"),
                content_type="text/csv",
            ),
            requirement_label="burp_csv.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        web_artifact = self.project.data_artifacts.get("web_issues")
        self.assertIsInstance(web_artifact, dict)
        self.assertEqual(
            web_artifact["low_sample_string"],
            "'Missing X-Frame-Options header', 'Banner Disclosure' and 'Directory Listing'",
        )
        self.assertEqual(
            web_artifact["med_sample_string"],
            "'lead to account takeover.', 'expose sensitive data.' and 'result in credential theft.'",
        )
        self.assertIn("high", web_artifact)
        self.assertIn("med", web_artifact)
        self.assertIn("low", web_artifact)
        high_summary = web_artifact["high"]
        self.assertEqual(high_summary["total_unique"], 1)
        self.assertEqual(len(high_summary["items"]), 1)
        self.assertEqual(high_summary["items"][0]["issue"], "SQL Injection")
        self.assertEqual(high_summary["items"][0]["count"], 1)
        med_summary = web_artifact["med"]
        self.assertEqual(med_summary["total_unique"], 3)
        self.assertEqual(len(med_summary["items"]), 3)
        self.assertEqual(med_summary["items"][0]["issue"], "Session Fixation")
        self.assertEqual(med_summary["items"][0]["count"], 3)
        low_summary = web_artifact["low"]
        self.assertEqual(low_summary["total_unique"], 3)
        self.assertEqual(len(low_summary["items"]), 3)
        self.assertEqual(low_summary["items"][0]["issue"], "Missing X-Frame-Options header")
