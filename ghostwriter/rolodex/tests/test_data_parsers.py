"""Tests for project data file parsing helpers."""

# Standard Libraries
import csv
import io
from typing import Any, Dict, Iterable
from unittest import mock

# Django Imports
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.factories import GenerateMockProject, OpenAIConfigurationFactory
from ghostwriter.rolodex.data_parsers import (
    NEXPOSE_ARTIFACT_DEFINITIONS,
    normalize_nexpose_artifact_payload,
    normalize_nexpose_artifacts_map,
    load_general_cap_map,
    load_dns_soa_cap_map,
    load_password_cap_map,
    load_password_compliance_matrix,
    build_workbook_password_response,
    parse_dns_report,
    DEFAULT_GENERAL_CAP_MAP,
)
from ghostwriter.rolodex.models import (
    DNSCapMapping,
    DNSSOACapMapping,
    DNSFindingMapping,
    DNSRecommendationMapping,
    GeneralCapMapping,
    PasswordCapMapping,
    ProjectDataFile,
    VulnerabilityMatrixEntry,
    WebIssueMatrixEntry,
)
from ghostwriter.reporting.models import PasswordComplianceMapping


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

    def test_nexpose_xml_upload_populates_findings(self):
        xml_payload = """<?xml version='1.0' encoding='UTF-8'?>
<NexposeReport version='1.0'>
  <scans>
    <scan>
      <id>scan-1</id>
      <name>Example</name>
      <startTime>2023-01-01T00:00:00Z</startTime>
      <endTime>2023-01-01T01:00:00Z</endTime>
      <status>complete</status>
    </scan>
  </scans>
  <nodes>
    <node>
      <address>192.0.2.10</address>
      <status>vulnerable</status>
      <names>
        <name>alpha.example.com</name>
        <name>beta</name>
      </names>
      <fingerprints>
        <os certainty='1.0' vendor='Microsoft' product='Windows 10'/>
      </fingerprints>
      <tests>
        <test id='vuln-host' status='vulnerable-version'>
          <evidence>Evidence for host</evidence>
        </test>
      </tests>
      <endpoints>
        <endpoint protocol='tcp' port='443' status='open'>
          <services>
            <service>
              <name>https</name>
              <tests>
                <test id='vuln-service' status='potential'>
                  <details>Context-dependent service evidence</details>
                </test>
              </tests>
            </service>
          </services>
        </endpoint>
      </endpoints>
      <software>
        <fingerprint vendor='ExampleCo' product='ExampleApp' version='1.2.3'/>
      </software>
    </node>
  </nodes>
  <vulnerabilityDefinitions>
    <vulnerability>
      <id>vuln-host</id>
      <title>Fancy — Vulnerability</title>
      <severity>7</severity>
      <description>Node description</description>
      <solution>Apply patches</solution>
      <references>
        <reference>
          <source>CVE</source>
          <value>CVE-2020-0001</value>
        </reference>
      </references>
    </vulnerability>
    <vulnerability>
      <id>vuln-service</id>
      <title>Service Vuln</title>
      <severity>5</severity>
      <description>Service description mentioning context-dependent risk.</description>
      <solution>Service fix</solution>
    </vulnerability>
  </vulnerabilityDefinitions>
</NexposeReport>
"""

        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=SimpleUploadedFile(
                "external_nexpose_xml.xml",
                xml_payload.encode("utf-8"),
                content_type="text/xml",
            ),
            requirement_label="external_nexpose_xml.xml",
            requirement_slug="required_external_nexpose_xml-xml",
            requirement_context="external nexpose_xml",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        artifact = self.project.data_artifacts.get("external_nexpose_findings")
        self.assertIsInstance(artifact, dict)
        findings = artifact.get("findings")
        software = artifact.get("software")
        self.assertIsInstance(findings, list)
        self.assertEqual(len(findings), 2)
        self.assertIsInstance(software, list)
        self.assertEqual(len(software), 1)

        host_finding = findings[0]
        self.assertEqual(host_finding["Asset IP Address"], "192.0.2.10")
        self.assertEqual(host_finding["Hostname(s)"], "alpha.example.com; beta")
        self.assertEqual(host_finding["Asset Operating System"], "Windows 10")
        self.assertEqual(host_finding["Vulnerability ID"], "vuln-host")
        self.assertEqual(host_finding["Vulnerability Title"], "Fancy Vulnerability")
        self.assertEqual(host_finding["Vulnerability Test Result Code"], "VE")
        self.assertEqual(host_finding["Vulnerability CVE IDs"], "CVE-2020-0001")
        self.assertEqual(host_finding["Details"], "Node description")

        service_finding = findings[1]
        self.assertEqual(service_finding["Service Port"], "443")
        self.assertEqual(service_finding["Protocol"], "TCP")
        self.assertEqual(service_finding["Vulnerability Test Result Code"], "VP")
        self.assertEqual(
            service_finding["Details"],
            "Service description mentioning context-dependent risk.",
        )

        software_entry = software[0]
        self.assertEqual(
            software_entry["System"], "192.0.2.10 (alpha.example.com; beta)"
        )
        self.assertEqual(software_entry["Software"], "ExampleApp")
        self.assertEqual(software_entry["Version"], "1.2.3")

    def test_vulnerability_matrix_enriches_artifacts(self):
        VulnerabilityMatrixEntry.objects.create(
            vulnerability="Zeta Exposure",
            action_required="Apply patches",
            remediation_impact="Moderate downtime",
            vulnerability_threat="Remote compromise",
            category="TLS",
        )
        rows = [
            {
                "Vulnerability Title": "Zeta Exposure",
                "Impact": "Existing impact",
                "Vulnerability Severity Level": "High",
            }
        ]
        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=self._build_csv_file("external_nexpose_csv.csv", rows),
            requirement_label="external_nexpose_csv.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        artifact = self.project.data_artifacts.get("external_nexpose_vulnerabilities")
        high_items = artifact["high"]["items"]
        self.assertTrue(high_items)
        self.assertEqual(high_items[0]["action_required"], "Apply patches")
        self.assertEqual(high_items[0]["remediation_impact"], "Moderate downtime")
        self.assertEqual(high_items[0]["vulnerability_threat"], "Remote compromise")
        self.assertEqual(high_items[0]["category"], "TLS")

    def test_firewall_csv_adds_vulnerability_summary(self):
        self.project.workbook_data = {
            "firewall": {"firewall_periodic_reviews": "No"},
        }
        self.project.data_responses = {}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        headers = [
            "Risk",
            "Issue",
            "Devices",
            "Solution",
            "Impact",
            "Details",
            "Reference",
            "Accepted",
            "Type",
            "Score",
        ]

        rows = [
            {
                "Risk": "High",
                "Issue": "Open management interface",
                "Devices": "FW-EDGE",
                "Solution": "Restrict access",
                "Impact": "Allows remote compromise. Additional details beyond the first sentence.",
                "Details": "Management interface exposed",
                "Reference": "http://example.com/high-1",
                "Accepted": "No",
                "Type": "Configuration",
                "Score": "8.0",
            },
            {
                "Risk": "High",
                "Issue": "Open management interface",
                "Devices": "FW-EDGE",
                "Solution": "Restrict access",
                "Impact": "Allows remote compromise.",
                "Details": "Duplicate finding",
                "Reference": "http://example.com/high-2",
                "Accepted": "No",
                "Type": "Configuration",
                "Score": "8.0",
            },
            {
                "Risk": "High",
                "Issue": "Legacy cipher suites enabled",
                "Devices": "FW-DMZ",
                "Solution": "Disable legacy ciphers",
                "Impact": "Enables downgrade attacks! Attackers may intercept data.",
                "Details": "TLS settings allow weak ciphers",
                "Reference": "http://example.com/high-3",
                "Accepted": "No",
                "Type": "Configuration",
                "Score": "7.5",
            },
            {
                "Risk": "Medium",
                "Issue": "Unused objects",
                "Devices": "FW-CORE",
                "Solution": "Remove stale objects",
                "Impact": "Clutters policy reviews. Leads to oversight of risky rules.",
                "Details": "Objects no longer referenced",
                "Reference": "",
                "Accepted": "Yes",
                "Type": "Operations",
                "Score": "5.0",
            },
            {
                "Risk": "Medium",
                "Issue": "Audit logging disabled",
                "Devices": "FW-CORE",
                "Solution": "Enable logging",
                "Impact": "Obscures incident response",
                "Details": "Logging turned off",
                "Reference": "http://example.com/med-2",
                "Accepted": "No",
                "Type": "Operations",
                "Score": "4.5",
            },
            {
                "Risk": "Low",
                "Issue": "Banner not customized",
                "Devices": "FW-EDGE",
                "Solution": "Update login banner",
                "Impact": "Reveals platform details",
                "Details": "Default login banner present",
                "Reference": "",
                "Accepted": "No",
                "Type": "Operations",
                "Score": "2.0",
            },
        ]

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        content = buffer.getvalue().encode("utf-8")
        buffer.close()

        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=SimpleUploadedFile("firewall_csv.csv", content, content_type="text/csv"),
            requirement_label="firewall_csv.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        artifact = self.project.data_artifacts.get("firewall_findings")
        self.assertIsInstance(artifact, dict)
        self.assertNotIn("findings", artifact)
        self.assertIn("vulnerabilities", artifact)

        summaries = artifact["vulnerabilities"]
        self.assertEqual(summaries["high"]["total_unique"], 2)
        self.assertEqual(
            summaries["high"]["items"],
            [
                {
                    "issue": "Open management interface",
                    "impact": "Allows remote compromise.",
                    "count": 2,
                },
                {
                    "issue": "Legacy cipher suites enabled",
                    "impact": "Enables downgrade attacks!",
                    "count": 1,
                },
            ],
        )

        self.assertEqual(summaries["med"]["total_unique"], 2)
        self.assertEqual(
            summaries["med"]["items"],
            [
                {
                    "issue": "Audit logging disabled",
                    "impact": "Obscures incident response",
                    "count": 1,
                },
                {
                    "issue": "Unused objects",
                    "impact": "Clutters policy reviews.",
                    "count": 1,
                },
            ],
        )

        self.assertEqual(summaries["low"]["total_unique"], 1)
        self.assertEqual(
            summaries["low"]["items"],
            [
                {
                    "issue": "Banner not customized",
                    "impact": "Reveals platform details",
                    "count": 1,
                }
            ],
        )

        firewall_cap = self.project.cap.get("firewall")
        self.assertIsInstance(firewall_cap, dict)
        cap_entries = firewall_cap.get("firewall_cap_map")
        self.assertIsInstance(cap_entries, list)
        self.assertEqual(len(cap_entries), 6)
        first_entry = cap_entries[0]
        expected_recommendation, expected_score = DEFAULT_GENERAL_CAP_MAP[
            "Business justification for firewall rules"
        ]
        self.assertEqual(first_entry.get("issue"), "Open management interface")
        self.assertEqual(first_entry.get("finding_score"), 8.0)
        self.assertEqual(first_entry.get("recommendation"), expected_recommendation)
        self.assertEqual(first_entry.get("score"), expected_score)

        global_entries = firewall_cap.get("global")
        self.assertIsInstance(global_entries, dict)
        justification_entry = global_entries.get(
            "Business justification for firewall rules"
        )
        self.assertIsInstance(justification_entry, dict)
        self.assertEqual(
            justification_entry.get("recommendation"), expected_recommendation
        )
        self.assertEqual(justification_entry.get("score"), expected_score)

    def test_firewall_global_entry_created_from_workbook_response(self):
        workbook_payload = {
            "firewall": {"firewall_periodic_reviews": "no"},
        }
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        cap_payload = self.project.cap or {}
        firewall_cap = cap_payload.get("firewall")
        self.assertIsInstance(firewall_cap, dict)
        global_entries = firewall_cap.get("global")
        self.assertIsInstance(global_entries, dict)
        justification_entry = global_entries.get(
            "Business justification for firewall rules"
        )
        self.assertIsInstance(justification_entry, dict)
        expected_recommendation, expected_score = DEFAULT_GENERAL_CAP_MAP[
            "Business justification for firewall rules"
        ]
        self.assertEqual(
            justification_entry.get("recommendation"), expected_recommendation
        )
        self.assertEqual(justification_entry.get("score"), expected_score)

        responses = self.project.data_responses.get("firewall")
        self.assertIsInstance(responses, dict)
        self.assertEqual(responses.get("firewall_periodic_reviews"), "no")

    def test_firewall_global_entry_skipped_when_reviews_performed(self):
        workbook_payload = {
            "firewall": {"firewall_periodic_reviews": "Yes"},
        }
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        cap_payload = self.project.cap or {}
        self.assertNotIn("firewall", cap_payload)
        responses = self.project.data_responses.get("firewall")
        self.assertIsInstance(responses, dict)
        self.assertEqual(responses.get("firewall_periodic_reviews"), "Yes")

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
                "ai_response": "Simulated response",
            }
        }

        normalized = normalize_nexpose_artifacts_map(payload)
        self.assertIsInstance(normalized["web_issues"], dict)
        self.assertEqual(normalized["web_issues"]["low_sample_string"], "'SQL'")
        self.assertEqual(normalized["web_issues"]["med_sample_string"], "")
        self.assertEqual(normalized["web_issues"].get("ai_response"), "Simulated response")
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
        self.assertIsNone(normalized_legacy["web_issues"].get("ai_response"))

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
                        "old_passwords": 40,
                        "inactive_accounts": 35,
                        "domain_admins": 12,
                        "ent_admins": 6,
                        "exp_passwords": 22,
                        "passwords_never_exp": 14,
                        "generic_accounts": 9,
                        "generic_logins": 4,
                    },
                    {
                        "domain": "modern.local",
                        "functionality_level": "Windows Server 2019",
                        "total_accounts": 100,
                        "enabled_accounts": 95,
                        "old_passwords": 5,
                        "inactive_accounts": 4,
                        "domain_admins": 4,
                        "ent_admins": 1,
                        "exp_passwords": 8,
                        "passwords_never_exp": 6,
                        "generic_accounts": 2,
                        "generic_logins": 1,
                    },
                    {
                        "domain": "ancient.local",
                        "functionality_level": "Windows 2000 Mixed",
                        "total_accounts": 80,
                        "enabled_accounts": 60,
                        "old_passwords": 18,
                        "inactive_accounts": 12,
                        "domain_admins": 7,
                        "ent_admins": 3,
                        "exp_passwords": 11,
                        "passwords_never_exp": 9,
                        "generic_accounts": 5,
                        "generic_logins": 2,
                    },
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.save(update_fields=["workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        artifact = self.project.data_artifacts.get("ad_issues")
        self.assertIsNone(artifact)

        ad_responses = self.project.data_responses.get("ad")
        self.assertIsInstance(ad_responses, dict)
        self.assertEqual(ad_responses.get("old_domains_string"), "'legacy.local' and 'ancient.local'")
        self.assertEqual(ad_responses.get("old_domains_str"), "'legacy.local'/'ancient.local'")
        self.assertEqual(ad_responses.get("old_domains_count"), 2)
        self.assertEqual(ad_responses.get("risk_contrib"), [])
        self.assertEqual(
            ad_responses.get("domain_metrics"),
            [
                {
                    "domain_name": "legacy.local",
                    "disabled_count": 50,
                    "disabled_pct": 25.0,
                    "old_pass_pct": 26.7,
                    "ia_pct": 23.3,
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
        self.assertEqual(ad_responses.get("disabled_account_string"), "50, 5 and 20")
        self.assertEqual(ad_responses.get("disabled_account_pct_string"), "25%, 5% and 25%")
        self.assertEqual(ad_responses.get("old_password_string"), "40, 5 and 18")
        self.assertEqual(ad_responses.get("old_password_pct_string"), "26.7%, 5.3% and 30%")
        self.assertEqual(ad_responses.get("inactive_accounts_string"), "35, 4 and 12")
        self.assertEqual(ad_responses.get("inactive_accounts_pct_string"), "23.3%, 4.2% and 20%")
        self.assertEqual(ad_responses.get("domain_admins_string"), "12, 4 and 7")
        self.assertEqual(ad_responses.get("ent_admins_string"), "6, 1 and 3")
        self.assertEqual(ad_responses.get("exp_passwords_string"), "22, 8 and 11")
        self.assertEqual(ad_responses.get("never_expire_string"), "14, 6 and 9")
        self.assertEqual(ad_responses.get("generic_accounts_string"), "9, 2 and 5")
        self.assertEqual(ad_responses.get("generic_logins_string"), "4, 1 and 2")

    def test_workbook_old_domain_count_defaults_to_zero(self):
        workbook_payload = {
            "ad": {
                "domains": [
                    {
                        "domain": "modern.local",
                        "functionality_level": "Windows Server 2016",
                        "total_accounts": 100,
                        "enabled_accounts": 90,
                        "old_passwords": 10,
                        "inactive_accounts": 8,
                    }
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.save(update_fields=["workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        ad_responses = self.project.data_responses.get("ad")
        self.assertIsInstance(ad_responses, dict)
        self.assertNotIn("old_domains_string", ad_responses)
        self.assertIsNone(ad_responses.get("old_domains_str"))
        self.assertEqual(ad_responses.get("old_domains_count"), 0)
        self.assertEqual(ad_responses.get("risk_contrib"), [])

    def test_rebuild_populates_ad_risk_contrib_for_medium_risk(self):
        workbook_payload = {
            "external_internal_grades": {
                "internal": {"iam": {"risk": "Medium"}},
            },
            "ad": {
                "domains": [
                    {
                        "domain": "legacy.local",
                        "functionality_level": "Windows Server 2016",
                        "total_accounts": 120,
                        "enabled_accounts": 90,
                        "old_passwords": 12,
                        "inactive_accounts": 8,
                    }
                ]
            },
        }

        ad_entries = [
            {
                "domain": "legacy.local",
                "domain_admins": "medium",
                "enterprise_admins": "low",
                "expired_passwords": "high",
                "passwords_never_expire": "medium",
                "inactive_accounts": "medium",
                "generic_accounts": "high",
                "generic_logins": "medium",
                "old_passwords": "low",
                "disabled_accounts": "medium",
            }
        ]

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {"ad": {"entries": ad_entries}}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        ad_responses = self.project.data_responses.get("ad")
        self.assertEqual(
            ad_responses.get("risk_contrib"),
            [
                "the number of Domain Admin accounts",
                "the number of accounts with expired passwords",
                "the number of accounts set with passwords that never expire",
                "the number of potentially inactive accounts",
                "the number of potentially generic accounts",
                "the number of generic accounts logged into systems",
                "the number of disabled accounts",
            ],
        )

    def test_rebuild_populates_ad_risk_contrib_for_high_risk(self):
        workbook_payload = {
            "external_internal_grades": {
                "internal": {"iam": {"risk": "High"}},
            },
            "ad": {
                "domains": [
                    {
                        "domain": "corp.example.com",
                        "functionality_level": "Windows Server 2019",
                        "total_accounts": 80,
                        "enabled_accounts": 70,
                        "old_passwords": 5,
                        "inactive_accounts": 6,
                    }
                ]
            },
        }

        ad_entries = [
            {
                "domain": "corp.example.com",
                "domain_admins": "high",
                "enterprise_admins": "medium",
                "expired_passwords": "high",
                "passwords_never_expire": "medium",
                "inactive_accounts": "medium",
                "generic_accounts": "high",
                "generic_logins": "medium",
                "old_passwords": "high",
                "disabled_accounts": "medium",
            }
        ]

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {"ad": {"entries": ad_entries}}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        ad_responses = self.project.data_responses.get("ad")
        self.assertEqual(
            ad_responses.get("risk_contrib"),
            [
                "the number of Domain Admin accounts",
                "the number of accounts with expired passwords",
                "the number of potentially generic accounts",
                "the number of accounts with 'old' passwords",
            ],
        )

    def test_rebuild_populates_password_strings(self):
        workbook_payload = {
            "ad": {
                "domains": [
                    {"domain": "corp.example.com"},
                    {"domain": "legacy.local"},
                ]
            },
            "password": {
                "policies": [
                    {
                        "domain_name": "corp.example.com",
                        "passwords_cracked": 10,
                        "enabled_accounts": 100,
                        "admin_cracked": {"count": 1, "confirm": "yes"},
                        "lanman_stored": "yes",
                        "history": 5,
                        "max_age": 90,
                        "min_age": 0,
                        "min_length": 7,
                        "lockout_threshold": 8,
                        "lockout_duration": 15,
                        "lockout_reset": 20,
                        "complexity_enabled": "yes",
                        "fgpp": [
                            {
                                "fgpp_name": "Tier0Admins",
                                "history": 24,
                                "max_age": 0,
                                "min_age": 1,
                                "min_length": 14,
                                "lockout_threshold": 3,
                                "lockout_duration": 30,
                                "lockout_reset": 30,
                                "complexity_enabled": "no",
                            },
                            {
                                "fgpp_name": "ServiceAccounts",
                                "history": 5,
                                "max_age": 365,
                                "min_age": 0,
                                "min_length": 6,
                                "lockout_threshold": 8,
                                "lockout_duration": 10,
                                "lockout_reset": 10,
                                "complexity_enabled": "yes",
                            },
                        ],
                    },
                    {
                        "domain_name": "legacy.local",
                        "passwords_cracked": 5,
                        "enabled_accounts": 40,
                        "admin_cracked": {"count": 0, "confirm": "no"},
                        "lanman_stored": "no",
                        "history": 15,
                        "max_age": 0,
                        "min_age": 2,
                        "min_length": 12,
                        "lockout_threshold": 4,
                        "lockout_duration": 0,
                        "lockout_reset": 45,
                        "complexity_enabled": "no",
                        "fgpp": {"count": 0},
                    },
                    {
                        "domain_name": "lab.example.com",
                        "passwords_cracked": 8,
                        "enabled_accounts": 60,
                        "admin_cracked": {"count": 3, "confirm": "yes"},
                        "lanman_stored": "yes",
                        "history": 8,
                        "max_age": 0,
                        "min_age": 1,
                        "min_length": 12,
                        "lockout_threshold": 5,
                        "lockout_duration": 0,
                        "lockout_reset": 60,
                        "complexity_enabled": "no",
                        "fgpp": {"count": 3},
                    },
                ]
            },
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {
            "password": {
                "password_additional_controls": "no",
                "password_enforce_mfa_all_accounts": "no",
            }
        }
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        password_responses = self.project.data_responses.get("password")
        self.assertIsInstance(password_responses, dict)
        self.assertEqual(password_responses.get("cracked_count_str"), "10/5/8")
        self.assertEqual(password_responses.get("cracked_finding_string"), "10, 5 and 8")
        self.assertEqual(password_responses.get("enabled_count_string"), "100, 40 and 60")
        self.assertEqual(password_responses.get("admin_cracked_string"), "1, 0 and 3")
        self.assertEqual(
            password_responses.get("admin_cracked_doms"),
            "'corp.example.com', 'legacy.local' and 'lab.example.com'",
        )
        self.assertEqual(
            password_responses.get("lanman_list_string"),
            "'corp.example.com' and 'lab.example.com'",
        )
        self.assertEqual(
            password_responses.get("no_fgpp_string"),
            "'legacy.local'",
        )
        self.assertEqual(password_responses.get("bad_pass_count"), 3)
        self.assertEqual(
            password_responses.get("policy_cap_fields"),
            [
                "max_age",
                "min_age",
                "min_length",
                "history",
                "lockout_threshold",
                "lockout_duration",
                "lockout_reset",
                "complexity_enabled",
            ],
        )
        expected_cap_map = {
            "corp.example.com": {
                "policy": {
                    "score": 4,
                    "max_age": (
                        "Change 'Maximum Age' from 90 to == 0 to align with NIST recommendations "
                        "to not force users to arbitrarily change passwords based solely on age"
                    ),
                    "min_age": "Change 'Minimum Age' from 0 to >= 1 and < 7",
                    "min_length": "Change 'Minimum Length' from 7 to >= 8",
                    "history": "Change 'History' from 5 to >= 10",
                    "lockout_threshold": "Change 'Lockout Threshold' from 8 to > 0 and <= 6",
                    "lockout_duration": "Change 'Lockout Duration' from 15 to >= 30 or admin unlock",
                    "lockout_reset": "Change 'Lockout Reset' from 20 to >= 30",
                    "complexity_enabled": (
                        "Change 'Complexity Required' from TRUE to FALSE and implement additional password selection "
                        "controls such as blacklists"
                    ),
                },
                "fgpp": {
                    "ServiceAccounts": {
                        "score": 4,
                        "max_age": (
                            "Change 'Maximum Age' from 365 to == 0 to align with NIST recommendations "
                            "to not force users to arbitrarily change passwords based solely on age"
                        ),
                        "min_age": "Change 'Minimum Age' from 0 to >= 1 and < 7",
                        "min_length": "Change 'Minimum Length' from 6 to >= 8",
                        "history": "Change 'History' from 5 to >= 10",
                        "lockout_threshold": "Change 'Lockout Threshold' from 8 to > 0 and <= 6",
                        "lockout_duration": "Change 'Lockout Duration' from 10 to >= 30 or admin unlock",
                        "lockout_reset": "Change 'Lockout Reset' from 10 to >= 30",
                        "complexity_enabled": (
                            "Change 'Complexity Required' from TRUE to FALSE and implement additional password selection "
                            "controls such as blacklists"
                        ),
                    },
                    "Tier0Admins": {
                        "score": 4,
                        "max_age": (
                            "Change 'Maximum Age' from 45 to == 0 to align with NIST recommendations "
                            "to not force users to arbitrarily change passwords based solely on age"
                        ),
                        "lockout_reset": "Change 'Lockout Reset' from 15 to >= 30",
                        "lockout_duration": "Change 'Lockout Duration' from 15 to >= 30 or admin unlock",
                        "complexity_enabled": (
                            "Change 'Complexity Required' from TRUE to FALSE and implement additional password selection "
                            "controls such as blacklists"
                        ),
                    },
                },
            },
            "lab.example.com": {
                "policy": {
                    "score": 4,
                    "history": "Change 'History' from 8 to >= 10",
                },
            },
        }
        self.assertEqual(password_responses.get("policy_cap_map"), expected_cap_map)
        self.assertEqual(
            password_responses.get("policy_cap_context"),
            {
                "corp.example.com": {
                    "policy": {
                        "max_age": 90,
                        "min_age": 0,
                        "min_length": 7,
                        "history": 5,
                        "lockout_threshold": 8,
                        "lockout_duration": 15,
                        "lockout_reset": 20,
                        "complexity_enabled": "TRUE",
                    },
                    "fgpp": {
                        "ServiceAccounts": {
                            "max_age": 365,
                            "min_age": 0,
                            "min_length": 6,
                            "history": 5,
                            "lockout_threshold": 8,
                            "lockout_duration": 10,
                            "lockout_reset": 10,
                            "complexity_enabled": "TRUE",
                        }
                    },
                },
                "lab.example.com": {
                    "policy": {
                        "history": 8,
                    }
                },
            },
        )

        password_entries = password_responses.get("entries")
        self.assertIsInstance(password_entries, list)
        corp_entry = next(
            (entry for entry in password_entries if entry.get("domain") == "corp.example.com"),
            {},
        )
        self.assertEqual(
            corp_entry.get("bad_policy_fields"),
            [
                "max_age",
                "min_age",
                "min_length",
                "history",
                "lockout_threshold",
                "lockout_duration",
                "lockout_reset",
                "complexity_enabled",
            ],
        )
        self.assertIn("policy_cap_values", corp_entry)
        self.assertIn("fgpp_bad_fields", corp_entry)
        self.assertIn("fgpp_cap_values", corp_entry)

        lab_entry = next(
            (entry for entry in password_entries if entry.get("domain") == "lab.example.com"),
            {},
        )
        self.assertEqual(lab_entry.get("bad_policy_fields"), ["history"])

        password_cap = self.project.cap.get("password")
        self.assertIsInstance(password_cap, dict)
        self.assertEqual(
            password_cap.get("policy_cap_fields"),
            password_responses.get("policy_cap_fields"),
        )
        self.assertEqual(
            password_cap.get("policy_cap_map"),
            password_responses.get("policy_cap_map"),
        )
        self.assertEqual(
            password_cap.get("policy_cap_context"),
            password_responses.get("policy_cap_context"),
        )
        expected_badpass_cap_map = {
            "corp.example.com": {
                "Weak passwords in use": {
                    "recommendation": (
                        "Force all accounts whose password was cracked to change their password. "
                        "Provide training on secure password creation"
                    ),
                    "score": 7,
                },
                "LANMAN password hashing enabled": {
                    "recommendation": (
                        "Configure the domain to disable LANMAN password hashing. "
                        "Force accounts with stored LANMAN password hashes to change their password"
                    ),
                    "score": 5,
                },
            },
            "legacy.local": {
                "Weak passwords in use": {
                    "recommendation": (
                        "Force all accounts whose password was cracked to change their password. "
                        "Provide training on secure password creation"
                    ),
                    "score": 7,
                },
                "Fine-grained Password Policies not defined": {
                    "recommendation": (
                        "Define and assign Fine-grained Password Policies for security groups based on the risk "
                        "associated with an account compromise.\n(Secure Password policy & procedures)"
                    ),
                    "score": 4,
                },
            },
            "lab.example.com": {
                "Weak passwords in use": {
                    "recommendation": (
                        "Force all accounts whose password was cracked to change their password. "
                        "Provide training on secure password creation"
                    ),
                    "score": 7,
                },
                "LANMAN password hashing enabled": {
                    "recommendation": (
                        "Configure the domain to disable LANMAN password hashing. "
                        "Force accounts with stored LANMAN password hashes to change their password"
                    ),
                    "score": 5,
                },
            },
            "global": {
                "Additional password controls not implemented": {
                    "recommendation": (
                        "Implement additional password controls as recommended by NIST for blacklisting and/or "
                        "repetitive/sequential characters, which are not available natively in Active Directory\n"
                        "(Secure Password policy & procedures)"
                    ),
                    "score": 4,
                },
                "MFA not enforced for all accounts": {
                    "recommendation": "Enforce MFA for all accounts as recommended by NIST",
                    "score": 4,
                },
            },
        }
        self.assertEqual(password_cap.get("badpass_cap_map"), expected_badpass_cap_map)
        cap_entries = password_cap.get("entries")
        self.assertIsInstance(cap_entries, list)
        corp_cap_entry = next(
            (entry for entry in cap_entries if entry.get("domain") == "corp.example.com"),
            {},
        )
        self.assertEqual(
            corp_cap_entry.get("policy_cap_values"),
            corp_entry.get("policy_cap_values"),
        )
        lab_cap_entry = next(
            (entry for entry in cap_entries if entry.get("domain") == "lab.example.com"),
            {},
        )
        self.assertEqual(
            lab_cap_entry.get("policy_cap_values"),
            lab_entry.get("policy_cap_values"),
        )

    def test_badpass_cap_prefers_existing_response_flags(self):
        general_cap_map = {
            issue: {"recommendation": recommendation, "score": score}
            for issue, (recommendation, score) in DEFAULT_GENERAL_CAP_MAP.items()
        }

        existing_password_responses = {
            "password_additional_controls": "no",
            "password_enforce_mfa_all_accounts": "no",
        }

        workbook_password_response = {
            "password_additional_controls": "yes",
            "password_enforce_mfa_all_accounts": "yes",
        }
        workbook_domain_values = {
            "corp.example.com": {
                "passwords_cracked": 3,
                "lanman": False,
                "no_fgpp": False,
            }
        }

        self.project.data_responses = {"password": existing_password_responses}
        self.project.workbook_data = {}
        self.project.cap = {}
        self.project.save(update_fields=["data_responses", "workbook_data", "cap"])

        with mock.patch("ghostwriter.rolodex.models.build_project_artifacts", return_value={}):
            with mock.patch("ghostwriter.rolodex.models.build_workbook_ad_response", return_value={}):
                with mock.patch(
                    "ghostwriter.rolodex.models.build_workbook_dns_response",
                    return_value={},
                ):
                    with mock.patch(
                        "ghostwriter.rolodex.models.build_workbook_firewall_response",
                        return_value={},
                    ):
                        with mock.patch(
                            "ghostwriter.rolodex.models.build_workbook_password_response",
                            return_value=(
                                workbook_password_response,
                                workbook_domain_values,
                                [],
                            ),
                        ):
                            with mock.patch(
                                "ghostwriter.rolodex.models.load_general_cap_map",
                                return_value=general_cap_map,
                            ):
                                self.project.rebuild_data_artifacts()

        self.project.refresh_from_db()

        password_cap = self.project.cap.get("password")
        self.assertIsInstance(password_cap, dict)
        badpass_cap_map = password_cap.get("badpass_cap_map")
        self.assertIsInstance(badpass_cap_map, dict)
        corp_entries = badpass_cap_map.get("corp.example.com")
        self.assertIsInstance(corp_entries, dict)
        self.assertIn("Weak passwords in use", corp_entries)
        self.assertNotIn("Additional password controls not implemented", corp_entries)
        self.assertNotIn("MFA not enforced for all accounts", corp_entries)
        global_entries = badpass_cap_map.get("global")
        self.assertIsInstance(global_entries, dict)
        self.assertIn("Additional password controls not implemented", global_entries)
        self.assertIn("MFA not enforced for all accounts", global_entries)

    def test_rebuild_populates_ad_cap_map(self):
        workbook_payload = {
            "ad": {
                "domains": [
                    {
                        "domain": "legacy.local",
                        "functionality_level": "Windows Server 2003",
                        "total_accounts": 200,
                        "enabled_accounts": 150,
                        "generic_accounts": 20,
                        "generic_logins": 10,
                        "inactive_accounts": 20,
                        "passwords_never_exp": 20,
                        "exp_passwords": 16,
                        "domain_admins": 10,
                        "ent_admins": 3,
                    },
                    {
                        "domain": "modern.local",
                        "functionality_level": "Windows Server 2019",
                        "total_accounts": 180,
                        "enabled_accounts": 175,
                        "generic_accounts": 4,
                        "generic_logins": 2,
                        "inactive_accounts": 3,
                        "passwords_never_exp": 2,
                        "exp_passwords": 1,
                        "domain_admins": 4,
                        "ent_admins": 1,
                    },
                    {
                        "domain": "ancient.local",
                        "functionality_level": "Windows 2000 Mixed",
                        "total_accounts": 80,
                        "enabled_accounts": 80,
                        "generic_accounts": 0,
                        "generic_logins": 0,
                        "inactive_accounts": 0,
                        "passwords_never_exp": 0,
                        "exp_passwords": 0,
                        "domain_admins": 2,
                        "ent_admins": 1,
                    },
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.cap = {}
        self.project.save(update_fields=["workbook_data", "data_responses", "cap"])

        with mock.patch("ghostwriter.rolodex.models.build_project_artifacts", return_value={}):
            with mock.patch(
                "ghostwriter.rolodex.models.build_workbook_password_response",
                return_value=({}, {}, []),
            ):
                with mock.patch(
                    "ghostwriter.rolodex.models.build_workbook_firewall_response",
                    return_value={},
                ):
                    with mock.patch(
                        "ghostwriter.rolodex.models.build_workbook_dns_response",
                        return_value={},
                    ):
                        self.project.rebuild_data_artifacts()

        self.project.refresh_from_db()

        ad_cap = self.project.cap.get("ad")
        self.assertIsInstance(ad_cap, dict)
        ad_cap_map = ad_cap.get("ad_cap_map")
        self.assertIsInstance(ad_cap_map, dict)

        def _expected(issue: str) -> Dict[str, Any]:
            recommendation, score = DEFAULT_GENERAL_CAP_MAP[issue]
            return {"recommendation": recommendation, "score": score}

        expected_legacy = {
            "Domain Functionality Level less than 2008": _expected(
                "Domain Functionality Level less than 2008"
            ),
            "Number of Disabled Accounts": _expected("Number of Disabled Accounts"),
            "Number of Systems with Logged in Generic Accounts": _expected(
                "Number of Systems with Logged in Generic Accounts"
            ),
            "Number of 'Generic Accounts'": _expected("Number of 'Generic Accounts'"),
            "Potentially Inactive Accounts": _expected(
                "Potentially Inactive Accounts"
            ),
            "Accounts with Passwords that Never Expire": _expected(
                "Accounts with Passwords that Never Expire"
            ),
            "Accounts with Expired Passwords": _expected(
                "Accounts with Expired Passwords"
            ),
            "Number of Domain Admins": _expected("Number of Domain Admins"),
            "Number of Enterprise Admins": _expected("Number of Enterprise Admins"),
        }
        self.assertEqual(ad_cap_map.get("legacy.local"), expected_legacy)

        expected_ancient = {
            "Domain Functionality Level less than 2008": _expected(
                "Domain Functionality Level less than 2008"
            ),
            "Number of Domain Admins": _expected("Number of Domain Admins"),
        }
        self.assertEqual(ad_cap_map.get("ancient.local"), expected_ancient)
        self.assertNotIn("modern.local", ad_cap_map)

    def test_firewall_ood_names_populated_from_workbook(self):
        workbook_payload = {
            "firewall": {
                "devices": [
                    {"name": "Firewall 1", "ood": "yes"},
                    {"name": "Firewall 2", "ood": "YES"},
                    {"name": "Firewall 3", "ood": True},
                    {"name": "Firewall 4", "ood": "no"},
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        firewall_responses = self.project.data_responses.get("firewall")
        self.assertIsInstance(firewall_responses, dict)
        self.assertEqual(
            firewall_responses.get("ood_name_list"),
            "'Firewall 1', 'Firewall 2', and 'Firewall 3'",
        )
        self.assertEqual(firewall_responses.get("ood_count"), 3)

    def test_dns_zone_transfer_count_populated_from_workbook(self):
        workbook_payload = {
            "dns": {
                "records": [
                    {"zone_transfer": "yes"},
                    {"zone_transfer": "Yes"},
                    {"zone_transfer": "no"},
                    {"zone_transfer": None},
                    "invalid",
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {"dns": {"existing": "value"}}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        dns_responses = self.project.data_responses.get("dns")
        self.assertIsInstance(dns_responses, dict)
        self.assertEqual(dns_responses.get("zone_trans"), 2)
        self.assertEqual(dns_responses.get("existing"), "value")

    def test_dns_soa_cap_map_populated(self):
        stored_responses = {
            "dns": {
                "entries": [
                    {"domain": "one.example", "soa_fields": ["serial", "refresh"]},
                    {"domain": "two.example", "soa_fields": ["retry"]},
                ]
            }
        }

        self.project.data_responses = stored_responses
        self.project.workbook_data = {}
        self.project.save(update_fields=["data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        dns_responses = self.project.data_responses.get("dns")
        self.assertIsInstance(dns_responses, dict)
        expected_soa_cap = {
            "one.example": {
                "serial": "Update to match the 'YYYYMMDDnn' scheme",
                "refresh": "Update to a value between 1200 and 43200 seconds",
            },
            "two.example": {
                "retry": "Update to a value less than or equal to half the REFRESH",
            },
        }
        self.assertEqual(dns_responses.get("soa_field_cap_map"), expected_soa_cap)

        dns_cap = self.project.cap.get("dns")
        self.assertIsInstance(dns_cap, dict)
        self.assertEqual(dns_cap.get("soa_field_cap_map"), expected_soa_cap)

    def test_dns_soa_cap_map_uses_database(self):
        DNSSOACapMapping.objects.update_or_create(
            soa_field="serial",
            defaults={"cap_text": "custom serial guidance"},
        )

        stored_responses = {
            "dns": {
                "entries": [
                    {"domain": "one.example", "soa_fields": ["serial"]},
                ]
            }
        }

        self.project.data_responses = stored_responses
        self.project.workbook_data = {}
        self.project.save(update_fields=["data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        dns_responses = self.project.data_responses.get("dns")
        self.assertIsInstance(dns_responses, dict)
        expected_override = {"one.example": {"serial": "custom serial guidance"}}
        self.assertEqual(dns_responses.get("soa_field_cap_map"), expected_override)

        dns_cap = self.project.cap.get("dns")
        self.assertIsInstance(dns_cap, dict)
        self.assertEqual(dns_cap.get("soa_field_cap_map"), expected_override)

    def test_dns_cap_map_populated_from_artifacts(self):
        csv_lines = [
            "Status,Info",
            "FAIL,One or more SOA fields are outside recommended ranges",
            "FAIL,Less than 2 nameservers exist",
            "FAIL,Some nameservers have duplicate addresses",
        ]
        upload = SimpleUploadedFile(
            "dns_report.csv",
            "\n".join(csv_lines).encode("utf-8"),
            content_type="text/csv",
        )
        data_file = ProjectDataFile.objects.create(
            project=self.project,
            file=upload,
            requirement_label="dns_report.csv",
            requirement_context="one.example",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=data_file.pk).delete())

        self.project.data_responses = {
            "dns": {
                "entries": [
                    {
                        "domain": "one.example",
                        "soa_fields": ["serial", "refresh"],
                    }
                ]
            }
        }
        self.project.workbook_data = {}
        self.project.save(update_fields=["data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        dns_responses = self.project.data_responses.get("dns")
        self.assertIsInstance(dns_responses, dict)
        expected_dns_cap = {
            "one.example": {
                "One or more SOA fields are outside recommended ranges": {
                    "score": 2,
                    "recommendation": (
                        "serial - Update to match the 'YYYYMMDDnn' scheme\n"
                        "refresh - Update to a value between 1200 and 43200 seconds"
                    ),
                },
                "Less than 2 nameservers exist": {
                    "score": 2,
                    "recommendation": "Assign a minimum of 2 nameservers for the domain",
                },
                "Some nameservers have duplicate addresses": {
                    "score": 2,
                    "recommendation": "Ensure all nameserver addresses are unique",
                },
            }
        }
        self.assertEqual(dns_responses.get("dns_cap_map"), expected_dns_cap)

        dns_cap = self.project.cap.get("dns")
        self.assertIsInstance(dns_cap, dict)
        self.assertEqual(dns_cap.get("dns_cap_map"), expected_dns_cap)
        self.assertEqual(
            dns_cap.get("soa_field_cap_map"),
            dns_responses.get("soa_field_cap_map"),
        )

    def test_dns_cap_map_added_when_dns_section_missing(self):
        csv_lines = [
            "Status,Info",
            "FAIL,Less than 2 nameservers exist",
        ]
        upload = SimpleUploadedFile(
            "dns_missing_section.csv",
            "\n".join(csv_lines).encode("utf-8"),
            content_type="text/csv",
        )
        data_file = ProjectDataFile.objects.create(
            project=self.project,
            file=upload,
            requirement_label="dns_missing_section.csv",
            requirement_context="missing.example",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=data_file.pk).delete())

        self.project.data_responses = {}
        self.project.workbook_data = {}
        self.project.save(update_fields=["data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        dns_responses = self.project.data_responses.get("dns")
        self.assertIsInstance(dns_responses, dict)
        expected_missing = {
            "dns_cap_map": {
                "missing.example": {
                    "Less than 2 nameservers exist": {
                        "score": 2,
                        "recommendation": "Assign a minimum of 2 nameservers for the domain",
                    },
                }
            }
        }
        self.assertEqual(dns_responses, expected_missing)

        dns_cap = self.project.cap.get("dns")
        self.assertIsInstance(dns_cap, dict)
        self.assertEqual(dns_cap.get("dns_cap_map"), expected_missing["dns_cap_map"])

    def test_osint_cap_map_populated_from_workbook(self):
        workbook_payload = {
            "osint": {
                "total_ips": 1,
                "total_domains": 1,
                "total_hostnames": 0,
                "total_buckets": 2,
                "total_leaks": 3,
                "total_squat": 4,
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.cap = {}
        self.project.save(update_fields=["workbook_data", "data_responses", "cap"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_osint_map = {
            "OSINT identified assets": general_map.get("OSINT identified assets"),
            "Exposed buckets identified": general_map.get("Exposed buckets identified"),
            "Exposed Credentials identified": general_map.get("Exposed Credentials identified"),
            "Potential domain squatters identified": general_map.get("Potential domain squatters identified"),
        }

        osint_cap = self.project.cap.get("osint")
        self.assertIsInstance(osint_cap, dict)
        self.assertEqual(osint_cap.get("osint_cap_map"), expected_osint_map)

    def test_osint_cap_map_removed_when_conditions_not_met(self):
        general_map = load_general_cap_map()
        existing_cap = {
            "osint": {
                "osint_cap_map": {
                    "OSINT identified assets": general_map.get("OSINT identified assets"),
                }
            }
        }

        workbook_payload = {
            "osint": {
                "total_ips": 0,
                "total_domains": 0,
                "total_hostnames": 0,
                "total_buckets": 0,
                "total_leaks": 0,
                "total_squat": 0,
            }
        }

        self.project.cap = existing_cap
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["cap", "workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertNotIn("osint", self.project.cap)

    def test_endpoint_cap_map_populated_from_workbook(self):
        workbook_payload = {
            "endpoint": {
                "domains": [
                    {"domain": "corp.example.com", "systems_ood": 3, "open_wifi": 0},
                    {"domain": "lab.example.com", "systems_ood": 0, "open_wifi": 4},
                    {"domain": "legacy.local", "systems_ood": 0, "open_wifi": 0},
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.cap = {}
        self.project.save(update_fields=["workbook_data", "data_responses", "cap"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_endpoint_map = {
            "corp.example.com": {
                "Systems without active up-to-date security software": general_map.get(
                    "Systems without active up-to-date security software"
                ),
            },
            "lab.example.com": {
                "Systems connecting to Open WiFi networks": general_map.get(
                    "Systems connecting to Open WiFi networks"
                ),
            },
        }

        endpoint_cap = self.project.cap.get("endpoint")
        self.assertIsInstance(endpoint_cap, dict)
        self.assertEqual(endpoint_cap.get("endpoint_cap_map"), expected_endpoint_map)

    def test_endpoint_cap_map_removed_when_conditions_not_met(self):
        general_map = load_general_cap_map()
        existing_cap = {
            "endpoint": {
                "endpoint_cap_map": {
                    "corp.example.com": {
                        "Systems without active up-to-date security software": general_map.get(
                            "Systems without active up-to-date security software"
                        )
                    }
                }
            }
        }

        workbook_payload = {
            "endpoint": {"domains": [{"domain": "corp.example.com", "systems_ood": 0, "open_wifi": 0}]}
        }

        self.project.cap = existing_cap
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["cap", "workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertNotIn("endpoint", self.project.cap)

    def test_wireless_cap_map_populated_from_workbook(self):
        workbook_payload = {
            "wireless": {
                "domains": [
                    {
                        "domain": "corp.example.com",
                        "psk_count": 4,
                        "rogue_count": 0,
                        "wep_inuse": {"confirm": "yes"},
                        "internal_access": "yes",
                        "802_1x_used": "no",
                        "weak_psks": "yes",
                    },
                    {
                        "domain": "lab.example.com",
                        "psk_count": 0,
                        "rogue_count": 2,
                        "wep_inuse": {"confirm": "no"},
                        "internal_access": "no",
                        "802_1x_used": "yes",
                        "weak_psks": "no",
                    },
                ]
            }
        }

        self.project.cap = {}
        self.project.data_responses = {}
        self.project.workbook_data = workbook_payload
        self.project.save(update_fields=["cap", "data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_wireless_map = {
            "corp.example.com": {
                "PSK’s in use on wireless networks": general_map.get(
                    "PSK’s in use on wireless networks"
                ),
                "WEP in use on wireless networks": general_map.get(
                    "WEP in use on wireless networks"
                ),
                "Open wireless network connected to the Internal network": general_map.get(
                    "Open wireless network connected to the Internal network"
                ),
                "802.1x authentication not implemented for wireless networks": general_map.get(
                    "802.1x authentication not implemented for wireless networks"
                ),
                "Weak PSK's in use": general_map.get("Weak PSK's in use"),
            },
            "lab.example.com": {
                "Potentially Rogue Access Points": general_map.get(
                    "Potentially Rogue Access Points"
                )
            },
        }

        wireless_cap = self.project.cap.get("wireless")
        self.assertIsInstance(wireless_cap, dict)
        self.assertEqual(wireless_cap.get("wireless_cap_map"), expected_wireless_map)

    def test_wireless_cap_map_without_domains(self):
        workbook_payload = {
            "wireless": {
                "psk_count": 2,
                "rogue_count": 0,
                "wep_inuse": {"confirm": "yes"},
                "internal_access": "no",
                "802_1x_used": "no",
                "weak_psks": "yes",
            }
        }

        self.project.cap = {}
        self.project.data_responses = {}
        self.project.workbook_data = workbook_payload
        self.project.save(update_fields=["cap", "data_responses", "workbook_data"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_wireless_map = {
            "PSK’s in use on wireless networks": general_map.get(
                "PSK’s in use on wireless networks"
            ),
            "WEP in use on wireless networks": general_map.get(
                "WEP in use on wireless networks"
            ),
            "802.1x authentication not implemented for wireless networks": general_map.get(
                "802.1x authentication not implemented for wireless networks"
            ),
            "Weak PSK's in use": general_map.get("Weak PSK's in use"),
        }

        wireless_cap = self.project.cap.get("wireless")
        self.assertIsInstance(wireless_cap, dict)
        self.assertEqual(wireless_cap.get("wireless_cap_map"), expected_wireless_map)

    def test_wireless_cap_map_removed_when_conditions_not_met(self):
        general_map = load_general_cap_map()
        existing_cap = {
            "wireless": {
                "wireless_cap_map": {
                    "corp.example.com": {
                        "PSK’s in use on wireless networks": general_map.get(
                            "PSK’s in use on wireless networks"
                        )
                    }
                }
            }
        }

        workbook_payload = {
            "wireless": {
                "domains": [
                    {
                        "domain": "corp.example.com",
                        "psk_count": 0,
                        "rogue_count": 0,
                        "wep_inuse": {"confirm": "no"},
                        "internal_access": "no",
                        "802_1x_used": "yes",
                        "weak_psks": "no",
                    }
                ]
            }
        }

        self.project.cap = existing_cap
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["cap", "workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertNotIn("wireless", self.project.cap)

    def test_sql_cap_map_populated_from_workbook(self):
        workbook_payload = {"sql": {"total_open": 3}}

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.cap = {}
        self.project.save(update_fields=["workbook_data", "data_responses", "cap"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_sql_map = {
            "Databases allowing open access": general_map.get(
                "Databases allowing open access"
            )
        }

        sql_cap = self.project.cap.get("sql")
        self.assertIsInstance(sql_cap, dict)
        self.assertEqual(sql_cap.get("sql_cap_map"), expected_sql_map)

    def test_sql_cap_map_removed_when_conditions_not_met(self):
        general_map = load_general_cap_map()
        existing_cap = {
            "sql": {
                "sql_cap_map": {
                    "Databases allowing open access": general_map.get(
                        "Databases allowing open access"
                    )
                }
            }
        }

        workbook_payload = {"sql": {"total_open": 0}}

        self.project.cap = existing_cap
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["cap", "workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertNotIn("sql", self.project.cap)

    def test_snmp_cap_map_populated_from_workbook(self):
        workbook_payload = {"snmp": {"total_strings": 2}}

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.cap = {}
        self.project.save(update_fields=["workbook_data", "data_responses", "cap"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        general_map = load_general_cap_map()
        expected_snmp_map = {
            "Default SNMP community strings & default credentials in use": general_map.get(
                "Default SNMP community strings & default credentials in use"
            )
        }

        snmp_cap = self.project.cap.get("snmp")
        self.assertIsInstance(snmp_cap, dict)
        self.assertEqual(snmp_cap.get("snmp_cap_map"), expected_snmp_map)

    def test_snmp_cap_map_removed_when_conditions_not_met(self):
        general_map = load_general_cap_map()
        existing_cap = {
            "snmp": {
                "snmp_cap_map": {
                    "Default SNMP community strings & default credentials in use": general_map.get(
                        "Default SNMP community strings & default credentials in use"
                    )
                }
            }
        }

        workbook_payload = {"snmp": {"total_strings": 0}}

        self.project.cap = existing_cap
        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["cap", "workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        self.assertNotIn("snmp", self.project.cap)

    def test_password_cap_map_uses_database(self):
        PasswordCapMapping.objects.update_or_create(
            setting="max_age",
            defaults={"cap_text": "custom max age guidance"},
        )

        workbook_payload = {
            "password": {
                "policies": [
                    {
                        "domain_name": "corp.example.com",
                        "passwords_cracked": 2,
                        "enabled_accounts": 20,
                        "history": 5,
                        "max_age": 90,
                        "min_age": 0,
                        "min_length": 6,
                        "lockout_threshold": 8,
                        "lockout_duration": 10,
                        "lockout_reset": 15,
                        "complexity_enabled": "yes",
                    }
                ]
            }
        }

        self.project.workbook_data = workbook_payload
        self.project.data_responses = {}
        self.project.save(update_fields=["workbook_data", "data_responses"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        password_responses = self.project.data_responses.get("password")
        policy_cap_map = password_responses.get("policy_cap_map", {})
        self.assertEqual(
            policy_cap_map.get("corp.example.com", {})
            .get("policy", {})
            .get("max_age"),
            "custom max age guidance",
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
        self.assertIn("ai_response", web_artifact)
        self.assertIsNone(web_artifact["ai_response"])
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

    def test_burp_cap_upload_populates_web_cap_map(self):
        csv_lines = [
            "Issue,Host(s),Action,ecfirst,Sev,Score",
            "Expired TLS Certificate,portal.example.com,Renew the TLS certificate,Yes,High,5",
            "Missing Security Headers,,Add CSP and HSTS,No,Medium,3",
            ",,,,",
        ]

        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=SimpleUploadedFile(
                "burp_cap.csv",
                "\n".join(csv_lines).encode("utf-8"),
                content_type="text/csv",
            ),
            requirement_label="burp_cap.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        web_section = self.project.cap.get("web")
        self.assertIsInstance(web_section, dict)
        self.assertEqual(
            web_section.get("web_cap_map"),
            [
                {
                    "issue": "Expired TLS Certificate",
                    "hosts": "portal.example.com",
                    "action": "Renew the TLS certificate",
                    "ecfirst": "Yes",
                    "severity": "High",
                    "score": 5,
                },
                {
                    "issue": "Missing Security Headers",
                    "action": "Add CSP and HSTS",
                    "ecfirst": "No",
                    "severity": "Medium",
                    "score": 3,
                },
            ],
        )

        artifacts = self.project.data_artifacts
        self.assertIsInstance(artifacts, dict)
        self.assertNotIn("web_cap_map", artifacts)
        self.assertNotIn("web_cap_entries", artifacts)

        web_response = self.project.data_responses.get("web")
        if isinstance(web_response, dict):
            self.assertNotIn("web_cap_map", web_response)
            self.assertNotIn("web_cap_entries", web_response)

    @mock.patch("ghostwriter.rolodex.data_parsers.submit_prompt_to_assistant")
    def test_web_issue_ai_response_generated_for_high_severity(self, mock_prompt):
        OpenAIConfigurationFactory(enable=True, assistant_id="asst_123", api_key="sk-test")
        csv_lines = [
            "Host,Risk,Issue,Impact",
            "portal.example.com,High,SQL Injection,This may lead to compromise.",
            "portal.example.com,High,Cross-Site Scripting,This may allow credential theft.",
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

        mock_prompt.side_effect = ["SQL summary", "XSS summary"]

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        web_artifact = self.project.data_artifacts.get("web_issues")
        self.assertEqual(web_artifact.get("ai_response"), "SQL summary XSS summary")
        self.assertEqual(mock_prompt.call_count, 2)

    def test_web_issue_matrix_enriches_summary(self):
        WebIssueMatrixEntry.objects.create(
            title="SQL Injection",
            impact="SQL matrix impact",
            fix="Use parameterized queries",
        )
        csv_lines = [
            "Host,Risk,Issue,Impact",
            "portal.example.com,High,SQL Injection,Original impact",
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
        high_items = web_artifact["high"]["items"]
        self.assertTrue(high_items)
        self.assertEqual(high_items[0]["impact"], "SQL matrix impact")
        self.assertEqual(high_items[0]["fix"], "Use parameterized queries")

    def test_nexpose_cap_upload_populates_cap_map(self):
        csv_lines = [
            "Systems,Action,Sev,Issue,ecfirst",
            "db01.example.com,Patch OpenSSL,5,SSL Certificate Expired,Yes",
            "web-tier,Restrict Access,3,,",
        ]

        upload = ProjectDataFile.objects.create(
            project=self.project,
            file=SimpleUploadedFile(
                "nexpose_cap.csv",
                "\n".join(csv_lines).encode("utf-8"),
                content_type="text/csv",
            ),
            requirement_label="nexpose_cap.csv",
        )
        self.addCleanup(lambda: ProjectDataFile.objects.filter(pk=upload.pk).delete())

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        nexpose_section = self.project.cap.get("nexpose")
        self.assertIsInstance(nexpose_section, dict)
        self.assertEqual(
            nexpose_section.get("nexpose_cap_map"),
            [
                {
                    "systems": "db01.example.com",
                    "action": "Patch OpenSSL",
                    "score": 5,
                    "issue": "SSL Certificate Expired",
                    "ecfirst": "Yes",
                },
                {
                    "systems": "web-tier",
                    "action": "Restrict Access",
                    "score": 3,
                },
            ],
        )

        artifacts = self.project.data_artifacts
        self.assertIsInstance(artifacts, dict)
        self.assertNotIn("nexpose_cap_map", artifacts)

    def test_nexpose_cap_section_includes_default_distilled_flag(self):
        self.project.cap = {}
        self.project.save(update_fields=["cap"])

        self.project.rebuild_data_artifacts()
        self.project.refresh_from_db()

        nexpose_section = self.project.cap.get("nexpose")
        self.assertIsInstance(nexpose_section, dict)
        self.assertIn("distilled", nexpose_section)
        self.assertFalse(nexpose_section["distilled"])


class DNSDataParserTests(TestCase):
    """Validate DNS CSV parsing behaviour."""

    def test_parse_dns_report_uses_database_mappings(self):
        issue_text = "Custom authoritative nameserver issue"
        DNSFindingMapping.objects.create(
            issue_text=issue_text,
            finding_text="custom finding language",
        )
        DNSRecommendationMapping.objects.create(
            issue_text=issue_text,
            recommendation_text="custom recommendation language",
        )
        DNSCapMapping.objects.create(
            issue_text=issue_text,
            cap_text="custom cap language",
        )

        upload = SimpleUploadedFile(
            "dns_report.csv",
            f"Status,Info\nFAIL,{issue_text}\n".encode("utf-8"),
            content_type="text/csv",
        )

        issues = parse_dns_report(upload)

        self.assertEqual(len(issues), 1)
        self.assertEqual(
            issues[0],
            {
                "issue": issue_text,
                "finding": "custom finding language",
                "recommendation": "custom recommendation language",
                "cap": "custom cap language",
                "impact": "",
            },
        )

    def test_load_general_cap_map_prefers_database(self):
        mapping = load_general_cap_map()
        weak_passwords = mapping.get("Weak passwords in use")
        self.assertIsInstance(weak_passwords, dict)
        self.assertEqual(weak_passwords.get("score"), 7)
        self.assertIn("Force all accounts whose password was cracked", weak_passwords.get("recommendation", ""))

        GeneralCapMapping.objects.update_or_create(
            issue_text="Weak passwords in use",
            defaults={
                "recommendation_text": "custom weak password guidance",
                "score": 8,
            },
        )

        updated_mapping = load_general_cap_map()
        updated = updated_mapping.get("Weak passwords in use")
        self.assertIsInstance(updated, dict)
        self.assertEqual(updated.get("recommendation"), "custom weak password guidance")
        self.assertEqual(updated.get("score"), 8)

    def test_load_dns_soa_cap_map_prefers_database(self):
        mapping = load_dns_soa_cap_map()
        self.assertEqual(
            mapping.get("serial"),
            "Update to match the 'YYYYMMDDnn' scheme",
        )

        DNSSOACapMapping.objects.update_or_create(
            soa_field="serial",
            defaults={"cap_text": "custom serial guidance"},
        )

        updated_mapping = load_dns_soa_cap_map()
        self.assertEqual(updated_mapping.get("serial"), "custom serial guidance")

    def test_load_password_cap_map_prefers_database(self):
        mapping = load_password_cap_map()
        self.assertEqual(
            mapping.get("max_age"),
            "Change 'Maximum Age' from {{ max_age }} to == 0 to align with NIST recommendations "
            "to not force users to arbitrarily change passwords based solely on age",
        )

        PasswordCapMapping.objects.update_or_create(
            setting="max_age",
            defaults={"cap_text": "custom max age guidance"},
        )

        updated_mapping = load_password_cap_map()
        self.assertEqual(updated_mapping.get("max_age"), "custom max age guidance")

    def test_load_password_compliance_matrix_prefers_database(self):
        matrix = load_password_compliance_matrix()
        self.assertEqual(matrix.get("max_age", {}).get("data_type"), "numeric")
        self.assertEqual(matrix.get("complexity_enabled", {}).get("data_type"), "string")

        PasswordComplianceMapping.objects.update_or_create(
            setting="max_age",
            defaults={
                "data_type": "numeric",
                "rule": {"operator": "lt", "value": 30},
            },
        )

        updated_matrix = load_password_compliance_matrix()
        self.assertEqual(
            updated_matrix.get("max_age", {}).get("rule", {}).get("value"),
            30,
        )

    def test_password_compliance_matrix_override_adjusts_failures(self):
        workbook_payload = {
            "password": {
                "policies": [
                    {
                        "domain_name": "corp.example.com",
                        "passwords_cracked": 5,
                        "enabled_accounts": 100,
                        "admin_cracked": {"confirm": "Yes", "count": 1},
                        "max_age": 90,
                        "min_age": 0,
                        "min_length": 7,
                        "history": 5,
                        "lockout_threshold": 8,
                        "lockout_duration": 10,
                        "lockout_reset": 20,
                        "complexity_enabled": "TRUE",
                    }
                ]
            }
        }

        _summary, domain_values, _domains = build_workbook_password_response(
            workbook_payload
        )
        corp_entry = domain_values.get("corp.example.com")
        self.assertIsInstance(corp_entry, dict)
        self.assertIn("max_age", corp_entry.get("policy_cap_fields", []))
        self.assertEqual(
            corp_entry.get("policy_cap_values", {}).get("max_age"),
            90,
        )

        PasswordComplianceMapping.objects.update_or_create(
            setting="max_age",
            defaults={
                "data_type": "numeric",
                "rule": {"operator": "lt", "value": 30},
            },
        )

        _summary, updated_domain_values, _domains = build_workbook_password_response(
            workbook_payload
        )
        updated_entry = updated_domain_values.get("corp.example.com")
        self.assertIsInstance(updated_entry, dict)
        self.assertNotIn("max_age", updated_entry.get("policy_cap_fields", []))
