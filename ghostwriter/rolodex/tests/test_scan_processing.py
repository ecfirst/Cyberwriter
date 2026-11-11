"""Tests for the project-less Scan Processing page and its cache-backed workspace."""

# Standard Libraries
import base64
import io
import shutil
import tempfile
from unittest import mock

# Django Imports
from django.core.cache import cache
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

# 3rd Party Libraries
from openpyxl import load_workbook

# Ghostwriter Libraries
from ghostwriter.factories import UserFactory
from ghostwriter.rolodex import scan_processing as store
from ghostwriter.rolodex.models import WebIssueMatrixEntry
from ghostwriter.rolodex.workbook_metrics import (
    derive_nexpose_workbook_section,
    derive_web_workbook_section,
)

PASSWORD = "SuperNaturalReporting!"
TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="cw-scan-processing-")

NEXPOSE_XML = """<?xml version='1.0' encoding='UTF-8'?>
<NexposeReport version='1.0'>
  <nodes>
    <node address='10.0.0.5' status='alive'>
      <names><name>async-host.example.com</name></names>
      <tests>
        <test id='async-issue' status='vulnerable-exploited'>
          <Paragraph><Paragraph>Async proof</Paragraph></Paragraph>
        </test>
      </tests>
    </node>
  </nodes>
  <vulnerabilityDefinitions>
    <vulnerability id='async-issue' title='Async Issue' severity='8'>
      <description>Async description</description>
      <solution>Fix async issue</solution>
    </vulnerability>
  </vulnerabilityDefinitions>
</NexposeReport>
"""

_BURP_RESPONSE = base64.b64encode(
    b"HTTP/1.1 200 OK\r\nHeader: value\r\n\r\n<html>content</html>"
).decode()

BURP_XML = f"""<?xml version='1.0' encoding='UTF-8'?>
<issues>
  <issue>
    <serialNumber>1</serialNumber>
    <type>134217728</type>
    <name>SQL Server injection</name>
    <host ip='192.0.2.1'>app.example.com</host>
    <path>/login</path>
    <location>/login</location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueBackground><p>Some background</p></issueBackground>
    <issueDetail><b>Example evidence</b></issueDetail>
    <remediationBackground>Patch immediately</remediationBackground>
    <requestresponse>
      <response base64='true'>{_BURP_RESPONSE}</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <type>99999</type>
    <name>Vulnerable Software detected on host</name>
    <host ip='198.51.100.2'>app.example.com</host>
    <path>/status</path>
    <location>/status</location>
    <severity>Information</severity>
    <confidence>Certain</confidence>
    <issueDetail>Software outdated</issueDetail>
    <remediationDetail></remediationDetail>
  </issue>
</issues>
"""


def _nexpose_upload(name="external_scan.xml", content=NEXPOSE_XML):
    return SimpleUploadedFile(name, content.encode("utf-8"), content_type="text/xml")


def _burp_upload(name="burp_export.xml", content=BURP_XML):
    return SimpleUploadedFile(name, content.encode("utf-8"), content_type="text/xml")


def _temp_upload_names():
    try:
        _dirs, files = default_storage.listdir(store.TEMP_UPLOAD_DIR)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return []
    return list(files)


@override_settings(MEDIA_ROOT=TEMP_MEDIA_ROOT)
class ScanProcessingViewTests(TestCase):
    """Exercise the page, uploads, downloads, and workspace lifecycle."""

    @classmethod
    def setUpTestData(cls):
        cls.user = UserFactory(password=PASSWORD)
        cls.other_user = UserFactory(password=PASSWORD)
        cls.page_url = reverse("rolodex:scan_processing")
        cls.upload_url = reverse("rolodex:ajax_upload_scan_processing_file")
        cls.state_url = reverse("rolodex:ajax_scan_processing_state")
        cls.clear_url = reverse("rolodex:ajax_clear_scan_processing")
        cls.remove_nexpose_url = reverse(
            "rolodex:ajax_remove_scan_processing_result", kwargs={"slot": store.SLOT_NEXPOSE}
        )
        cls.remove_web_url = reverse(
            "rolodex:ajax_remove_scan_processing_result", kwargs={"slot": store.SLOT_WEB}
        )
        cls.nexpose_download_url = reverse("rolodex:scan_processing_nexpose_data_download")
        cls.web_download_url = reverse("rolodex:scan_processing_web_data_download")
        cls.nexpose_missing_url = reverse("rolodex:scan_processing_nexpose_missing_download")
        cls.web_missing_url = reverse("rolodex:scan_processing_web_issue_missing_download")

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(TEMP_MEDIA_ROOT, ignore_errors=True)

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.assertTrue(self.client.login(username=self.user.username, password=PASSWORD))

    def _token(self, client=None):
        client = client or self.client
        return client.session.get(store.SESSION_TOKEN_KEY)

    # -- page ---------------------------------------------------------------

    def test_page_requires_login(self):
        response = Client().get(self.page_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response["Location"])

    def test_page_renders_empty_state_and_creates_token(self):
        response = self.client.get(self.page_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "rolodex/scan_processing.html")
        self.assertContains(response, "Scan Processing")
        self.assertContains(response, "No Nexpose XML has been processed.")
        self.assertContains(response, "No sites have been added yet.")
        self.assertContains(response, 'data-processing="0"')
        token = self._token()
        self.assertTrue(token)
        self.assertEqual(cache.get(store._meta_key(token))["owner_id"], self.user.pk)

    def test_sidebar_links_to_page(self):
        response = self.client.get(reverse("home:dashboard"))
        self.assertContains(response, self.page_url)
        self.assertContains(response, "Scan Processing")

    # -- nexpose ------------------------------------------------------------

    def test_nexpose_upload_is_queued_processed_and_cleaned_up(self):
        response = self.client.post(
            self.upload_url, {"upload_field": "nexpose_xml", "file": _nexpose_upload()}
        )
        self.assertEqual(response.status_code, 202)
        payload = response.json()
        self.assertTrue(payload["queued"])
        self.assertEqual(payload["upload_field"], "nexpose_xml")

        # Q_CLUSTER["sync"] = True ran the task inline, so results are visible now.
        token = self._token()
        result = store.read_result(token, store.SLOT_NEXPOSE)
        self.assertIsNotNone(result)
        self.assertEqual(result["file_name"], "external_scan.xml")
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["metrics"]["summary"]["total"], 1)
        self.assertEqual(result["metrics"]["summary"]["total_high"], 1)
        self.assertIn("xlsx", result["metrics"])
        for trimmed in ("all_issues", "high_issues", "majority_unique", "_xlsx_temp_path"):
            self.assertNotIn(trimmed, result["metrics"])
        self.assertEqual(result["workbook"]["total"], 1)
        self.assertEqual(result["workbook"]["total_high"], 1)
        self.assertEqual([row["Vulnerability"] for row in result["missing_matrix_entries"]], ["Async Issue"])

        workbook_bytes = store.read_xlsx(token, store.SLOT_NEXPOSE)
        self.assertTrue(workbook_bytes)
        self.assertTrue(load_workbook(io.BytesIO(workbook_bytes)).sheetnames)

        self.assertEqual(store.get_processing_uploads(token), {})
        self.assertEqual(_temp_upload_names(), [])

        page = self.client.get(self.page_url)
        self.assertContains(page, "Total Count")
        self.assertContains(page, "Download Nexpose Data file")
        self.assertContains(page, "Missing Nexpose issues identified!")
        self.assertContains(page, "external_scan.xml")
        self.assertContains(page, 'data-processing="0"')

    def test_nexpose_downloads(self):
        self.client.post(self.upload_url, {"upload_field": "nexpose_xml", "file": _nexpose_upload()})

        response = self.client.get(self.nexpose_download_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertIn("nexpose_data.xlsx", response["Content-Disposition"])

        response = self.client.get(self.nexpose_missing_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        lines = response.content.decode().splitlines()
        self.assertEqual(
            lines[0], "Vulnerability,Action Required,Remediation Impact,Vulnerability Threat,Category,CVE"
        )
        self.assertTrue(lines[1].startswith("Async Issue"))

    def test_nexpose_download_without_data_redirects(self):
        response = self.client.get(self.nexpose_download_url)
        self.assertRedirects(response, self.page_url, fetch_redirect_response=False)
        response = self.client.get(self.nexpose_missing_url)
        self.assertRedirects(response, self.page_url, fetch_redirect_response=False)

    def test_page_shows_processing_state(self):
        token = store.get_or_create_token(self._request_stub())
        store.set_processing(token, store.SLOT_NEXPOSE, filename="big.xml")
        session = self.client.session
        session[store.SESSION_TOKEN_KEY] = token
        session.save()

        page = self.client.get(self.page_url)
        self.assertContains(page, 'data-processing="1"')
        self.assertContains(page, "Processing upload")
        self.assertContains(page, "big.xml")

        state = self.client.get(self.state_url).json()
        self.assertIn("nexpose_xml", state["data_artifacts"]["processing_uploads"])

        # A second Nexpose upload while one is processing is refused.
        response = self.client.post(
            self.upload_url, {"upload_field": "nexpose_xml", "file": _nexpose_upload()}
        )
        self.assertEqual(response.status_code, 409)
        response = self.client.post(self.remove_nexpose_url)
        self.assertEqual(response.status_code, 409)

    def test_nexpose_task_failure_cleans_up_and_notifies(self):
        with mock.patch(
            "ghostwriter.rolodex.scan_processing.process_nexpose_upload",
            side_effect=RuntimeError("boom"),
        ), mock.patch("ghostwriter.rolodex.tasks._notify_user") as notify:
            response = self.client.post(
                self.upload_url, {"upload_field": "nexpose_xml", "file": _nexpose_upload()}
            )
        self.assertEqual(response.status_code, 202)
        token = self._token()
        self.assertIsNone(store.read_result(token, store.SLOT_NEXPOSE))
        self.assertEqual(store.get_processing_uploads(token), {})
        self.assertEqual(_temp_upload_names(), [])
        self.assertIn("nexpose_xml", store.get_errors(token))
        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs["status"], "error")
        self.assertEqual(notify.call_args.kwargs["event"], "scan_processing_complete")
        self.assertEqual(notify.call_args.kwargs["token"], token)

        page = self.client.get(self.page_url)
        self.assertContains(page, "Something went wrong while processing external_scan.xml")

    def test_malformed_nexpose_xml_yields_warning_notification(self):
        with mock.patch("ghostwriter.rolodex.tasks._notify_user") as notify:
            response = self.client.post(
                self.upload_url,
                {"upload_field": "nexpose_xml", "file": _nexpose_upload(content="<not-xml")},
            )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(notify.call_args.kwargs["status"], "warning")
        self.assertEqual(_temp_upload_names(), [])

    # -- burp / web ---------------------------------------------------------

    def test_burp_upload_is_processed_inline(self):
        WebIssueMatrixEntry.objects.create(
            title="SQL injection", impact="Matrix impact", fix="Matrix fix"
        )
        with mock.patch("ghostwriter.rolodex.data_parsers._build_web_issue_ai_response") as ai:
            response = self.client.post(
                self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload()}
            )
        self.assertEqual(response.status_code, 200)
        ai.assert_not_called()

        payload = response.json()
        self.assertIn("message", payload)
        summary = payload["data_artifacts"]["web_metrics"]["summary"]
        self.assertEqual(summary["host_risk_counts"][0]["host"], "app.example.com")
        self.assertEqual(summary["unique_high"], 1)
        self.assertNotIn("xlsx_base64", payload["data_artifacts"]["web_metrics"])
        self.assertIn("xlsx", payload["data_artifacts"]["web_metrics"])
        self.assertEqual(payload["workbook_data"]["web"]["sites"][0]["url"], "app.example.com")
        self.assertEqual(payload["workbook_data"]["web"]["sites"][0]["unique_high"], 1)
        self.assertEqual(payload["workbook_data"]["web"]["combined_unique_high"], 1)
        gaps = payload["data_artifacts"]["web_issue_matrix_gaps"]["entries"]
        self.assertTrue(any("Vulnerable Software" in row["issue"] for row in gaps))

        page = self.client.get(self.page_url)
        self.assertContains(page, "Site/App 1")
        self.assertContains(page, "app.example.com")
        self.assertContains(page, "Combined Metrics")
        self.assertContains(page, "Download Web Data file")
        self.assertContains(page, "Missing Web issues identified!")
        self.assertContains(page, "burp_export.xml")

        response = self.client.get(self.web_download_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("burp_data.xlsx", response["Content-Disposition"])
        self.assertTrue(load_workbook(io.BytesIO(response.content)).sheetnames)

        response = self.client.get(self.web_missing_url)
        self.assertEqual(response.status_code, 200)
        lines = response.content.decode().splitlines()
        self.assertEqual(lines[0], "issue,impact,fix")
        self.assertGreaterEqual(len(lines), 2)

    def test_burp_upload_never_calls_openai(self):
        with mock.patch("ghostwriter.rolodex.data_parsers.submit_prompt_to_assistant") as prompt:
            response = self.client.post(
                self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload()}
            )
        self.assertEqual(response.status_code, 200)
        prompt.assert_not_called()

    def test_malformed_burp_xml_returns_warning(self):
        response = self.client.post(
            self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload(content="<not-xml")}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("warning", payload)
        result = store.read_result(self._token(), store.SLOT_WEB)
        self.assertEqual(result["total_findings"], 0)
        self.assertIsNone(store.read_xlsx(self._token(), store.SLOT_WEB))

    def test_cache_write_failure_returns_503(self):
        fake_cache = mock.MagicMock()
        fake_cache.get.return_value = None
        with mock.patch.object(store, "cache", fake_cache):
            response = self.client.post(
                self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload()}
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("error", response.json())

    # -- validation ---------------------------------------------------------

    def test_rejects_non_xml_and_unknown_field(self):
        response = self.client.post(
            self.upload_url,
            {"upload_field": "burp_xml", "file": SimpleUploadedFile("notes.txt", b"hello")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(".xml", response.json()["error"])

        response = self.client.post(
            self.upload_url, {"upload_field": "firewall_xml", "file": _burp_upload()}
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(self.upload_url, {"upload_field": "burp_xml"})
        self.assertEqual(response.status_code, 400)

        response = self.client.post(reverse("rolodex:ajax_remove_scan_processing_result", kwargs={"slot": "bogus"}))
        self.assertEqual(response.status_code, 400)

    # -- lifecycle ----------------------------------------------------------

    def test_remove_and_clear(self):
        self.client.post(self.upload_url, {"upload_field": "nexpose_xml", "file": _nexpose_upload()})
        self.client.post(self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload()})
        token = self._token()
        self.assertIsNotNone(store.read_result(token, store.SLOT_NEXPOSE))
        self.assertIsNotNone(store.read_result(token, store.SLOT_WEB))

        response = self.client.post(self.remove_web_url)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(store.read_result(token, store.SLOT_WEB))
        self.assertIsNone(store.read_xlsx(token, store.SLOT_WEB))
        self.assertIsNotNone(store.read_result(token, store.SLOT_NEXPOSE))
        self.assertNotIn("web_metrics", response.json()["data_artifacts"])

        response = self.client.post(self.clear_url)
        self.assertEqual(response.status_code, 200)
        new_token = self._token()
        self.assertNotEqual(new_token, token)
        self.assertIsNone(store.read_result(token, store.SLOT_NEXPOSE))
        self.assertIsNone(store.read_xlsx(token, store.SLOT_NEXPOSE))
        self.assertIsNone(cache.get(store._meta_key(token)))
        self.assertEqual(response.json()["token"], new_token)

    def test_workspaces_are_isolated_per_user(self):
        self.client.post(self.upload_url, {"upload_field": "burp_xml", "file": _burp_upload()})
        token_a = self._token()

        other = Client()
        self.assertTrue(other.login(username=self.other_user.username, password=PASSWORD))
        page = other.get(self.page_url)
        self.assertContains(page, "No sites have been added yet.")
        self.assertNotEqual(self._token(other), token_a)

        # A session carrying another user's token is rotated, never read.
        session = other.session
        session[store.SESSION_TOKEN_KEY] = token_a
        session.save()
        page = other.get(self.page_url)
        self.assertContains(page, "No sites have been added yet.")
        self.assertNotEqual(self._token(other), token_a)
        self.assertIsNotNone(store.read_result(token_a, store.SLOT_WEB))

    def test_stale_upload_cleanup_only_removes_old_files(self):
        stale_path = default_storage.save(f"{store.TEMP_UPLOAD_DIR}/stale.xml", io.BytesIO(b"<x/>"))
        fresh_path = default_storage.save(f"{store.TEMP_UPLOAD_DIR}/fresh.xml", io.BytesIO(b"<x/>"))
        with mock.patch.object(
            store.default_storage,
            "get_modified_time",
            side_effect=lambda path: store.timezone.now()
            - (store.STALE_UPLOAD_MAX_AGE * 2 if "stale" in path else store.datetime.timedelta(0)),
        ):
            removed = store.cleanup_stale_uploads()
        self.assertEqual(removed, 1)
        self.assertFalse(default_storage.exists(stale_path))
        self.assertTrue(default_storage.exists(fresh_path))
        default_storage.delete(fresh_path)

    # -- helpers ------------------------------------------------------------

    def _request_stub(self):
        request = mock.Mock()
        request.user = self.user
        request.session = {}
        return request


class WorkbookMetricsDerivationTests(TestCase):
    """The lifted derivation helpers behave like the closures they replaced."""

    def test_nexpose_section_maps_summary_and_category_labels(self):
        metrics = {
            "summary": {
                "total": "7",
                "total_high": 2,
                "total_med": 3,
                "total_low": 2,
                "unique": 5,
                "unique_high_med": 4,
                "total_ood": 3,
                "total_isc": 1,
                "total_iwc": 1,
                "majority_count": 9,
                "minority_count": 8,
            },
            "majority_type": "ood",
            "minority_type": "even",
            "host_counts": [{"host": "a", "count": 1}],
            "top_hosts": ["a"],
            "top_hosts_high": "2",
            "top_hosts_total": None,
        }
        existing = {"unique_majority_sub": 42, "total": 0}
        section = derive_nexpose_workbook_section(metrics, existing)

        self.assertEqual(existing["total"], 0)  # caller's dict untouched
        self.assertEqual(section["unique_majority_sub"], 42)
        self.assertEqual(section["total"], 7)
        self.assertEqual(section["unique_high_med"], 4)
        self.assertEqual(section["host_counts"], [{"host": "a", "count": 1}])
        self.assertEqual(section["top_hosts_high"], 2)
        self.assertEqual(section["top_hosts_total"], 0)
        self.assertEqual(section["majority_type"], "OOD Software or Missing Patches")
        self.assertEqual(section["unique_majority"], 3)
        self.assertEqual(section["minority_type"], "Even")
        self.assertEqual(section["unique_minority"], 8)

    def test_nexpose_section_without_summary_zeroes_counts(self):
        section = derive_nexpose_workbook_section({}, None)
        self.assertEqual(section["total"], 0)
        self.assertNotIn("majority_type", section)

    def test_web_section_builds_sites_from_host_risk_counts(self):
        metrics = {
            "summary": {
                "unique": 3,
                "unique_high": 1,
                "unique_med": "1",
                "unique_low": 1,
                "host_risk_counts": [
                    {"host": "app.example.com", "high": 1, "medium": 1, "low": 1},
                    {"host": "", "high": 9},
                    "not-a-dict",
                ],
            }
        }
        section = derive_web_workbook_section(metrics, {"sites": [{"url": "old"}]})
        self.assertEqual(section["combined_unique"], 3)
        self.assertEqual(section["combined_unique_med"], 1)
        self.assertEqual(
            section["sites"],
            [{"url": "app.example.com", "unique_high": 1, "unique_med": 1, "unique_low": 1}],
        )

    def test_web_section_without_summary_is_unchanged(self):
        existing = {"sites": [{"url": "keep"}], "combined_unique": 2}
        section = derive_web_workbook_section({"summary": None}, existing)
        self.assertEqual(section, existing)
        self.assertIsNot(section, existing)
