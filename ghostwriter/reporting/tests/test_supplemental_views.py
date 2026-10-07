# Standard Libraries
import logging
import os
import shutil
import tempfile
from unittest import mock

# Django Imports
from django.contrib.messages import get_messages
from django.test import Client, TestCase, override_settings
from django.urls import reverse

# Ghostwriter Libraries
from ghostwriter.factories import ProjectAssignmentFactory, ReportFactory, UserFactory
from ghostwriter.reporting.models import ReportSupplementalFile
from ghostwriter.reporting.tests.supplemental_fixtures import (
    nexpose_workbook,
    uploaded,
    web_workbook,
)

logging.disable(logging.CRITICAL)

PASSWORD = "SuperNaturalReporting!"
MEDIA_ROOT = tempfile.mkdtemp(prefix="gw-supplementals-")


def tearDownModule():
    shutil.rmtree(MEDIA_ROOT, ignore_errors=True)


def messages_for(response):
    return [str(message) for message in get_messages(response.wsgi_request)]


def create_supplemental(report, kind="nexpose", filename=None, data=None, **extra):
    """Create a :model:`reporting.ReportSupplementalFile` with a real file on disk."""
    filename = filename or f"{kind}.xlsx"
    data = (
        data
        if data is not None
        else (nexpose_workbook() if kind == "nexpose" else web_workbook())
    )
    defaults = {
        "original_filename": filename,
        "cap_entries": [
            {
                "source": kind,
                "issue": "A",
                "systems": "",
                "action": "",
                "risk": "High",
                "score": None,
            }
        ],
        "row_count": 1,
    }
    defaults.update(extra)
    return ReportSupplementalFile.objects.create(
        report=report, kind=kind, document=uploaded(filename, data), **defaults
    )


@override_settings(MEDIA_ROOT=MEDIA_ROOT)
class SupplementalViewTestsBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.report = ReportFactory()
        cls.user = UserFactory(password=PASSWORD)
        cls.mgr_user = UserFactory(password=PASSWORD, role="manager")
        cls.detail_uri = reverse("reporting:report_detail", kwargs={"pk": cls.report.pk})
        cls.supplementals_uri = cls.detail_uri + "#supplementals"
        cls.upload_uri = reverse(
            "reporting:report_supplemental_upload", kwargs={"pk": cls.report.pk}
        )

    def setUp(self):
        self.client = Client()
        self.client_auth = Client()
        self.client_mgr = Client()
        self.assertTrue(
            self.client_auth.login(username=self.user.username, password=PASSWORD)
        )
        self.assertTrue(
            self.client_mgr.login(username=self.mgr_user.username, password=PASSWORD)
        )


class ReportSupplementalUploadTests(SupplementalViewTestsBase):
    """Collection of tests for :view:`reporting.ReportSupplementalUpload`."""

    def post_upload(
        self,
        client,
        kind="nexpose",
        filename="nexpose.xlsx",
        data=None,
        content_type=None,
    ):
        data = data if data is not None else nexpose_workbook()
        kwargs = {"content_type": content_type} if content_type else {}
        payload = {"document": uploaded(filename, data, **kwargs)}
        if kind is not None:
            payload["kind"] = kind
        return client.post(self.upload_uri, payload)

    def test_view_requires_login_and_permissions(self):
        response = self.post_upload(self.client)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)

        response = self.post_upload(self.client_auth)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)

        assignment = ProjectAssignmentFactory(
            project=self.report.project, operator=self.user
        )
        response = self.post_upload(self.client_auth)
        self.assertRedirects(
            response, self.supplementals_uri, fetch_redirect_response=False
        )
        self.assertEqual(ReportSupplementalFile.objects.count(), 1)
        assignment.delete()

    def test_get_is_not_allowed(self):
        response = self.client_mgr.get(self.upload_uri)
        self.assertEqual(response.status_code, 405)

    def test_upload_nexpose_workbook(self):
        response = self.post_upload(
            self.client_mgr, filename="Client Detailed System Vulnerability Findings.xlsx"
        )
        self.assertRedirects(
            response, self.supplementals_uri, fetch_redirect_response=False
        )

        obj = ReportSupplementalFile.objects.get(report=self.report, kind="nexpose")
        self.assertEqual(obj.row_count, 3)
        self.assertEqual(len(obj.cap_entries), 3)
        self.assertEqual(
            obj.original_filename, "Client Detailed System Vulnerability Findings.xlsx"
        )
        self.assertEqual(obj.uploaded_by, self.mgr_user)
        self.assertTrue(obj.parse_warnings)
        self.assertTrue(os.path.isfile(obj.document.path))
        self.assertTrue(
            obj.document.name.startswith(f"supplementals/report_{self.report.pk}/")
        )

        messages = messages_for(response)
        self.assertIn("Uploaded the Nexpose workbook: 3 CAP rows.", messages)
        self.assertTrue(
            any(m.startswith("2 parser warnings:") for m in messages), messages
        )

    def test_upload_web_workbook(self):
        response = self.post_upload(
            self.client_mgr, kind="web", filename="web.xlsx", data=web_workbook()
        )
        self.assertEqual(response.status_code, 302)
        obj = ReportSupplementalFile.objects.get(report=self.report, kind="web")
        self.assertEqual(obj.row_count, 2)
        self.assertEqual(obj.parse_warnings, [])
        self.assertEqual(
            messages_for(response), ["Uploaded the Web (Burp) workbook: 2 CAP rows."]
        )

    def test_rejects_non_xlsx_files(self):
        response = self.post_upload(
            self.client_mgr,
            filename="notes.txt",
            data=b"hello",
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)
        self.assertTrue(
            messages_for(response)[0].startswith("Could not upload the file: document:")
        )

    def test_rejects_unparseable_workbook(self):
        response = self.post_upload(
            self.client_mgr, filename="bad.xlsx", data=b"not a workbook"
        )
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)
        self.assertIn(
            "Could not parse the Nexpose workbook: The file is not a valid XLSX workbook.",
            messages_for(response),
        )

    def test_parse_error_keeps_existing_file(self):
        self.post_upload(self.client_mgr, filename="good.xlsx")
        existing = ReportSupplementalFile.objects.get(report=self.report, kind="nexpose")
        existing_path = existing.document.path

        self.post_upload(self.client_mgr, filename="bad.xlsx", data=b"garbage")
        still = ReportSupplementalFile.objects.get(report=self.report, kind="nexpose")
        self.assertEqual(still.pk, existing.pk)
        self.assertEqual(still.original_filename, "good.xlsx")
        self.assertTrue(os.path.isfile(existing_path))

    def test_missing_or_invalid_kind(self):
        response = self.post_upload(self.client_mgr, kind=None)
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)
        self.assertIn("kind:", messages_for(response)[0])

        response = self.post_upload(self.client_mgr, kind="firewall")
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)
        self.assertIn("kind:", messages_for(response)[0])

    def test_replace_updates_row_in_place(self):
        self.post_upload(self.client_mgr, filename="first.xlsx")
        first = ReportSupplementalFile.objects.get(report=self.report, kind="nexpose")
        first_path = first.document.path
        self.assertTrue(os.path.isfile(first_path))

        # Second workbook has a single unique issue so the row count changes
        # Ghostwriter Libraries
        from ghostwriter.reporting.tests.supplemental_fixtures import (
            NEXPOSE_UNIQUE_HEADERS,
            row,
        )

        data = nexpose_workbook(
            unique_rows=[
                row(NEXPOSE_UNIQUE_HEADERS, risk="Low", issue="Only", remediation="Fix")
            ],
            all_rows=[],
        )
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post_upload(
                self.client_mgr, filename="second.xlsx", data=data
            )
        self.assertRedirects(
            response, self.supplementals_uri, fetch_redirect_response=False
        )

        self.assertEqual(
            ReportSupplementalFile.objects.filter(report=self.report).count(), 1
        )
        second = ReportSupplementalFile.objects.get(report=self.report, kind="nexpose")
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(second.original_filename, "second.xlsx")
        self.assertEqual(second.row_count, 1)
        self.assertTrue(os.path.isfile(second.document.path))
        self.assertNotEqual(second.document.path, first_path)
        self.assertFalse(os.path.isfile(first_path), "Replaced file is removed from disk")

    def test_oversize_upload_rejected(self):
        with mock.patch("ghostwriter.reporting.forms.MAX_SUPPLEMENTAL_UPLOAD_BYTES", 10):
            response = self.post_upload(self.client_mgr)
        self.assertEqual(ReportSupplementalFile.objects.count(), 0)
        self.assertIn("larger than", messages_for(response)[0])


class ReportSupplementalDownloadTests(SupplementalViewTestsBase):
    """Collection of tests for :view:`reporting.ReportSupplementalDownload`."""

    def setUp(self):
        super().setUp()
        self.supplemental = create_supplemental(
            self.report, filename="Original Name.xlsx"
        )
        self.uri = reverse(
            "reporting:report_supplemental_download", kwargs={"pk": self.supplemental.pk}
        )

    def test_view_uri_exists_at_desired_location(self):
        response = self.client_mgr.get(self.uri)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get("Content-Disposition"),
            'attachment; filename="Original Name.xlsx"',
        )

    def test_view_requires_login_and_permissions(self):
        response = self.client.get(self.uri)
        self.assertEqual(response.status_code, 302)

        response = self.client_auth.get(self.uri)
        self.assertEqual(response.status_code, 302)

        ProjectAssignmentFactory(operator=self.user, project=self.report.project)
        response = self.client_auth.get(self.uri)
        self.assertEqual(response.status_code, 200)

    def test_missing_file_returns_404(self):
        os.remove(self.supplemental.document.path)
        response = self.client_mgr.get(self.uri)
        self.assertEqual(response.status_code, 404)


class ReportSupplementalDeleteTests(SupplementalViewTestsBase):
    """Collection of tests for :view:`reporting.ReportSupplementalDelete`."""

    def setUp(self):
        super().setUp()
        self.supplemental = create_supplemental(self.report, kind="web")
        self.uri = reverse(
            "reporting:report_supplemental_delete", kwargs={"pk": self.supplemental.pk}
        )

    def test_get_is_not_allowed(self):
        response = self.client_mgr.get(self.uri)
        self.assertEqual(response.status_code, 405)
        self.assertTrue(
            ReportSupplementalFile.objects.filter(pk=self.supplemental.pk).exists()
        )

    def test_view_requires_login_and_permissions(self):
        response = self.client.post(self.uri)
        self.assertEqual(response.status_code, 302)
        response = self.client_auth.post(self.uri)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            ReportSupplementalFile.objects.filter(pk=self.supplemental.pk).exists()
        )

    def test_delete_removes_row_and_file(self):
        path = self.supplemental.document.path
        self.assertTrue(os.path.isfile(path))

        response = self.client_mgr.post(self.uri)
        self.assertRedirects(
            response, self.supplementals_uri, fetch_redirect_response=False
        )
        self.assertFalse(
            ReportSupplementalFile.objects.filter(pk=self.supplemental.pk).exists()
        )
        self.assertFalse(os.path.isfile(path))
        self.assertIn("Deleted the Web (Burp) supplemental file.", messages_for(response))


class ReportDetailSupplementalsTabTests(SupplementalViewTestsBase):
    """Tests for the Supplementals tab rendered by :view:`reporting.ReportDetailView`."""

    def test_tab_renders_two_empty_slots(self):
        response = self.client_mgr.get(self.detail_uri)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'href="#supplementals"')
        self.assertContains(response, 'id="supplementals"')
        self.assertContains(response, "<strong>Web (Burp)</strong>")
        self.assertContains(response, "<strong>Nexpose</strong>")
        self.assertContains(response, "Not uploaded", count=2)
        self.assertContains(response, self.upload_uri)

        self.assertTrue(response.context["can_edit"])
        self.assertFalse(response.context["has_supplementals"])
        self.assertEqual(
            [slot["kind"] for slot in response.context["supplemental_slots"]],
            ["web", "nexpose"],
        )
        self.assertEqual(
            [slot["file"] for slot in response.context["supplemental_slots"]],
            [None, None],
        )

    def test_tab_shows_uploaded_file(self):
        supplemental = create_supplemental(
            self.report,
            kind="nexpose",
            filename="Acme Detailed System Vulnerability Findings.xlsx",
            row_count=7,
            parse_warnings=["Issue 'X' has no systems in All Issues."],
        )
        response = self.client_mgr.get(self.detail_uri)
        self.assertContains(response, "Acme Detailed System Vulnerability Findings.xlsx")
        self.assertContains(
            response,
            reverse(
                "reporting:report_supplemental_download", kwargs={"pk": supplemental.pk}
            ),
        )
        self.assertContains(
            response,
            reverse(
                "reporting:report_supplemental_delete", kwargs={"pk": supplemental.pk}
            ),
        )
        self.assertContains(response, "1 warning")
        self.assertContains(response, "Not uploaded", count=1)
        self.assertTrue(response.context["has_supplementals"])
        self.assertEqual(response.context["supplemental_slots"][1]["file"], supplemental)
