"""
Views for uploading, downloading, and deleting the supplemental workbooks
(:model:`reporting.ReportSupplementalFile`) attached to a :model:`reporting.Report`.
"""

# Standard Libraries
import logging
import os

# Django Imports
from django.contrib import messages
from django.db import IntegrityError, transaction
from django.http import FileResponse, Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import View
from django.views.generic.detail import SingleObjectMixin

# Ghostwriter Libraries
from ghostwriter.api.utils import RoleBasedAccessControlMixin
from ghostwriter.reporting.forms import ReportSupplementalUploadForm
from ghostwriter.reporting.models import Report, ReportSupplementalFile
from ghostwriter.reporting.supplemental_parsers import (
    SupplementalParseError,
    parse_supplemental,
)

logger = logging.getLogger(__name__)

# Number of parser warnings echoed back to the user after an upload
MAX_WARNINGS_IN_MESSAGE = 5


def _supplementals_url(report_pk) -> str:
    return reverse("reporting:report_detail", kwargs={"pk": report_pk}) + "#supplementals"


def _remove_file(path: str) -> None:
    """Best-effort removal of a replaced supplemental file from storage."""
    if path and os.path.isfile(path):
        try:
            os.remove(path)
            logger.info("Deleted replaced supplemental file at %s", path)
        except Exception:  # pragma: no cover
            logger.warning("Failed to delete replaced supplemental file at %s", path)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


class ReportSupplementalUpload(RoleBasedAccessControlMixin, SingleObjectMixin, View):
    """
    Upload (or replace) the supplemental workbook for one slot of an individual
    :model:`reporting.Report`. The workbook is parsed before anything is saved so that
    a bad file never displaces a good one.
    """

    model = Report
    http_method_names = ["post"]

    def test_func(self):
        return self.get_object().user_can_edit(self.request.user)

    def handle_no_permission(self):
        messages.error(self.request, "You do not have permission to access that.")
        return redirect("home:dashboard")

    def post(self, request, *args, **kwargs):
        report = self.get_object()
        redirect_url = _supplementals_url(report.pk)

        form = ReportSupplementalUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            errors = "; ".join(
                error if field == "__all__" else f"{field}: {error}"
                for field, field_errors in form.errors.items()
                for error in field_errors
            )
            messages.error(
                request, f"Could not upload the file: {errors}", extra_tags="alert-danger"
            )
            return redirect(redirect_url)

        kind = form.cleaned_data["kind"]
        upload = form.cleaned_data["document"]
        label = ReportSupplementalFile.Kind(kind).label

        data = upload.read()
        upload.seek(0)
        try:
            result = parse_supplemental(kind, data)
        except SupplementalParseError as error:
            messages.error(
                request,
                f"Could not parse the {label} workbook: {error}",
                extra_tags="alert-danger",
            )
            return redirect(redirect_url)

        try:
            with transaction.atomic():
                obj, _ = ReportSupplementalFile.objects.select_for_update().get_or_create(
                    report=report, kind=kind
                )
                old_path = obj.document.path if obj.document else None
                obj.document = upload
                obj.original_filename = upload.name[:255]
                obj.uploaded_by = request.user
                obj.cap_entries = result.entries
                obj.row_count = len(result.entries)
                obj.parse_warnings = result.warnings
                obj.save()
                if old_path and old_path != obj.document.path:
                    transaction.on_commit(lambda: _remove_file(old_path))
        except IntegrityError:
            logger.exception(
                "Concurrent supplemental upload collided for report %s, kind %s",
                report.pk,
                kind,
            )
            messages.error(
                request,
                "Another upload for this slot was in progress. Please try again.",
                extra_tags="alert-danger",
            )
            return redirect(redirect_url)

        logger.info(
            "Uploaded %s supplemental workbook for report %s by request of %s (%s rows)",
            kind,
            report.pk,
            request.user,
            obj.row_count,
        )
        messages.success(
            request,
            f"Uploaded the {label} workbook: {_plural(obj.row_count, 'CAP row')}.",
            extra_tags="alert-success",
        )
        if result.warnings:
            shown = result.warnings[:MAX_WARNINGS_IN_MESSAGE]
            remaining = len(result.warnings) - len(shown)
            text = "; ".join(shown)
            if remaining:
                text += f"; and {_plural(remaining, 'more')}"
            messages.warning(
                request,
                f"{_plural(len(result.warnings), 'parser warning')}: {text}",
                extra_tags="alert-warning",
            )
        return redirect(redirect_url)


class ReportSupplementalDownload(RoleBasedAccessControlMixin, SingleObjectMixin, View):
    """Return the uploaded :model:`reporting.ReportSupplementalFile` workbook for download."""

    model = ReportSupplementalFile

    def test_func(self):
        return self.get_object().report.user_can_view(self.request.user)

    def handle_no_permission(self):
        messages.error(self.request, "You do not have permission to access that.")
        return redirect("home:dashboard")

    def get(self, *args, **kwargs):
        obj = self.get_object()
        file_path = obj.document.path if obj.document else ""
        if file_path and os.path.exists(file_path):
            return FileResponse(
                open(file_path, "rb"),
                as_attachment=True,
                filename=obj.original_filename or obj.filename,
            )
        raise Http404


class ReportSupplementalDelete(RoleBasedAccessControlMixin, SingleObjectMixin, View):
    """Delete an individual :model:`reporting.ReportSupplementalFile` and its file on disk."""

    model = ReportSupplementalFile
    http_method_names = ["post"]

    def test_func(self):
        return self.get_object().report.user_can_edit(self.request.user)

    def handle_no_permission(self):
        messages.error(self.request, "You do not have permission to access that.")
        return redirect("home:dashboard")

    def post(self, request, *args, **kwargs):
        obj = self.get_object()
        report_pk = obj.report_id
        label = obj.get_kind_display()
        obj.delete()
        logger.info(
            "Deleted %s supplemental workbook for report %s by request of %s",
            obj.kind,
            report_pk,
            request.user,
        )
        messages.success(
            request, f"Deleted the {label} supplemental file.", extra_tags="alert-success"
        )
        return redirect(_supplementals_url(report_pk))
