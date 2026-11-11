"""Views for the project-less Scan Processing page.

State lives in the cache under a per-session token (see ``rolodex/scan_processing.py``);
no view here touches the database beyond the matrix lookups the parsers make.
"""

# Standard Libraries
import logging
from typing import Any, Dict, List, Optional

# Django Imports
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.generic import View

# 3rd Party Libraries
from django_q.tasks import async_task

# Ghostwriter Libraries
from ghostwriter.modules.shared import add_content_disposition_header
from ghostwriter.rolodex import scan_processing as store
from ghostwriter.rolodex.data_parsers import (
    summarize_nexpose_matrix_gaps,
    summarize_web_issue_matrix_gaps,
)
from ghostwriter.rolodex.forms_workbook import ScanProcessingUploadForm
from ghostwriter.rolodex.views import render_nexpose_missing_csv, render_web_issue_missing_csv

logger = logging.getLogger(__name__)

XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

# Read-only workbook fields shown on the Nexpose card, with the labels the project
# workbook modal uses (project_detail.html, areaSubsectionConfig.external_nexpose). The
# analyst-only "Sub-Count" fields are never derived from a scan, so they are omitted.
NEXPOSE_FIELDS = (
    ("total", "Total Count"),
    ("total_high", "Total High"),
    ("total_med", "Total Medium"),
    ("total_low", "Total Low"),
    ("unique", "Unique Count"),
    ("unique_high_med", "Unique High/Medium"),
    ("majority_type", "Majority Vulnerability Type"),
    ("unique_majority", "Unique Majority Vulnerability Count"),
    ("minority_type", "Second-majority Vulnerability Type"),
    ("unique_minority", "Second-majority Vulnerability Count"),
)

WEB_COMBINED_FIELDS = (
    ("combined_unique", "Unique Combined Total"),
    ("combined_unique_high", "Unique Combined High"),
    ("combined_unique_med", "Unique Combined Medium"),
    ("combined_unique_low", "Unique Combined Low"),
)


def _build_state(token: str) -> Dict[str, Any]:
    artifacts, workbook = store.build_artifacts_view(token)
    return {"workbook_data": workbook, "data_artifacts": artifacts, "token": token}


def _field_rows(section: Dict[str, Any], fields) -> List[Dict[str, Any]]:
    return [
        {"key": key, "label": label, "value": section.get(key)} for key, label in fields
    ]


def _summary_of(metrics: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(metrics, dict):
        return None
    summary = metrics.get("summary")
    return summary if isinstance(summary, dict) else None


def build_page_context(token: str) -> Dict[str, Any]:
    """Build the template context for the page (no workbook bytes)."""
    artifacts, workbook = store.build_artifacts_view(token)
    processing = artifacts.get("processing_uploads") or {}
    errors = artifacts.get("scan_processing_errors") or {}

    nexpose_metrics = artifacts.get(store.NEXPOSE_METRICS_KEY)
    nexpose_processing = processing.get(store.UPLOAD_FIELD_NEXPOSE)
    nexpose = {
        "slot": store.SLOT_NEXPOSE,
        "upload_field": store.UPLOAD_FIELD_NEXPOSE,
        "has_result": isinstance(nexpose_metrics, dict),
        "file_name": artifacts.get(store.NEXPOSE_FILE_NAME_KEY) or "",
        "processing": bool(nexpose_processing),
        "processing_filename": (nexpose_processing or {}).get("filename") or "",
        "error": errors.get(store.UPLOAD_FIELD_NEXPOSE) or "",
        "fields": _field_rows(workbook.get("external_nexpose") or {}, NEXPOSE_FIELDS),
        "summary": _summary_of(nexpose_metrics),
        "has_file": bool(isinstance(nexpose_metrics, dict) and nexpose_metrics.get("xlsx")),
        "missing_entries": summarize_nexpose_matrix_gaps(artifacts).get(
            store.NEXPOSE_ARTIFACT_KEY, []
        ),
    }

    web_metrics = artifacts.get(store.WEB_METRICS_KEY)
    web_section = workbook.get("web") or {}
    web = {
        "slot": store.SLOT_WEB,
        "upload_field": store.UPLOAD_FIELD_BURP,
        "has_result": isinstance(web_metrics, dict),
        "file_name": artifacts.get(store.WEB_FILE_NAME_KEY) or "",
        "processing": False,
        "error": errors.get(store.UPLOAD_FIELD_BURP) or "",
        "sites": web_section.get("sites") or [],
        "combined": _field_rows(web_section, WEB_COMBINED_FIELDS),
        "summary": _summary_of(web_metrics),
        "has_file": bool(isinstance(web_metrics, dict) and web_metrics.get("xlsx")),
        "missing_entries": summarize_web_issue_matrix_gaps(artifacts),
    }

    urls = {
        "page": reverse("rolodex:scan_processing"),
        "upload": reverse("rolodex:ajax_upload_scan_processing_file"),
        "state": reverse("rolodex:ajax_scan_processing_state"),
        "clear": reverse("rolodex:ajax_clear_scan_processing"),
        "remove_nexpose": reverse(
            "rolodex:ajax_remove_scan_processing_result", kwargs={"slot": store.SLOT_NEXPOSE}
        ),
        "remove_web": reverse(
            "rolodex:ajax_remove_scan_processing_result", kwargs={"slot": store.SLOT_WEB}
        ),
        "nexpose_download": reverse("rolodex:scan_processing_nexpose_data_download"),
        "web_download": reverse("rolodex:scan_processing_web_data_download"),
        "nexpose_missing_download": reverse(
            "rolodex:scan_processing_nexpose_missing_download"
        ),
        "web_missing_download": reverse("rolodex:scan_processing_web_issue_missing_download"),
    }

    return {
        "scan_processing": {
            "token": token,
            "nexpose": nexpose,
            "web": web,
            "any_processing": nexpose["processing"],
        },
        "scan_processing_urls": urls,
    }


def _first_form_error(form: ScanProcessingUploadForm) -> str:
    for errors in form.errors.values():
        for error in errors:
            return str(error)
    return "The upload could not be processed."


class ScanProcessingPage(LoginRequiredMixin, View):
    """Render the Scan Processing page from the caller's cached workspace."""

    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        return render(request, "rolodex/scan_processing.html", build_page_context(token))


class ScanProcessingState(LoginRequiredMixin, View):
    """Return the current workspace state as JSON (used by the page's polling fallback)."""

    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        return JsonResponse(_build_state(token))


class ScanProcessingUpload(LoginRequiredMixin, View):
    """Accept a Nexpose XML (queued) or Burp XML (processed inline) upload."""

    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        form = ScanProcessingUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            return JsonResponse({"error": _first_form_error(form)}, status=400)

        upload_field = form.cleaned_data["upload_field"]
        upload = form.cleaned_data["file"]
        if upload_field == store.UPLOAD_FIELD_NEXPOSE:
            return self._queue_nexpose(request, token, upload)
        return self._process_burp(token, upload)

    def _queue_nexpose(self, request, token: str, upload) -> JsonResponse:
        if store.get_processing_uploads(token).get(store.UPLOAD_FIELD_NEXPOSE):
            return JsonResponse(
                {"error": "A Nexpose XML is already being processed. Wait for it to finish."},
                status=409,
            )

        store.cleanup_stale_uploads()
        store.delete_result(token, store.SLOT_NEXPOSE)
        storage_path = store.save_temp_upload(upload)
        # Mark processing *before* queueing: the worker can start (and finish, in
        # sync mode) before async_task returns, and it clears this marker itself.
        store.set_processing(token, store.SLOT_NEXPOSE, filename=upload.name)
        try:
            task_id = async_task(
                "ghostwriter.rolodex.tasks.process_scan_processing_upload",
                token=token,
                username=request.user.get_clean_username(),
                upload_field=store.UPLOAD_FIELD_NEXPOSE,
                storage_path=storage_path,
                original_filename=upload.name,
                group="Scan Processing",
            )
        except Exception:
            logger.exception("Failed to queue Scan Processing upload %s", upload.name)
            store.delete_temp_upload(storage_path)
            store.clear_processing(token, store.SLOT_NEXPOSE)
            return JsonResponse(
                {"error": "The upload could not be queued for processing. Try again."},
                status=503,
            )

        return JsonResponse(
            {
                "queued": True,
                "task_id": task_id,
                "upload_field": store.UPLOAD_FIELD_NEXPOSE,
                "message": "Upload received. Processing in the background…",
            },
            status=202,
        )

    def _process_burp(self, token: str, upload) -> JsonResponse:
        try:
            payload, xlsx_bytes = store.process_burp_upload(upload)
        except Exception:
            logger.exception("Failed to process Scan Processing Burp upload %s", upload.name)
            return JsonResponse(
                {
                    "error": (
                        f"Something went wrong while processing {upload.name}. "
                        "Check the server logs for details."
                    )
                },
                status=500,
            )

        payload["file_name"] = upload.name
        payload["processed_at"] = timezone.now().isoformat()
        if not store.write_result(token, store.SLOT_WEB, payload, xlsx_bytes):
            return JsonResponse(
                {"error": "The results could not be stored. Try again in a moment."},
                status=503,
            )

        data = _build_state(token)
        total = payload.get("total_findings") or 0
        if total:
            data["message"] = f"{upload.name} processed successfully ({total} findings)."
        else:
            data["warning"] = (
                f"No findings could be read from {upload.name}. "
                "It may not be a valid Burp XML export."
            )
        return JsonResponse(data)


class ScanProcessingRemove(LoginRequiredMixin, View):
    """Discard one slot's cached result and workbook."""

    http_method_names = ["post"]

    def post(self, request, slot: str, *args, **kwargs):
        if slot not in store.SLOTS:
            return JsonResponse({"error": "Unknown data type."}, status=400)
        token = store.get_or_create_token(request)
        upload_field = store.SLOT_UPLOAD_FIELDS[slot]
        if store.get_processing_uploads(token).get(upload_field):
            return JsonResponse(
                {"error": "That upload is still being processed. Wait for it to finish."},
                status=409,
            )
        store.delete_result(token, slot)
        return JsonResponse(_build_state(token))


class ScanProcessingClear(LoginRequiredMixin, View):
    """Discard everything in the workspace and start a fresh one."""

    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        token = store.clear_workspace(request)
        return JsonResponse(_build_state(token))


class _ScanProcessingDownload(LoginRequiredMixin, View):
    """Shared plumbing for the XLSX and CSV downloads."""

    def redirect_with_error(self, request, message: str) -> HttpResponseRedirect:
        messages.error(request, message)
        return HttpResponseRedirect(reverse("rolodex:scan_processing"))


class ScanProcessingNexposeDataDownload(_ScanProcessingDownload):
    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        workbook_bytes = store.read_xlsx(token, store.SLOT_NEXPOSE)
        if not workbook_bytes:
            return self.redirect_with_error(request, "No Nexpose data file is available.")
        result = store.read_result(token, store.SLOT_NEXPOSE) or {}
        metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
        filename = metrics.get("xlsx_filename") or store.NEXPOSE_DEFAULT_XLSX_FILENAME
        response = HttpResponse(workbook_bytes, content_type=XLSX_CONTENT_TYPE)
        add_content_disposition_header(response, filename)
        return response


class ScanProcessingWebDataDownload(_ScanProcessingDownload):
    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        workbook_bytes = store.read_xlsx(token, store.SLOT_WEB)
        if not workbook_bytes:
            return self.redirect_with_error(request, "No Web data file is available.")
        result = store.read_result(token, store.SLOT_WEB) or {}
        metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
        filename = metrics.get("xlsx_filename") or store.WEB_DEFAULT_XLSX_FILENAME
        response = HttpResponse(workbook_bytes, content_type=XLSX_CONTENT_TYPE)
        add_content_disposition_header(response, filename)
        return response


class ScanProcessingNexposeMissingDownload(_ScanProcessingDownload):
    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        artifacts, _workbook = store.build_artifacts_view(token)
        entries = summarize_nexpose_matrix_gaps(artifacts).get(store.NEXPOSE_ARTIFACT_KEY)
        if not entries:
            return self.redirect_with_error(
                request, "No missing Nexpose matrix entries are available for download."
            )
        response = HttpResponse(render_nexpose_missing_csv(entries), content_type="text/csv")
        add_content_disposition_header(response, "nexpose-missing.csv")
        return response


class ScanProcessingWebIssueMissingDownload(_ScanProcessingDownload):
    def get(self, request, *args, **kwargs):
        token = store.get_or_create_token(request)
        artifacts, _workbook = store.build_artifacts_view(token)
        entries = summarize_web_issue_matrix_gaps(artifacts)
        if not entries:
            return self.redirect_with_error(
                request, "No missing Web issues are available for download."
            )
        response = HttpResponse(render_web_issue_missing_csv(entries), content_type="text/csv")
        add_content_disposition_header(response, "burp-missing.csv")
        return response
