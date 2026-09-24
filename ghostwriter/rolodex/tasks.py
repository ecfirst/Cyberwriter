"""This contains tasks to be run using Django Q and Redis."""

# Standard Libraries
import datetime
import logging
from datetime import date
from typing import Any, Dict

# 3rd Party Libraries
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

# Ghostwriter Libraries
from ghostwriter.modules.notifications_slack import SlackNotification
from ghostwriter.rolodex.data_parsers import (
    NEXPOSE_METRICS_KEY_MAP,
    NEXPOSE_METRICS_LABELS,
    NEXPOSE_XML_ARTIFACT_MAP,
)
from ghostwriter.rolodex.models import Project, ProjectDataFile

# Using __name__ resolves to ghostwriter.rolodex.tasks
logger = logging.getLogger(__name__)

channel_layer = get_channel_layer()


def check_project_freshness():
    """Checks all entries in :model:`rolodex.Project` for incomplete projects that are overdue."""
    slack = SlackNotification()
    project_queryset = Project.objects.filter(complete=False)
    for project in project_queryset:
        nag_date = project.end_date + datetime.timedelta(1)
        # Check if date is before or is the end date
        if date.today() >= nag_date:
            message = "{} : This project should now be complete but is not marked as such in CyberWriter. Extend the end date or mark the project and check that all reports have been marked as completed and delivered.".format(
                project
            )
            if slack.enabled:
                if project.slack_channel:
                    err = slack.send_msg(message, project.slack_channel)
                else:
                    err = slack.send_msg(message)
                if err:
                    logger.warning(
                        "Attempt to send a Slack notification returned an error: %s",
                        err,
                    )


def _notify_user(username: str, *, title: str, message: str, level: str, **extra) -> None:
    """Push a toast to every one of ``username``'s open tabs over WebSockets.

    ``username`` must be the hex-encoded form (``User.get_clean_username()``)
    -- that's what ``UserConsumer.connect()`` (home/consumers.py) groups on,
    and what ``base_generic.html`` subscribes to as ``ws_user``. Any keys in
    ``extra`` ride along in the message payload; the generic toast handler
    in base templates reads only message/level/title and ignores the rest,
    so project_detail.html can key off e.g. "event"/"project_id" without
    touching that shared handler.
    """
    async_to_sync(channel_layer.group_send)(
        "notify_{}".format(username),
        {
            "type": "message",
            "message": {"message": message, "level": level, "title": title, **extra},
        },
    )


def process_project_data_upload(
    project_id: int,
    data_file_id: int,
    upload_field: str,
    area_key: str,
    username: str,
) -> Dict[str, Any]:
    """Parse an uploaded project data file and rebuild the project's derived artifacts.

    Runs off the request/response cycle (queued via ``async_task`` from
    ``ProjectWorkbookDataUpdate.post``, rolodex/views.py) specifically for
    the Nexpose XML upload fields, whose scans can run to hundreds of MB and
    hundreds of thousands of findings -- parsing that synchronously risks
    nginx's ``proxy_read_timeout`` and uvicorn's worker healthcheck killing
    the request mid-response (see NEXPOSE_AGGREGATE_SCHEMA_VERSION in
    data_parsers.py for the storage side of that same problem). Named
    generically, not "nexpose"-specific, since firewall/burp XML uploads
    share the same risk profile and could reuse this task later.

    Always ends by notifying ``username`` over WebSockets (success, empty
    result, or failure) -- there's no synchronous HTTP response left to
    report any of that through.
    """

    label = NEXPOSE_METRICS_LABELS.get(
        NEXPOSE_METRICS_KEY_MAP.get(
            NEXPOSE_XML_ARTIFACT_MAP.get(upload_field.replace("_nexpose_xml", ""), "")
        ),
        upload_field.replace("_", " ").title(),
    )

    try:
        project = Project.objects.get(pk=project_id)
    except Project.DoesNotExist:
        logger.error("Project ID=%s no longer exists; dropping queued upload for %s", project_id, upload_field)
        return {"status": "error", "reason": "project_missing"}

    try:
        data_file = ProjectDataFile.objects.get(pk=data_file_id, project=project)
    except ProjectDataFile.DoesNotExist:
        logger.error(
            "ProjectDataFile ID=%s no longer exists for project ID=%s; dropping queued upload for %s",
            data_file_id,
            project_id,
            upload_field,
        )
        _notify_user(
            username,
            title=f"{label} Upload Failed",
            message="The uploaded file could not be found. Please try uploading it again.",
            level="error",
            event="workbook_upload_complete",
            project_id=project_id,
            upload_field=upload_field,
            area_key=area_key,
            status="error",
        )
        return {"status": "error", "reason": "data_file_missing"}

    try:
        project.rebuild_data_artifacts(changed_file_ids={data_file.pk})
        project.refresh_from_db(fields=["workbook_data", "data_artifacts"])
    except Exception:
        logger.exception(
            "Failed to process uploaded Nexpose XML for project ID=%s, upload_field=%s",
            project_id,
            upload_field,
        )
        _notify_user(
            username,
            title=f"{label} Upload Failed",
            message=f"Something went wrong while processing {data_file.filename}. Check the server logs for details.",
            level="error",
            event="workbook_upload_complete",
            project_id=project_id,
            upload_field=upload_field,
            area_key=area_key,
            status="error",
        )
        return {"status": "error", "reason": "processing_failed"}
    finally:
        # Clear the "Processing..." marker regardless of outcome, so a
        # failure doesn't leave the upload card stuck.
        artifacts = project.data_artifacts if isinstance(project.data_artifacts, dict) else {}
        processing = artifacts.get("processing_uploads")
        if isinstance(processing, dict) and upload_field in processing:
            artifacts = dict(artifacts)
            processing = dict(processing)
            processing.pop(upload_field, None)
            if processing:
                artifacts["processing_uploads"] = processing
            else:
                artifacts.pop("processing_uploads", None)
            project.data_artifacts = artifacts
            project.save(update_fields=["data_artifacts"])

    metrics_key = NEXPOSE_METRICS_KEY_MAP.get(
        NEXPOSE_XML_ARTIFACT_MAP.get(upload_field.replace("_nexpose_xml", ""), "")
    )
    artifacts = project.data_artifacts if isinstance(project.data_artifacts, dict) else {}
    metrics_payload = artifacts.get(metrics_key) if metrics_key else None
    total_findings = 0
    if isinstance(metrics_payload, dict):
        summary = metrics_payload.get("summary")
        if isinstance(summary, dict):
            total_findings = summary.get("total") or 0

    if total_findings:
        _notify_user(
            username,
            title=f"{label} Processed",
            message=f"{data_file.filename} processed successfully ({total_findings} findings).",
            level="success",
            event="workbook_upload_complete",
            project_id=project_id,
            upload_field=upload_field,
            area_key=area_key,
            status="success",
        )
    else:
        # parse_nexpose_xml_report (data_parsers.py) swallows malformed XML
        # and simply returns no findings -- this is the only place that can
        # surface that to the user, since there's no synchronous response
        # left to return a 400 through.
        _notify_user(
            username,
            title=f"{label} Upload Complete",
            message=(
                f"No findings could be read from {data_file.filename}. "
                "It may not be a valid Nexpose XML export."
            ),
            level="warning",
            event="workbook_upload_complete",
            project_id=project_id,
            upload_field=upload_field,
            area_key=area_key,
            status="success",
        )

    return {"status": "success", "total_findings": total_findings}
