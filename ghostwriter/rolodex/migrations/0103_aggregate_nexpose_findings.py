import logging

from django.db import migrations

logger = logging.getLogger(__name__)

# Schema version this migration produces. Must match
# data_parsers.NEXPOSE_AGGREGATE_SCHEMA_VERSION forever, even if that
# constant's value changes in a later release -- a migration replayed on a
# fresh database years from now must still emit exactly this shape. That's
# why the aggregation logic below is a standalone copy of
# data_parsers._build_nexpose_metrics_payload's unique_issues/cap_systems
# computation and data_parsers._format_system_label, not an import of them.
_SCHEMA_VERSION = 2

# xml_artifact_key -> metrics_key, duplicated from
# data_parsers.NEXPOSE_METRICS_KEY_MAP for the same reason.
_FINDINGS_TO_METRICS_KEY = {
    "external_nexpose_findings": "external_nexpose_metrics",
    "internal_nexpose_findings": "internal_nexpose_metrics",
    "iot_iomt_nexpose_findings": "iot_iomt_nexpose_metrics",
}


def _coerce_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace(",", "")
    try:
        return int(normalized)
    except (TypeError, ValueError):
        try:
            return int(float(normalized))
        except (TypeError, ValueError):
            return None


def _format_system_label(finding):
    ip_address = (finding.get("Asset IP Address") or "").strip()
    hostnames = (finding.get("Hostname(s)") or "").strip()
    if ip_address:
        label = ip_address
        if hostnames:
            label = f"{label} [{hostnames}]"
    elif hostnames:
        label = hostnames
    else:
        return ""
    status_code = (finding.get("Vulnerability Test Result Code") or "").strip().upper()
    if status_code == "VP":
        label = f"{label} (P)"
    return label


def _derive_counts_and_cap_systems(findings):
    """Return (counts_by_unique_key, cap_systems_list) from a raw findings list.

    ``counts_by_unique_key`` is keyed exactly like
    data_parsers._build_nexpose_metrics_payload's ``unique_entries`` --
    ``(severity, title.lower())`` -- so callers can add a "count" to an
    *existing* stored ``unique_issues`` entry (preserving its other fields
    exactly as already stored) rather than reconstructing the list from
    scratch and risking a subtly different result.
    """

    counts = {}
    cap_systems = {}
    cap_systems_seen = {}

    for entry in findings or []:
        if not isinstance(entry, dict):
            continue
        title = (entry.get("Vulnerability Title") or entry.get("Vulnerability ID") or "").strip()
        if not title:
            title = "Untitled Vulnerability"
        severity = _coerce_int(entry.get("Vulnerability Severity Level")) or 0

        unique_key = (severity, title.lower())
        counts[unique_key] = counts.get(unique_key, 0) + 1

        cap_key = title.lower()
        cap_entry = cap_systems.get(cap_key)
        if cap_entry is None:
            cap_entry = {"key": cap_key, "title": title, "systems": []}
            cap_systems[cap_key] = cap_entry
            cap_systems_seen[cap_key] = set()
        system_label = _format_system_label(entry)
        if system_label and system_label not in cap_systems_seen[cap_key]:
            cap_systems_seen[cap_key].add(system_label)
            cap_entry["systems"].append(system_label)

    return counts, list(cap_systems.values())


def _migrate_project_artifacts(artifacts):
    """Return (new_artifacts, changed) for one project's data_artifacts dict."""

    if not isinstance(artifacts, dict):
        return artifacts, False

    changed = False
    new_artifacts = dict(artifacts)

    for findings_key, metrics_key in _FINDINGS_TO_METRICS_KEY.items():
        entry = new_artifacts.get(findings_key)
        if not isinstance(entry, dict):
            continue
        if entry.get("schema_version") == _SCHEMA_VERSION:
            continue  # already migrated
        findings = entry.get("findings")
        if not isinstance(findings, list):
            # Old shape but no findings list to derive from (e.g. already
            # partially cleaned up some other way) -- just stamp the
            # version and drop whatever's there beyond software.
            new_artifacts[findings_key] = {
                "schema_version": _SCHEMA_VERSION,
                "software": entry.get("software") if isinstance(entry.get("software"), list) else [],
            }
            changed = True
            continue

        counts, cap_systems = _derive_counts_and_cap_systems(findings)

        metrics_entry = new_artifacts.get(metrics_key)
        if isinstance(metrics_entry, dict):
            metrics_entry = dict(metrics_entry)
            unique_issues = metrics_entry.get("unique_issues")
            if isinstance(unique_issues, list):
                new_unique_issues = []
                for issue in unique_issues:
                    if not isinstance(issue, dict):
                        new_unique_issues.append(issue)
                        continue
                    issue = dict(issue)
                    key = (_coerce_int(issue.get("severity")) or 0, (issue.get("issue") or "").strip().lower())
                    issue["count"] = counts.get(key, issue.get("count") or 1)
                    new_unique_issues.append(issue)
                metrics_entry["unique_issues"] = new_unique_issues
            metrics_entry["cap_systems"] = cap_systems
            # The raw per-finding xlsx-building fields never belonged in
            # storage (dropped in rebuild_data_artifacts before this
            # migration existed) -- clear them defensively in case an older
            # row somehow still carries one.
            for stale_key in ("all_issues", "high_issues", "med_issues", "low_issues"):
                metrics_entry.pop(stale_key, None)
            new_artifacts[metrics_key] = metrics_entry

        new_artifacts[findings_key] = {
            "schema_version": _SCHEMA_VERSION,
            "software": entry.get("software") if isinstance(entry.get("software"), list) else [],
        }
        changed = True

    return new_artifacts, changed


def aggregate_nexpose_findings(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")

    updated = 0
    skipped = 0
    queryset = Project.objects.filter(data_artifacts__isnull=False).only("id", "data_artifacts")
    for project in queryset.iterator(chunk_size=5):
        artifacts = project.data_artifacts
        try:
            new_artifacts, changed = _migrate_project_artifacts(artifacts)
        except Exception:
            logger.exception(
                "Failed to migrate Nexpose data_artifacts for project ID=%s; leaving as-is",
                project.pk,
            )
            skipped += 1
            continue
        if changed:
            Project.objects.filter(pk=project.pk).update(data_artifacts=new_artifacts)
            updated += 1
        del artifacts, new_artifacts

    logger.info(
        "Nexpose data_artifacts aggregation migration complete: %s project(s) updated, %s skipped due to errors",
        updated,
        skipped,
    )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0102_projectartifactfile"),
    ]

    operations = [
        migrations.RunPython(aggregate_nexpose_findings, migrations.RunPython.noop),
    ]
