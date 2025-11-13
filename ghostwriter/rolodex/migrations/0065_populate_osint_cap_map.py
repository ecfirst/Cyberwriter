from django.db import migrations

from ghostwriter.rolodex.data_parsers import DEFAULT_GENERAL_CAP_MAP


def _default_general_cap_map():
    return {
        issue: {"recommendation": recommendation, "score": score}
        for issue, (recommendation, score) in DEFAULT_GENERAL_CAP_MAP.items()
    }


def _safe_int(value):
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(float(text))
        except ValueError:
            return 0
    return 0


def _clone_entry(mapping, issue):
    entry = mapping.get(issue)
    if not isinstance(entry, dict):
        return None
    payload = {}
    if "recommendation" in entry and entry["recommendation"] is not None:
        payload["recommendation"] = entry["recommendation"]
    if "score" in entry and entry["score"] is not None:
        payload["score"] = entry["score"]
    return payload or None


def populate_osint_cap_map(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    GeneralCapMapping = apps.get_model("rolodex", "GeneralCapMapping")

    general_cap_map = {}
    for entry in GeneralCapMapping.objects.all().values(
        "issue_text", "recommendation_text", "score"
    ):
        issue = entry.get("issue_text")
        if not issue:
            continue
        general_cap_map[issue] = {
            "recommendation": entry.get("recommendation_text"),
            "score": entry.get("score"),
        }

    if not general_cap_map:
        general_cap_map = _default_general_cap_map()

    for project in Project.objects.all():
        workbook_data = project.workbook_data
        if not isinstance(workbook_data, dict):
            continue
        osint_data = workbook_data.get("osint")
        if not isinstance(osint_data, dict):
            continue

        osint_cap_map = {}
        total_assets = (
            _safe_int(osint_data.get("total_ips"))
            + _safe_int(osint_data.get("total_domains"))
            + _safe_int(osint_data.get("total_hostnames"))
        )
        if total_assets >= 2:
            entry = _clone_entry(general_cap_map, "OSINT identified assets")
            if entry:
                osint_cap_map["OSINT identified assets"] = entry

        if _safe_int(osint_data.get("total_buckets")) > 0:
            entry = _clone_entry(general_cap_map, "Exposed buckets identified")
            if entry:
                osint_cap_map["Exposed buckets identified"] = entry

        if _safe_int(osint_data.get("total_leaks")) > 0:
            entry = _clone_entry(general_cap_map, "Exposed Credentials identified")
            if entry:
                osint_cap_map["Exposed Credentials identified"] = entry

        if _safe_int(osint_data.get("total_squat")) > 0:
            entry = _clone_entry(
                general_cap_map, "Potential domain squatters identified"
            )
            if entry:
                osint_cap_map["Potential domain squatters identified"] = entry

        original_cap = project.cap or {}
        if not osint_cap_map and "osint" not in original_cap:
            continue

        cap_payload = dict(original_cap)
        osint_section = cap_payload.get("osint")
        if isinstance(osint_section, dict):
            osint_section = dict(osint_section)
        else:
            osint_section = {}

        if osint_cap_map:
            osint_section["osint_cap_map"] = osint_cap_map
        else:
            osint_section.pop("osint_cap_map", None)

        if osint_section:
            cap_payload["osint"] = osint_section
        else:
            cap_payload.pop("osint", None)

        if cap_payload != original_cap:
            project.cap = cap_payload
            project.save(update_fields=["cap"])


class Migration(migrations.Migration):
    dependencies = [
        ("rolodex", "0064_migrate_project_cap"),
    ]

    operations = [
        migrations.RunPython(populate_osint_cap_map, migrations.RunPython.noop),
    ]
