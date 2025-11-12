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
    entry = mapping.get(issue) if isinstance(mapping, dict) else None
    if not isinstance(entry, dict):
        return None
    payload = {}
    if "recommendation" in entry and entry["recommendation"] is not None:
        payload["recommendation"] = entry["recommendation"]
    if "score" in entry and entry["score"] is not None:
        payload["score"] = entry["score"]
    return payload or None


def populate_sql_snmp_cap_map(apps, schema_editor):
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

        original_cap = project.cap or {}
        cap_payload = dict(original_cap)
        changed = False

        sql_data = workbook_data.get("sql")
        sql_section = cap_payload.get("sql")
        if isinstance(sql_section, dict):
            sql_section = dict(sql_section)
        else:
            sql_section = {}

        sql_cap_map = {}
        if isinstance(sql_data, dict):
            if _safe_int(sql_data.get("total_open")) > 0:
                entry = _clone_entry(general_cap_map, "Databases allowing open access")
                if entry:
                    sql_cap_map["Databases allowing open access"] = entry

        if sql_cap_map:
            if sql_section.get("sql_cap_map") != sql_cap_map:
                changed = True
            sql_section["sql_cap_map"] = sql_cap_map
        else:
            if sql_section.pop("sql_cap_map", None) is not None:
                changed = True

        if sql_section:
            if cap_payload.get("sql") != sql_section:
                changed = True
            cap_payload["sql"] = sql_section
        else:
            if cap_payload.pop("sql", None) is not None:
                changed = True

        snmp_data = workbook_data.get("snmp")
        snmp_section = cap_payload.get("snmp")
        if isinstance(snmp_section, dict):
            snmp_section = dict(snmp_section)
        else:
            snmp_section = {}

        snmp_cap_map = {}
        if isinstance(snmp_data, dict):
            if _safe_int(snmp_data.get("total_strings")) > 0:
                entry = _clone_entry(
                    general_cap_map,
                    "Default SNMP community strings & default credentials in use",
                )
                if entry:
                    snmp_cap_map[
                        "Default SNMP community strings & default credentials in use"
                    ] = entry

        if snmp_cap_map:
            if snmp_section.get("snmp_cap_map") != snmp_cap_map:
                changed = True
            snmp_section["snmp_cap_map"] = snmp_cap_map
        else:
            if snmp_section.pop("snmp_cap_map", None) is not None:
                changed = True

        if snmp_section:
            if cap_payload.get("snmp") != snmp_section:
                changed = True
            cap_payload["snmp"] = snmp_section
        else:
            if cap_payload.pop("snmp", None) is not None:
                changed = True

        if changed and cap_payload != original_cap:
            project.cap = cap_payload
            project.save(update_fields=["cap"])


class Migration(migrations.Migration):
    dependencies = [
        ("rolodex", "0066_update_cap_map_scores"),
    ]

    operations = [
        migrations.RunPython(populate_sql_snmp_cap_map, migrations.RunPython.noop),
    ]
