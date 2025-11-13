from django.db import migrations


def backfill_wireless_cap(apps, schema_editor):
    """Populate missing wireless CAP entries for historical projects."""

    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    for project in Project.objects.iterator():
        cap_payload = project.cap if isinstance(project.cap, dict) else {}
        wireless_section = cap_payload.get("wireless")

        if isinstance(wireless_section, dict):
            if isinstance(wireless_section.get("wireless_cap_map"), dict) and wireless_section["wireless_cap_map"]:
                continue

        workbook_payload = getattr(project, "workbook_data", None)
        if not isinstance(workbook_payload, dict):
            continue

        wireless_data = workbook_payload.get("wireless")
        if not isinstance(wireless_data, dict):
            continue

        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0077_refresh_wireless_cap_map"),
    ]

    operations = [
        migrations.RunPython(backfill_wireless_cap, migrations.RunPython.noop),
    ]
