from django.db import migrations


def rebuild_wireless_cap_maps(apps, schema_editor):
    """Refresh wireless CAP data to drop legacy global grouping."""

    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    for project in Project.objects.iterator():
        cap_payload = project.cap if isinstance(project.cap, dict) else {}
        wireless_section = cap_payload.get("wireless") if isinstance(cap_payload, dict) else None

        needs_refresh = False
        if isinstance(wireless_section, dict):
            wireless_map = wireless_section.get("wireless_cap_map")
            if isinstance(wireless_map, dict) and "global" in wireless_map:
                needs_refresh = True

        if not needs_refresh:
            continue

        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0078_backfill_missing_wireless_cap_map"),
    ]

    operations = [
        migrations.RunPython(rebuild_wireless_cap_maps, migrations.RunPython.noop),
    ]
