from django.db import migrations


def populate_web_cap_entries(apps, schema_editor):
    """Generate web CAP entries for projects with uploaded burp CAP files."""

    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    for project in Project.objects.iterator():
        try:
            has_burp_cap = project.data_files.filter(
                requirement_label__iexact="burp_cap.csv"
            ).exists()
            if not has_burp_cap:
                has_burp_cap = project.data_files.filter(
                    requirement_label__iexact="burp-cap.csv"
                ).exists()
            if not has_burp_cap:
                continue
        except Exception:
            continue

        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0079_update_wireless_cap_structure"),
    ]

    operations = [
        migrations.RunPython(populate_web_cap_entries, migrations.RunPython.noop),
    ]
