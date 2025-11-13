from django.db import migrations


def populate_nexpose_cap_map(apps, schema_editor):
    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    queryset = Project.objects.filter(
        data_files__requirement_label__iexact="nexpose_cap.csv"
    ).distinct()
    for project in queryset.iterator():
        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0082_move_firewall_findings_to_cap"),
    ]

    operations = [
        migrations.RunPython(populate_nexpose_cap_map, migrations.RunPython.noop),
    ]
