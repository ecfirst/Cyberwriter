from django.db import migrations


def refresh_nexpose_cap_scores(apps, schema_editor):
    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    queryset = (
        Project.objects.filter(data_files__requirement_label__iexact="nexpose_cap.csv")
        .distinct()
        .iterator()
    )

    for project in queryset:
        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0083_populate_nexpose_cap_map"),
    ]

    operations = [
        migrations.RunPython(refresh_nexpose_cap_scores, migrations.RunPython.noop),
    ]
