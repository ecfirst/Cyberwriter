from django.db import migrations


def rebuild_project_cap(apps, schema_editor):
    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    for project in Project.objects.iterator():
        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0070_update_badpass_cap_map_entries"),
    ]

    operations = [
        migrations.RunPython(rebuild_project_cap, migrations.RunPython.noop),
    ]
