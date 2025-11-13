from django.db import migrations


def drop_cap_maps(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    for project in Project.objects.exclude(data_artifacts__isnull=True):
        artifacts = project.data_artifacts
        if not isinstance(artifacts, dict):
            continue
        updated = dict(artifacts)
        changed = False
        for key in ("web_cap_map", "web_cap_entries", "nexpose_cap_map"):
            if key in updated:
                updated.pop(key, None)
                changed = True
        if changed:
            project.data_artifacts = updated
            project.save(update_fields=["data_artifacts"])


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0084_update_nexpose_cap_scores"),
    ]

    operations = [
        migrations.RunPython(drop_cap_maps, migrations.RunPython.noop),
    ]
