from django.db import migrations


def rebuild_firewall_cap(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")

    for project in Project.objects.iterator():
        project.rebuild_data_artifacts()


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0081_update_web_cap_map"),
    ]

    operations = [
        migrations.RunPython(rebuild_firewall_cap, migrations.RunPython.noop),
    ]
