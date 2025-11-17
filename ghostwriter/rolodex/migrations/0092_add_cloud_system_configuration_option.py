from django.db import migrations


def enable_cloud_system_configuration(apps, schema_editor):  # pragma: no cover - data migration
    Project = apps.get_model("rolodex", "Project")

    queryset = Project.objects.exclude(scoping__isnull=True)
    for project in queryset.iterator():
        scoping_payload = project.scoping
        if not isinstance(scoping_payload, dict):
            continue
        cloud_payload = scoping_payload.get("cloud")
        if not isinstance(cloud_payload, dict):
            continue
        if not cloud_payload.get("selected"):
            continue
        if cloud_payload.get("system_configuration"):
            continue

        cloud_payload["system_configuration"] = True
        project.scoping = scoping_payload
        project.save(update_fields=["scoping"])


class Migration(migrations.Migration):
    dependencies = [
        ("rolodex", "0091_add_generic_login_general_cap_map"),
    ]

    operations = [
        migrations.RunPython(enable_cloud_system_configuration, migrations.RunPython.noop),
    ]
