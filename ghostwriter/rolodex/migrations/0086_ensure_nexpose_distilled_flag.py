from django.db import migrations


TRUTHY_VALUES = {"true", "1", "yes", "y"}


def normalize_bool(value):
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        return text.lower() in TRUTHY_VALUES
    if isinstance(value, (int, float)):
        return bool(value)
    return bool(value)


def ensure_nexpose_distilled_flag(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    for project in Project.objects.iterator():
        original_cap = project.cap if isinstance(project.cap, dict) else {}
        cap_payload = dict(original_cap)
        nexpose_section = cap_payload.get("nexpose")
        if isinstance(nexpose_section, dict):
            nexpose_section = dict(nexpose_section)
        else:
            nexpose_section = {}

        normalized_distilled = normalize_bool(nexpose_section.get("distilled"))
        if nexpose_section.get("distilled") != normalized_distilled:
            nexpose_section["distilled"] = normalized_distilled

        if cap_payload.get("nexpose") != nexpose_section:
            cap_payload["nexpose"] = nexpose_section

        if cap_payload != original_cap:
            project.cap = cap_payload
            project.save(update_fields=["cap"])


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0085_remove_cap_maps_from_artifacts"),
    ]

    operations = [
        migrations.RunPython(ensure_nexpose_distilled_flag, migrations.RunPython.noop),
    ]
