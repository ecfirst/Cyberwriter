from django.db import migrations


GLOBAL_BADPASS_KEYS = (
    "Additional password controls not implemented",
    "MFA not enforced for all accounts",
)


def ensure_global_badpass_entries(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    for project in Project.objects.iterator():
        cap_payload = project.cap if isinstance(project.cap, dict) else {}
        password_section = cap_payload.get("password")
        if not isinstance(password_section, dict):
            continue
        badpass_map = password_section.get("badpass_cap_map")
        if not isinstance(badpass_map, dict):
            continue

        new_cap_payload = dict(cap_payload)
        new_password_section = dict(password_section)
        new_badpass_map = dict(badpass_map)

        global_entries = new_badpass_map.get("global")
        if isinstance(global_entries, dict):
            global_entries = dict(global_entries)
        else:
            global_entries = {}

        changed = False
        for key in GLOBAL_BADPASS_KEYS:
            entry = new_badpass_map.get(key)
            if isinstance(entry, dict):
                global_entries[key] = entry
                new_badpass_map.pop(key, None)
                changed = True

        if global_entries:
            if new_badpass_map.get("global") != global_entries:
                new_badpass_map["global"] = global_entries
                changed = True
        else:
            if "global" in new_badpass_map:
                new_badpass_map.pop("global")
                changed = True

        if not changed:
            continue

        new_password_section["badpass_cap_map"] = new_badpass_map
        new_cap_payload["password"] = new_password_section
        project.cap = new_cap_payload
        project.save(update_fields=["cap"])


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0086_ensure_nexpose_distilled_flag"),
    ]

    operations = [
        migrations.RunPython(ensure_global_badpass_entries, migrations.RunPython.noop),
    ]
