from django.db import migrations


def rename_web_cap_entries(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")

    for project in Project.objects.iterator():
        update_fields = []

        artifacts = project.data_artifacts
        if isinstance(artifacts, dict) and "web_cap_entries" in artifacts:
            new_artifacts = dict(artifacts)
            entries = new_artifacts.pop("web_cap_entries", None)
            if entries:
                new_artifacts["web_cap_map"] = entries
            else:
                new_artifacts.pop("web_cap_map", None)
            project.data_artifacts = new_artifacts
            update_fields.append("data_artifacts")

        cap_payload = project.cap
        if isinstance(cap_payload, dict):
            web_section = cap_payload.get("web")
        else:
            web_section = None
        if isinstance(web_section, dict) and "web_cap_entries" in web_section:
            new_cap = dict(cap_payload)
            new_web_section = dict(web_section)
            entries = new_web_section.pop("web_cap_entries", None)
            if entries:
                new_web_section["web_cap_map"] = entries
            else:
                new_web_section.pop("web_cap_map", None)
            new_cap["web"] = new_web_section
            project.cap = new_cap
            update_fields.append("cap")

        responses = project.data_responses
        if isinstance(responses, dict):
            web_response = responses.get("web")
        else:
            web_response = None
        if isinstance(web_response, dict) and (
            "web_cap_entries" in web_response or "web_cap_map" in web_response
        ):
            new_responses = dict(responses)
            new_web_response = dict(web_response)
            new_web_response.pop("web_cap_entries", None)
            new_web_response.pop("web_cap_map", None)
            new_responses["web"] = new_web_response
            project.data_responses = new_responses
            update_fields.append("data_responses")

        if update_fields:
            project.save(update_fields=sorted(set(update_fields)))


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0080_populate_web_cap_entries"),
    ]

    operations = [
        migrations.RunPython(rename_web_cap_entries, migrations.RunPython.noop),
    ]
