from django.db import migrations


def add_ai_response_placeholder(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    for project in Project.objects.all().only("pk", "data_artifacts"):
        artifacts = project.data_artifacts or {}
        if not isinstance(artifacts, dict):
            continue
        web_issues = artifacts.get("web_issues")
        if not isinstance(web_issues, dict):
            continue
        if "ai_response" in web_issues:
            continue
        web_issues["ai_response"] = None
        project.data_artifacts = artifacts
        project.save(update_fields=["data_artifacts"])


def remove_ai_response_placeholder(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    for project in Project.objects.all().only("pk", "data_artifacts"):
        artifacts = project.data_artifacts or {}
        if not isinstance(artifacts, dict):
            continue
        web_issues = artifacts.get("web_issues")
        if not isinstance(web_issues, dict):
            continue
        if "ai_response" not in web_issues:
            continue
        web_issues.pop("ai_response", None)
        project.data_artifacts = artifacts
        project.save(update_fields=["data_artifacts"])


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0088_populate_firewall_global_entries"),
    ]

    operations = [
        migrations.RunPython(add_ai_response_placeholder, remove_ai_response_placeholder),
    ]
