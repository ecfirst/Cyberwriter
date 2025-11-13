from django.db import migrations

FIREWALL_JUSTIFICATION_ISSUE = "Business justification for firewall rules"


def ensure_firewall_global_entries(apps, schema_editor):
    Project = apps.get_model("rolodex", "Project")
    GeneralCapMapping = apps.get_model("rolodex", "GeneralCapMapping")

    try:
        mapping = GeneralCapMapping.objects.get(issue_text=FIREWALL_JUSTIFICATION_ISSUE)
    except GeneralCapMapping.DoesNotExist:
        cap_defaults = {}
    else:
        cap_defaults = {}
        recommendation = getattr(mapping, "recommendation_text", "")
        if recommendation:
            cap_defaults["recommendation"] = recommendation
        score = getattr(mapping, "score", None)
        if score is not None:
            cap_defaults["score"] = score

    if not cap_defaults:
        return

    for project in Project.objects.iterator():
        responses = project.data_responses if isinstance(project.data_responses, dict) else {}
        firewall_responses = responses.get("firewall")
        if not isinstance(firewall_responses, dict):
            continue

        reviews_value = firewall_responses.get("firewall_periodic_reviews")
        if reviews_value in (None, ""):
            continue
        if str(reviews_value).strip().lower() != "no":
            continue

        cap_payload = project.cap if isinstance(project.cap, dict) else {}
        firewall_section = cap_payload.get("firewall")
        if isinstance(firewall_section, dict):
            new_firewall_section = dict(firewall_section)
        else:
            new_firewall_section = {}

        existing_global = new_firewall_section.get("global")
        if isinstance(existing_global, dict):
            new_global = dict(existing_global)
        else:
            new_global = {}

        if new_global.get(FIREWALL_JUSTIFICATION_ISSUE) == cap_defaults:
            continue

        new_global[FIREWALL_JUSTIFICATION_ISSUE] = dict(cap_defaults)
        new_firewall_section["global"] = new_global

        new_cap_payload = dict(cap_payload)
        new_cap_payload["firewall"] = new_firewall_section
        project.cap = new_cap_payload
        project.save(update_fields=["cap"])


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0087_promote_global_badpass_entries"),
    ]

    operations = [
        migrations.RunPython(ensure_firewall_global_entries, migrations.RunPython.noop),
    ]
