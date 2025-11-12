from __future__ import annotations

from django.db import migrations


def _ensure_password_scores(section):
    changed = False
    if not isinstance(section, dict):
        return changed

    cap_map = section.get("policy_cap_map")
    if not isinstance(cap_map, dict):
        return changed

    for domain, domain_map in cap_map.items():
        if not isinstance(domain_map, dict):
            continue

        policy_map = domain_map.get("policy")
        if isinstance(policy_map, dict) and policy_map:
            if policy_map.get("score") != 4:
                policy_map["score"] = 4
                changed = True
        fgpp_map = domain_map.get("fgpp")
        if isinstance(fgpp_map, dict) and fgpp_map:
            for name, fgpp_values in fgpp_map.items():
                if not isinstance(fgpp_values, dict) or not fgpp_values:
                    continue
                if fgpp_values.get("score") != 4:
                    fgpp_values["score"] = 4
                    changed = True

    return changed


def _ensure_dns_scores(section):
    changed = False
    if not isinstance(section, dict):
        return changed

    dns_cap_map = section.get("dns_cap_map")
    if not isinstance(dns_cap_map, dict):
        return changed

    for domain, issue_map in dns_cap_map.items():
        if not isinstance(issue_map, dict):
            continue
        updated_domain = False
        new_issue_map = {}
        for issue, recommendation in issue_map.items():
            if isinstance(recommendation, dict):
                issue_entry = dict(recommendation)
                if issue_entry.get("score") != 2:
                    issue_entry["score"] = 2
                    updated_domain = True
                if "recommendation" not in issue_entry:
                    issue_entry["recommendation"] = (
                        "" if recommendation is None else str(recommendation)
                    )
                    updated_domain = True
            else:
                issue_entry = {
                    "score": 2,
                    "recommendation": "" if recommendation is None else str(recommendation),
                }
                updated_domain = True
            new_issue_map[issue] = issue_entry
        if updated_domain:
            dns_cap_map[domain] = new_issue_map
            changed = True

    return changed


def apply_score_updates(apps, schema_editor):  # pylint: disable=unused-argument
    Project = apps.get_model("rolodex", "Project")

    for project in Project.objects.all().iterator():
        responses = project.data_responses if isinstance(project.data_responses, dict) else None
        cap_data = project.cap if isinstance(project.cap, dict) else None

        response_changed = False
        cap_changed = False

        if responses is not None:
            password_section = responses.get("password")
            if _ensure_password_scores(password_section):
                response_changed = True

            dns_section = responses.get("dns")
            if _ensure_dns_scores(dns_section):
                response_changed = True

        if cap_data is not None:
            password_cap = cap_data.get("password")
            if _ensure_password_scores(password_cap):
                cap_changed = True

            dns_cap = cap_data.get("dns")
            if _ensure_dns_scores(dns_cap):
                cap_changed = True

        if response_changed:
            project.data_responses = responses

        if cap_changed:
            project.cap = cap_data

        if response_changed or cap_changed:
            update_fields = []
            if response_changed:
                update_fields.append("data_responses")
            if cap_changed:
                update_fields.append("cap")
            project.save(update_fields=update_fields)


def noop(apps, schema_editor):  # pylint: disable=unused-argument
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0065_populate_osint_cap_map"),
    ]

    operations = [
        migrations.RunPython(apply_score_updates, noop),
    ]

