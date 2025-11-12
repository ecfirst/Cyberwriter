from django.db import migrations


WIRELESS_WEAK_PSK_ISSUE = "Weak PSK's in use"
WIRELESS_WEAK_PSK_RECOMMENDATION = (
    "Replace weak wireless pre-shared keys with strong, unique values that align "
    "with organizational complexity requirements"
)
WIRELESS_WEAK_PSK_SCORE = 5


def ensure_wireless_cap_entries(apps, schema_editor):
    try:
        general_model = apps.get_model("rolodex", "GeneralCapMapping")
    except LookupError:
        return

    general_model.objects.update_or_create(
        issue_text=WIRELESS_WEAK_PSK_ISSUE,
        defaults={
            "recommendation_text": WIRELESS_WEAK_PSK_RECOMMENDATION,
            "score": WIRELESS_WEAK_PSK_SCORE,
        },
    )


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
        ("rolodex", "0074_populate_endpoint_cap_map"),
    ]

    operations = [
        migrations.RunPython(ensure_wireless_cap_entries, migrations.RunPython.noop),
        migrations.RunPython(rebuild_project_cap, migrations.RunPython.noop),
    ]
