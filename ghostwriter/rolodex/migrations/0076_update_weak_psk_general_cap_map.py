from django.db import migrations


ISSUE_TEXT = "Weak PSK's in use"
RECOMMENDATION_TEXT = (
    "Change the PSK's to be of sufficient length & entropy; ensure PSK's are not "
    "based on Company information or dictionary words"
)
SCORE = 4


def update_general_cap(apps, schema_editor):
    try:
        general_model = apps.get_model("rolodex", "GeneralCapMapping")
    except LookupError:
        return

    general_model.objects.update_or_create(
        issue_text=ISSUE_TEXT,
        defaults={
            "recommendation_text": RECOMMENDATION_TEXT,
            "score": SCORE,
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
        ("rolodex", "0075_populate_wireless_cap_map"),
    ]

    operations = [
        migrations.RunPython(update_general_cap, migrations.RunPython.noop),
        migrations.RunPython(rebuild_project_cap, migrations.RunPython.noop),
    ]

