from django.db import migrations


ISSUE_TEXT = "Number of Systems with Logged in Generic Accounts"
RECOMMENDATION_TEXT = (
    "Review systems with 'generic account' login activity to ensure it is authorized and/or intended"
)
SCORE = 5


def add_general_cap(apps, schema_editor):
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
        ("rolodex", "0090_project_scoping"),
    ]

    operations = [
        migrations.RunPython(add_general_cap, migrations.RunPython.noop),
        migrations.RunPython(rebuild_project_cap, migrations.RunPython.noop),
    ]
