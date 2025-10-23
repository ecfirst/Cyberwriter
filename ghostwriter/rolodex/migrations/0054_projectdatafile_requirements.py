from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0053_project_reporting_workbook"),
    ]

    operations = [
        migrations.AddField(
            model_name="projectdatafile",
            name="requirement_slug",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="Requirement Key",
            ),
        ),
        migrations.AddField(
            model_name="projectdatafile",
            name="requirement_label",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="Requirement Label",
            ),
        ),
        migrations.AddField(
            model_name="projectdatafile",
            name="requirement_context",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                verbose_name="Requirement Context",
            ),
        ),
    ]
