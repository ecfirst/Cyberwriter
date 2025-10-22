# Generated manually because Django is unavailable in the execution environment.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("rolodex", "0052_projectobjective_result"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProjectReportData",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "project",
                    models.OneToOneField(
                        on_delete=models.CASCADE,
                        related_name="report_data",
                        to="rolodex.project",
                    ),
                ),
                (
                    "workbook",
                    models.FileField(
                        blank=True,
                        help_text="Upload the JSON workbook that powers reporting",
                        null=True,
                        upload_to="reporting/workbooks/",
                        verbose_name="Workbook",
                    ),
                ),
                (
                    "workbook_uploaded_at",
                    models.DateTimeField(
                        auto_now=True,
                        help_text="Timestamp of the most recent workbook upload",
                        verbose_name="Workbook Updated",
                    ),
                ),
                (
                    "responses",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Stored answers for dynamic reporting questions",
                        verbose_name="Report Responses",
                    ),
                ),
            ],
            options={
                "verbose_name": "Project report data",
                "verbose_name_plural": "Project report data",
            },
        ),
        migrations.CreateModel(
            name="ProjectReportArtifact",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=models.CASCADE,
                        related_name="report_artifacts",
                        to="rolodex.project",
                    ),
                ),
                (
                    "category",
                    models.CharField(
                        help_text="Identifier used to determine how the artifact is used",
                        max_length=255,
                        verbose_name="Artifact Category",
                    ),
                ),
                (
                    "label",
                    models.CharField(
                        help_text="Human-readable label for this artifact",
                        max_length=255,
                        verbose_name="Artifact Label",
                    ),
                ),
                (
                    "file",
                    models.FileField(
                        help_text="Upload a supplemental file used during reporting",
                        upload_to="reporting/artifacts/",
                        verbose_name="Artifact File",
                    ),
                ),
                ("uploaded_at", models.DateTimeField(auto_now_add=True, verbose_name="Uploaded")),
                ("updated_at", models.DateTimeField(auto_now=True, verbose_name="Updated")),
            ],
            options={
                "ordering": ["project", "category", "uploaded_at"],
                "verbose_name": "Project report artifact",
                "verbose_name_plural": "Project report artifacts",
            },
        ),
    ]
