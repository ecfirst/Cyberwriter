from django.db import migrations, models
import django.db.models.deletion

import ghostwriter.rolodex.models


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0101_normalize_matrix_entry_text"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProjectArtifactFile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "artifact_key",
                    models.CharField(
                        help_text="The data_artifacts key this generated file belongs to (e.g. 'internal_nexpose_metrics').",
                        max_length=64,
                        verbose_name="Artifact Key",
                    ),
                ),
                (
                    "file",
                    models.FileField(
                        max_length=255,
                        upload_to=ghostwriter.rolodex.models._project_artifact_upload_to,
                        verbose_name="Generated Artifact File",
                    ),
                ),
                (
                    "filename",
                    models.CharField(blank=True, default="", max_length=255, verbose_name="Display Filename"),
                ),
                ("byte_size", models.BigIntegerField(default=0, verbose_name="File Size (bytes)")),
                ("generated_at", models.DateTimeField(auto_now=True)),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="artifact_files",
                        to="rolodex.project",
                    ),
                ),
            ],
            options={
                "verbose_name": "Project artifact file",
                "verbose_name_plural": "Project artifact files",
                "ordering": ["project", "artifact_key"],
            },
        ),
        migrations.AlterUniqueTogether(
            name="projectartifactfile",
            unique_together={("project", "artifact_key")},
        ),
    ]
