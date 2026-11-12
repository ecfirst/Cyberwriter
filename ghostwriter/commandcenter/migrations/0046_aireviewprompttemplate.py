# Admin-editable prompt text for each OWASP Top 10:2025 AI review category

# Django Imports
from django.db import migrations, models

# Ghostwriter Libraries
from ghostwriter.reporting.ai_review_prompts import (
    AI_REVIEW_PROMPT_DEFAULTS,
    AI_REVIEW_SECTION_CHOICES,
)


def seed_default_prompts(apps, schema_editor):
    """Create one row per AI review category carrying the built-in prompt text."""

    AIReviewPromptTemplate = apps.get_model("commandcenter", "AIReviewPromptTemplate")
    for section_key, entry in AI_REVIEW_PROMPT_DEFAULTS.items():
        AIReviewPromptTemplate.objects.get_or_create(
            section_key=section_key,
            defaults={"instruction": entry["instruction"], "footer": entry["footer"]},
        )


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0045_openaiconfiguration"),
    ]

    operations = [
        migrations.CreateModel(
            name="AIReviewPromptTemplate",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "section_key",
                    models.CharField(
                        choices=list(AI_REVIEW_SECTION_CHOICES),
                        help_text="OWASP Top 10 category this prompt text applies to",
                        max_length=64,
                        unique=True,
                        verbose_name="Category",
                    ),
                ),
                (
                    "instruction",
                    models.TextField(
                        help_text=(
                            "Opening instruction sent to OpenAI before the report data JSON. "
                            "{label} is replaced with the category label (e.g. A01:2025 Broken Access Control)."
                        ),
                        verbose_name="Instruction",
                    ),
                ),
                (
                    "footer",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text=(
                            "Closing instruction sent after the report data JSON. {label} is replaced with the "
                            "category label. Leave blank to send no footer."
                        ),
                        verbose_name="Footer",
                    ),
                ),
            ],
            options={
                "verbose_name": "AI Review Prompt",
                "verbose_name_plural": "AI Review Prompts",
                "ordering": ["section_key"],
            },
        ),
        migrations.RunPython(seed_default_prompts, migrations.RunPython.noop),
    ]
