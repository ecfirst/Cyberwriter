# OpenAI Responses API settings behind the report AI review

# Django Imports
from django.db import migrations, models
import django_cryptography.fields

# Ghostwriter Libraries
from ghostwriter.reporting.ai_review_prompts import (
    DEFAULT_OPENAI_MODEL,
    DEFAULT_OPENAI_REASONING_EFFORT,
    DEFAULT_OPENAI_VERBOSITY,
    OPENAI_EFFORT_CHOICES,
)


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0044_bloodhoundconfiguration_bloodhound_results"),
    ]

    operations = [
        migrations.CreateModel(
            name="OpenAIConfiguration",
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
                    "enable",
                    models.BooleanField(
                        default=False,
                        help_text="Enable to allow Cyberwriter to query the OpenAI Responses API",
                    ),
                ),
                (
                    "api_key",
                    django_cryptography.fields.encrypt(
                        models.CharField(
                            blank=True,
                            default="",
                            help_text="API key used to authenticate with OpenAI",
                            max_length=255,
                        )
                    ),
                ),
                (
                    "model",
                    models.CharField(
                        default=DEFAULT_OPENAI_MODEL,
                        help_text="OpenAI model name sent with every request (e.g. gpt-6-sol)",
                        max_length=100,
                    ),
                ),
                (
                    "reasoning_effort",
                    models.CharField(
                        choices=OPENAI_EFFORT_CHOICES,
                        default=DEFAULT_OPENAI_REASONING_EFFORT,
                        help_text="Reasoning effort requested from the model",
                        max_length=16,
                    ),
                ),
                (
                    "verbosity",
                    models.CharField(
                        choices=OPENAI_EFFORT_CHOICES,
                        default=DEFAULT_OPENAI_VERBOSITY,
                        help_text="Output verbosity requested from the model",
                        max_length=16,
                    ),
                ),
                (
                    "instructions",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text=(
                            "System instructions sent with every request, ahead of the category prompt. "
                            "Leave blank to use the built-in default text."
                        ),
                    ),
                ),
            ],
            options={
                "verbose_name": "OpenAI Configuration",
            },
        ),
    ]
