# Moves the OpenAI prompt settings out of the retired dashboard prompt object

# Django Imports
from django.db import migrations, models

# Ghostwriter Libraries
from ghostwriter.rolodex.ai_review_prompts import (
    DEFAULT_OPENAI_MODEL,
    DEFAULT_OPENAI_REASONING_EFFORT,
    DEFAULT_OPENAI_VERBOSITY,
    OPENAI_EFFORT_CHOICES,
)


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0048_aireviewprompttemplate"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="openaiconfiguration",
            name="prompt_id",
        ),
        # Help text drifted from the original Assistants API wording; folded in
        # here so ``makemigrations --check`` is clean.
        migrations.AlterField(
            model_name="openaiconfiguration",
            name="enable",
            field=models.BooleanField(
                default=False,
                help_text="Enable to allow CyberWriter to query the OpenAI Responses API",
            ),
        ),
        migrations.AddField(
            model_name="openaiconfiguration",
            name="model",
            field=models.CharField(
                default=DEFAULT_OPENAI_MODEL,
                help_text="OpenAI model name sent with every request (e.g. gpt-6-sol)",
                max_length=100,
            ),
        ),
        migrations.AddField(
            model_name="openaiconfiguration",
            name="reasoning_effort",
            field=models.CharField(
                choices=OPENAI_EFFORT_CHOICES,
                default=DEFAULT_OPENAI_REASONING_EFFORT,
                help_text="Reasoning effort requested from the model",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="openaiconfiguration",
            name="verbosity",
            field=models.CharField(
                choices=OPENAI_EFFORT_CHOICES,
                default=DEFAULT_OPENAI_VERBOSITY,
                help_text="Output verbosity requested from the model",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="openaiconfiguration",
            name="instructions",
            field=models.TextField(
                blank=True,
                default="",
                help_text=(
                    "System instructions sent with every request, ahead of the area prompt. "
                    "Leave blank to use the built-in default text."
                ),
            ),
        ),
    ]
