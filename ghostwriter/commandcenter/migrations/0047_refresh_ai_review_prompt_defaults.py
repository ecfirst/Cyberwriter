# Refresh seeded AI review prompt rows that still carry the first-release wording

# Django Imports
from django.db import migrations

# Ghostwriter Libraries
from ghostwriter.reporting.ai_review_prompts import (
    AI_REVIEW_PROMPT_DEFAULTS,
    previous_default_instruction,
)


def refresh_untouched_prompts(apps, schema_editor):
    """Rewrite the instruction of rows whose text equals the previous default; leave edited rows alone."""

    AIReviewPromptTemplate = apps.get_model("commandcenter", "AIReviewPromptTemplate")
    for row in AIReviewPromptTemplate.objects.all():
        previous = previous_default_instruction(row.section_key)
        current_default = AI_REVIEW_PROMPT_DEFAULTS.get(row.section_key)
        if previous is None or current_default is None:
            continue
        if (row.instruction or "").strip() == previous.strip():
            row.instruction = current_default["instruction"]
            row.save(update_fields=["instruction"])


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0046_aireviewprompttemplate"),
    ]

    operations = [
        migrations.RunPython(refresh_untouched_prompts, migrations.RunPython.noop),
    ]
