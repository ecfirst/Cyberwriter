# Stores the AI-generated OWASP Top 10 review text for a report

# Django Imports
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("reporting", "0063_reportsupplementalfile_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="ai_review",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="AI-generated OWASP Top 10 review text keyed by category",
            ),
        ),
    ]
