from django.db import migrations, models

from ghostwriter.rolodex.ai_review_prompts import AI_REVIEW_PROMPT_DEFAULTS


def seed_default_prompts(apps, schema_editor):
    """Create one row per AI review area carrying the built-in prompt text."""

    AIReviewPromptTemplate = apps.get_model("commandcenter", "AIReviewPromptTemplate")
    for section_key, entry in AI_REVIEW_PROMPT_DEFAULTS.items():
        AIReviewPromptTemplate.objects.get_or_create(
            section_key=section_key,
            defaults={"instruction": entry["instruction"], "footer": entry["footer"]},
        )


class Migration(migrations.Migration):
    dependencies = [
        ("commandcenter", "0047_scoringconfiguration"),
    ]

    operations = [
        migrations.CreateModel(
            name="AIReviewPromptTemplate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "section_key",
                    models.CharField(
                        choices=[
                            ("osint_rt", "OSINT"),
                            ("dns_rt", "DNS"),
                            ("external_nexpose_rt", "External Nexpose"),
                            ("web_rt", "Web"),
                            ("ad_rt", "AD"),
                            ("ad_attack_paths_rt", "AD Attack Paths"),
                            ("password_rt", "Password"),
                            ("internal_nexpose_rt", "Internal Nexpose"),
                            ("iot_iomt_nexpose_rt", "IoT/IoMT Nexpose"),
                            ("endpoint_rt", "Endpoint"),
                            ("snmp_rt", "SNMP"),
                            ("sql_rt", "SQL"),
                            ("wireless_rt", "Wireless"),
                            ("firewall_rt", "Firewall"),
                            ("cloud_management_rt", "Cloud Management"),
                            ("iam_management_rt", "IAM Management"),
                            ("system_configuration_rt", "System Configuration"),
                        ],
                        help_text="AI review area this prompt text applies to",
                        max_length=64,
                        unique=True,
                        verbose_name="Area",
                    ),
                ),
                (
                    "instruction",
                    models.TextField(
                        help_text="Opening instruction sent to OpenAI before the project data JSON. {risk} is replaced with the area's risk label (e.g. High).",
                        verbose_name="Instruction",
                    ),
                ),
                (
                    "footer",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Closing instruction sent after the project data JSON, normally the required risk statement. {risk} is replaced with the area's risk label. Leave blank to send no footer.",
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
