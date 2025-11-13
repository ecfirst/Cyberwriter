from django.db import migrations, models

DEFAULT_PASSWORD_CAPS = {
    "max_age": (
        "Change 'Maximum Age' from {{ max_age }} to == 0 to align with NIST recommendations "
        "to not force users to arbitrarily change passwords based solely on age"
    ),
    "min_age": "Change 'Minimum Age' from {{ min_age }} to >= 1 and < 7",
    "min_length": "Change 'Minimum Length' from {{ min_length }} to >= 8",
    "history": "Change 'History' from {{ history }} to >= 10",
    "lockout_threshold": "Change 'Lockout Threshold' from {{ lockout_threshold }} to > 0 and <= 6",
    "lockout_duration": "Change 'Lockout Duration' from {{ lockout_duration }} to >= 30 or admin unlock",
    "lockout_reset": "Change 'Lockout Reset' from {{ lockout_reset }} to >= 30",
    "complexity_enabled": (
        "Change 'Complexity Required' from TRUE to FALSE and implement additional password selection controls "
        "such as blacklists"
    ),
}


def seed_password_caps(apps, schema_editor):
    cap_model = apps.get_model("rolodex", "PasswordCapMapping")

    for setting, cap in DEFAULT_PASSWORD_CAPS.items():
        cap_model.objects.update_or_create(
            setting=setting,
            defaults={"cap_text": cap},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0060_dns_soa_cap_mappings"),
    ]

    operations = [
        migrations.CreateModel(
            name="PasswordCapMapping",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "setting",
                    models.CharField(
                        help_text="Name of the password policy setting captured from workbook data.",
                        max_length=64,
                        unique=True,
                        verbose_name="Password setting",
                    ),
                ),
                (
                    "cap_text",
                    models.TextField(
                        help_text="Guidance presented when the setting is outside recommended bounds.",
                        verbose_name="Corrective action plan",
                    ),
                ),
            ],
            options={
                "ordering": ["setting"],
                "verbose_name": "Password CAP mapping",
                "verbose_name_plural": "Password CAP mappings",
            },
        ),
        migrations.RunPython(seed_password_caps, migrations.RunPython.noop),
    ]
