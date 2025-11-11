from django.db import migrations, models


DEFAULT_DNS_SOA_CAPS = {
    "serial": "Update to match the 'YYYYMMDDnn' scheme",
    "expire": "Update to a value between 1209600 to 2419200",
    "mname": "Update to a value that is an authoritative name server",
    "minimum": "Update to a value greater than 300",
    "refresh": "Update to a value between 1200 and 43200 seconds",
    "retry": "Update to a value less than or equal to half the REFRESH",
}


def seed_dns_soa_caps(apps, schema_editor):
    cap_model = apps.get_model("rolodex", "DNSSOACapMapping")

    for field, cap in DEFAULT_DNS_SOA_CAPS.items():
        cap_model.objects.update_or_create(
            soa_field=field,
            defaults={"cap_text": cap},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0059_dns_cap_mappings"),
    ]

    operations = [
        migrations.CreateModel(
            name="DNSSOACapMapping",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "soa_field",
                    models.CharField(
                        help_text="Name of the SOA field flagged as outside the recommended range.",
                        max_length=64,
                        unique=True,
                        verbose_name="SOA field",
                    ),
                ),
                (
                    "cap_text",
                    models.TextField(
                        help_text="Guidance presented when the SOA field is selected in DNS responses.",
                        verbose_name="Corrective action plan",
                    ),
                ),
            ],
            options={
                "ordering": ["soa_field"],
                "verbose_name": "DNS SOA CAP mapping",
                "verbose_name_plural": "DNS SOA CAP mappings",
            },
        ),
        migrations.RunPython(seed_dns_soa_caps, migrations.RunPython.noop),
    ]
