from django.db import migrations, models


DEFAULT_DNS_CAPS = {
    "One or more SOA fields are outside recommended ranges": "Get-SOA $domname",
    "Less than 2 nameservers exist": "Assign a minimum of 2 nameservers for the domain",
    "More than 8 nameservers exist": "Limit the number of nameservers to less than 8",
    "Some nameservers have duplicate addresses": "Ensure all nameserver addresses are unique",
    "Some nameservers did not respond": "Ensure all nameservers respond to queries",
    "Some nameservers respond recursive queries": "Configure nameservers to not respond to recursive queries",
    "Some nameservers do not respond to TCP queries": "Ensure all nameservers respond to TCP queries",
    "Some nameservers return version numbers": "Configure nameservers to not return version numbers",
    "Some nameservers provide a differing list of nameservers": "Ensure all nameservers provide the same list of nameservers",
    "Some nameserver addresses are private": "Ensure all nameserver addresses are public",
    "Some nameservers do not provide a SOA record for the zone": "Ensure all nameservers provide a SOA record for the zone",
    "Some nameserver SOAs have differing serial numbers": "Ensure all nameserver SOA serial numbers match",
    "No MX records exist within the zone": "Implement an MX record and corrisponding mail server",
    "Only one MX record exists within the zone": "Consider implementing a secondary MX record and corresponding mail server",
    "MX record resolves to a single IP address": "Consider implementing a secondary mail server and corresponding MX record",
    "Hostnames referenced by MX records resolve to the same IP address": "Consider implementing a secondary mail server and corresponding MX record",
    "Some addresses referenced by MX records do not have matching reverse DNS entries": "Create PTR records for MX IP addresses",
    "Some mailserver IP addresses are private": "Ensure all listed mailserver IP addresses are public",
    "Some connections to Mailservers port 25 failed": "Ensure all mailservers allow access",
    "Some mailservers appear to be open relays": "Configure mailservers to not allow open relaying",
    "This domain does not have DNSSEC records": "Consider implementing DNSSEC",
    "The DNSKEY does not appear to be valid for the domain": "Ensure a valid DNSKEY record exists",
    "The domain does not have an SPF record": "Consider implementing a SPF record",
    "The SPF value does not allow mail delivery from all mailservers in the domain": "Update the SPF record to include all authorized mail servers",
    "The SPF record contains the overly permissive modifier '+all'": "Remove the '+all' modifier",
}


def seed_dns_caps(apps, schema_editor):
    cap_model = apps.get_model("rolodex", "DNSCapMapping")

    for issue, cap in DEFAULT_DNS_CAPS.items():
        cap_model.objects.update_or_create(
            issue_text=issue,
            defaults={"cap_text": cap},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0058_dns_issue_mappings"),
    ]

    operations = [
        migrations.CreateModel(
            name="DNSCapMapping",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "issue_text",
                    models.TextField(
                        help_text="Exact text of the DNS check failure (matches dns_report.csv entries).",
                        unique=True,
                        verbose_name="DNS issue",
                    ),
                ),
                (
                    "cap_text",
                    models.TextField(
                        help_text="Prescribed DNS CAP guidance displayed with the DNS finding.",
                        verbose_name="Corrective action plan",
                    ),
                ),
            ],
            options={
                "ordering": ["issue_text"],
                "verbose_name": "DNS CAP mapping",
                "verbose_name_plural": "DNS CAP mappings",
            },
        ),
        migrations.RunPython(seed_dns_caps, migrations.RunPython.noop),
    ]
