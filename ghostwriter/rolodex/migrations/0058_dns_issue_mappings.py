from django.db import migrations, models


DEFAULT_DNS_RECOMMENDATIONS = {
    "One or more SOA fields are outside recommended ranges": "update SOA fields to follow best practice",
    "Less than 2 nameservers exist": "assign a minimum of 2 nameservers for the domain",
    "More than 8 nameservers exist": "limit the number of nameservers to less than 8",
    "Some nameservers have duplicate addresses": "ensure all nameserver addresses are unique",
    "Some nameservers did not respond": "ensure all nameservers respond to queries",
    "Some nameservers respond recursive queries": "configure nameservers to not respond to recursive queries",
    "Some nameservers do not respond to TCP queries": "ensure all nameservers respond to TCP queries",
    "Some nameservers return version numbers": "configure nameservers to not return version numbers",
    "Some nameservers provide a differing list of nameservers": "ensure all nameservers provide the same list of nameservers",
    "Some nameserver addresses are private": "ensure all nameserver addresses are public",
    "Some nameservers do not provide a SOA record for the zone": "ensure all nameservers provide a SOA record for the zone",
    "Some nameserver SOAs have differing serial numbers": "ensure all nameserver SOA serial numbers match",
    "No MX records exist within the zone": "implement an MX record and corrisponding mail server",
    "Only one MX record exists within the zone": "consider implementing a secondary MX record and corresponding mail server",
    "MX record resolves to a single IP address": "consider implementing a secondary MX record and corresponding mail server",
    "Some addresses referenced by MX records do not have matching reverse DNS entries": "create PTR records for MX IP addresses",
    "Some mailserver IP addresses are private": "ensure all listed mailserver IP addresses are public",
    "Some connections to Mailservers port 25 failed": "ensure all mailservers allow access",
    "Some mailservers appear to be open relays": "configure mailservers to not allow open relaying",
    "This domain does not have DNSSEC records": "consider implementing DNSSEC",
    "The DNSKEY does not appear to be valid for the domain": "ensure a valid DNSKEY record exists",
    "The domain does not have an SPF record": "consider implementing a SPF record",
    "The SPF value does not allow mail delivery from all mailservers in the domain": "update the SPF record to include all authorized mail servers",
    "The SPF record contains the overly permissive modifier '+all'": "remove the '+all' modifier",
}


DEFAULT_DNS_FINDINGS = {
    "One or more SOA fields are outside recommended ranges": "configuring DNS records according to best practice",
    "Less than 2 nameservers exist": "the number/availability of nameservers",
    "More than 8 nameservers exist": "the number/availability of nameservers",
    "Some nameservers have duplicate addresses": "the number/availability of nameservers",
    "Some nameservers did not respond": "the number/availability of nameservers",
    "Some nameservers respond recursive queries": "the number/availability of nameservers",
    "Some nameservers do not respond to TCP queries": "the number/availability of nameservers",
    "Some nameservers return version numbers": "information leakage by nameservers",
    "Some nameservers provide a differing list of nameservers": "the number/availability of nameservers",
    "Some nameserver addresses are private": "the number/availability of nameservers",
    "Some nameservers do not provide a SOA record for the zone": "configuring DNS records according to best practice",
    "Some nameserver SOAs have differing serial numbers": "configuring DNS records according to best practice",
    "No MX records exist within the zone": "email delivery for the domain",
    "Only one MX record exists within the zone": "email delivery for the domain",
    "MX record resolves to a single IP address": "email delivery for the domain",
    "Some addresses referenced by MX records do not have matching reverse DNS entries": "email delivery for the domain",
    "Some mailserver IP addresses are private": "email delivery for the domain",
    "Some connections to Mailservers port 25 failed": "email delivery for the domain",
    "Some mailservers appear to be open relays": "email delivery for the domain",
    "This domain does not have DNSSEC records": "protection of DNS records",
    "The DNSKEY does not appear to be valid for the domain": "protection of DNS records",
    "The domain does not have an SPF record": "email delivery for the domain",
    "The SPF value does not allow mail delivery from all mailservers in the domain": "email delivery for the domain",
    "The SPF record contains the overly permissive modifier '+all'": "email delivery for the domain",
}


def seed_dns_mappings(apps, schema_editor):
    finding_model = apps.get_model("rolodex", "DNSFindingMapping")
    recommendation_model = apps.get_model("rolodex", "DNSRecommendationMapping")

    for issue, finding in DEFAULT_DNS_FINDINGS.items():
        finding_model.objects.update_or_create(
            issue_text=issue,
            defaults={"finding_text": finding},
        )

    for issue, recommendation in DEFAULT_DNS_RECOMMENDATIONS.items():
        recommendation_model.objects.update_or_create(
            issue_text=issue,
            defaults={"recommendation_text": recommendation},
        )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0057_backfill_project_risks"),
    ]

    operations = [
        migrations.CreateModel(
            name="DNSFindingMapping",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("issue_text", models.TextField(help_text="Exact text of the DNS check failure (matches dns_report.csv entries).", unique=True, verbose_name="DNS issue")),
                ("finding_text", models.TextField(help_text="Short description used when summarizing the issue in reports.", verbose_name="Finding summary")),
            ],
            options={
                "ordering": ["issue_text"],
                "verbose_name": "DNS finding mapping",
                "verbose_name_plural": "DNS finding mappings",
            },
        ),
        migrations.CreateModel(
            name="DNSRecommendationMapping",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("issue_text", models.TextField(help_text="Exact text of the DNS check failure (matches dns_report.csv entries).", unique=True, verbose_name="DNS issue")),
                ("recommendation_text", models.TextField(help_text="Remediation guidance presented alongside the DNS finding.", verbose_name="Recommendation")),
            ],
            options={
                "ordering": ["issue_text"],
                "verbose_name": "DNS recommendation mapping",
                "verbose_name_plural": "DNS recommendation mappings",
            },
        ),
        migrations.RunPython(seed_dns_mappings, migrations.RunPython.noop),
    ]
