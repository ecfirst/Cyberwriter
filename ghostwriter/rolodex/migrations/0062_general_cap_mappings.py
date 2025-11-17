from django.db import migrations, models


DEFAULT_GENERAL_CAPS = {
    "Weak passwords in use": (
        "Force all accounts whose password was cracked to change their password. "
        "Provide training on secure password creation",
        7,
    ),
    "LANMAN password hashing enabled": (
        "Configure the domain to disable LANMAN password hashing. Force accounts with stored "
        "LANMAN password hashes to change their password",
        5,
    ),
    "Fine-grained Password Policies not defined": (
        "Define and assign Fine-grained Password Policies for security groups based on the risk "
        "associated with an account compromise.\n(Secure Password policy & procedures)",
        4,
    ),
    "Additional password controls not implemented": (
        "Implement additional password controls as recommended by NIST for blacklisting and/or "
        "repetitive/sequential characters, which are not available natively in Active Directory\n"
        "(Secure Password policy & procedures)",
        4,
    ),
    "MFA not enforced for all accounts": (
        "Enforce MFA for all accounts as recommended by NIST",
        4,
    ),
    "Systems without active up-to-date security software": (
        "Review the systems identified without active, current security software and remediate as appropriate",
        5,
    ),
    "Systems connecting to Open WiFi networks": (
        "Review the systems that have connected to Open WiFi networks to ensure appropriate protections are in place",
        5,
    ),
    "Domain Functionality Level less than 2008": (
        "Upgrade the domain functionality level to 2008 or greater.",
        5,
    ),
    "Number of Disabled Accounts": (
        "Delete accounts that are no longer needed. Additionally, develop a policy and procedure to delete accounts "
        "that have remained disabled for 90 or more days.\r(Account Management policy & procedures)",
        5,
    ),
    "Number of Systems with Logged in Generic Accounts": (
        "Review systems with 'generic account' login activity to ensure it is authorized and/or intended",
        5,
    ),
    "Number of 'Generic Accounts'": (
        "Unique user accounts should always be used to access data and systems; deviations from this must be documented "
        "including a valid business justification. Additionally, extra security controls should be enforced on any "
        "shared or generic accounts as appropriate.\r(Account Management policy & procedures)",
        5,
    ),
    "Potentially Inactive Accounts": (
        "Review the potentially inactive accounts and disable or delete those no longer needed. Additionally, it should be "
        "recorded why valid account users have not logged into the domain in a timely fashion.\r(Account Management policy "
        "& procedures)",
        5,
    ),
    "Accounts with Passwords that Never Expire": (
        "Company policy should force users to change their passwords minimally every 90 days. All groups should follow this "
        "policy (except service accounts which should typically force or remind administrators to change these account "
        "passwords every six to twelve months). If service account password expiration dates are handled differently from "
        "user accounts, company policy must dictate that in writing.\r(Account Management policy & procedures)",
        5,
    ),
    "Accounts with Expired Passwords": (
        "Review accounts with expired passwords and disable or delete those no longer needed.\r(Account Management policy "
        "& procedures)",
        5,
    ),
    "Number of Enterprise Admins": (
        "Members of the Enterprise Admins group should be restricted to no more than 3 accounts.\r(Account Management "
        "policy & procedures)",
        5,
    ),
    "Number of Domain Admins": (
        "Members of the Domain Admins group should be restricted to the least number of accounts possible.\r(Account "
        "Management policy & procedures)",
        5,
    ),
    "Databases allowing open access": (
        "Review the data contained in databases allowing open access to determine the sensitivity level and thus additional "
        "security controls.",
        5,
    ),
    "Default SNMP community strings & default credentials in use": (
        "Configure all systems to use unique credentials, including SNMP community strings",
        5,
    ),
    "OSINT identified assets": (
        "Review the assets identified to ensure they are known and managed appropriately",
        1,
    ),
    "Exposed buckets identified": (
        "Review the identified buckets to ensure they are not exposing sensitive information",
        1,
    ),
    "Exposed Credentials identified": (
        "Review the exposed credentials identified and take appropriate action",
        1,
    ),
    "Potential domain squatters identified": (
        "Review the domains identified as potentially being used for domain typo-squatting and take appropriate action",
        1,
    ),
    "PSK’s in use on wireless networks": (
        "Ensure all Pre-Shared Keys (PSK) in use for wireless networks are changed periodically or whenever someone with "
        "knowledge of the keys leaves the company",
        3,
    ),
    "Weak PSK's in use": (
        "Change the PSK's to be of sufficient length & entropy; ensure PSK's are not based on Company information or "
        "dictionary words",
        4,
    ),
    "Potentially Rogue Access Points": (
        "Investigate the potentially rogue access points identified to ensure they are not connected to the internal network",
        5,
    ),
    "WEP in use on wireless networks": (
        "Disable WEP and utilize WPA2 at a minimum",
        9,
    ),
    "Open wireless network connected to the Internal network": (
        "Properly segment the open wireless network from the Internal network",
        9,
    ),
    "802.1x authentication not implemented for wireless networks": (
        "Review if 802.1x authentication is possible with the existing Access Points in use. If so, transition SSID’s to utilize "
        "802.1x authentication instead of the PSK’s. If not, investigate replacing the devices",
        3,
    ),
    "Business justification for firewall rules": (
        "Review all firewall rules to ensure there is a valid business justification; document the business justification and "
        "network access requirements",
        5,
    ),
}


def seed_general_caps(apps, schema_editor):
    cap_model = apps.get_model("rolodex", "GeneralCapMapping")

    for issue, (recommendation, score) in DEFAULT_GENERAL_CAPS.items():
        cap_model.objects.update_or_create(
            issue_text=issue,
            defaults={
                "recommendation_text": recommendation,
                "score": score,
            },
        )


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0061_password_cap_mappings"),
    ]

    operations = [
        migrations.CreateModel(
            name="GeneralCapMapping",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "issue_text",
                    models.TextField(
                        help_text="Exact text describing the issue that needs remediation.",
                        unique=True,
                        verbose_name="Issue",
                    ),
                ),
                (
                    "recommendation_text",
                    models.TextField(
                        help_text="Corrective action guidance presented for this issue.",
                        verbose_name="Recommendation",
                    ),
                ),
                (
                    "score",
                    models.PositiveSmallIntegerField(
                        default=0,
                        help_text="Numeric score representing the severity or priority of the issue.",
                        verbose_name="Score",
                    ),
                ),
            ],
            options={
                "ordering": ["issue_text"],
                "verbose_name": "General CAP mapping",
                "verbose_name_plural": "General CAP mappings",
            },
        ),
        migrations.RunPython(seed_general_caps, migrations.RunPython.noop),
    ]

