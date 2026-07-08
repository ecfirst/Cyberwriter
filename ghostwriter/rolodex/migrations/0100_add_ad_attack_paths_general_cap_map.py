from django.db import migrations


ATTACK_PATHS_GENERAL_CAPS = {
    "Active Directory Certificate Services Templates Enable Privilege Escalation": (
        "Restrict enrollment on client-authentication templates to privileged groups, remove "
        "`ENROLLEE_SUPPLIES_SUBJECT` from any template granting client auth EKUs, and require manager "
        "approval on high-privilege templates.",
        10,
    ),
    "Plaintext Credentials Recoverable from Group Policy Preferences on SYSVOL": (
        "Remove every Group Policy Preferences XML file containing `cpassword` from SYSVOL and treat "
        "every exposed account as compromised — rotate all referenced credentials immediately.",
        9,
    ),
    "Non-Domain-Controller Principals Configured for Unconstrained Delegation": (
        "Convert non-DC unconstrained delegation to constrained delegation with protocol transition "
        "only where required, and remove `TRUSTED_FOR_DELEGATION` from user accounts entirely.",
        9,
    ),
    "Active Directory Certificate Authority Configuration Enables Privilege Escalation": (
        "Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on all Certificate Authorities, restrict ManageCA "
        "and ManageCertificates rights to tier-0 administrators, and disable HTTP CA web enrollment.",
        8,
    ),
    "User Accounts Do Not Require Kerberos Pre-Authentication": (
        'Remove the "Do not require Kerberos preauthentication" flag from all user accounts and '
        "verify no privileged account carries it.",
        8,
    ),
    "Alternate Certificate-Based Credentials Present on Domain Accounts (Shadow Credentials)": (
        "Triage each `msDS-KeyCredentialLink` entry against the client's Windows Hello for Business "
        "enrollment inventory and remove any credential not tied to an authorized enrollment.",
        8,
    ),
    "Enabled User Accounts Allow Kerberoasting": (
        "Migrate SPN-bearing user accounts to group Managed Service Accounts where possible, and "
        "enforce 25+ character random passwords on any that must remain.",
        8,
    ),
    "Local Administrator Password Rotation (LAPS) Not Fully Deployed": (
        "Deploy Windows LAPS to 100% of domain-joined workstations and member servers, retire legacy "
        "LAPS on any remaining endpoints, and confirm rotation is occurring on schedule.",
        7,
    ),
    "Objects Grant Resource-Based Constrained Delegation to Other Principals": (
        "Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` values across the domain and remove any not "
        "tied to a documented delegation requirement.",
        7,
    ),
    "Domain Controllers Accept Anonymous or Unsigned LDAP Binds": (
        "Disable anonymous LDAP bind on all Domain Controllers and enforce LDAP signing and channel "
        "binding (`LdapEnforceChannelBinding=2`).",
        7,
    ),
    "Accounts Configured for Kerberos Constrained Delegation with Protocol Transition": (
        "Remove `TrustedToAuthForDelegation` (T2A4D) from any account whose workflow does not require "
        "protocol transition, and document the remaining legitimate use cases.",
        7,
    ),
    "Privileged Accounts Are Not Members of the Protected Users Group": (
        "Add all Domain Admins and Enterprise Admins to the Protected Users group after validating no "
        "service dependency will break under its protocol restrictions.",
        6,
    ),
}


def seed_general_caps(apps, schema_editor):
    cap_model = apps.get_model("rolodex", "GeneralCapMapping")

    for issue, (recommendation, score) in ATTACK_PATHS_GENERAL_CAPS.items():
        cap_model.objects.update_or_create(
            issue_text=issue,
            defaults={
                "recommendation_text": recommendation,
                "score": score,
            },
        )


def rebuild_project_cap(apps, schema_editor):
    try:
        from ghostwriter.rolodex.models import Project  # type: ignore
    except Exception:
        return

    for project in Project.objects.iterator():
        try:
            project.rebuild_data_artifacts()
        except Exception:
            continue


class Migration(migrations.Migration):

    dependencies = [
        ("rolodex", "0099_dns_impact_mappings"),
    ]

    operations = [
        migrations.RunPython(seed_general_caps, migrations.RunPython.noop),
        migrations.RunPython(rebuild_project_cap, migrations.RunPython.noop),
    ]
