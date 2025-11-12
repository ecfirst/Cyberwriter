"""Utilities for parsing uploaded project data files."""

from __future__ import annotations

# Standard Libraries
import csv
import io
import re
from collections import Counter
from collections import abc
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from django.apps import apps
from django.core.files.base import File
from django.db.utils import OperationalError, ProgrammingError

if False:  # pragma: no cover - typing only
    from ghostwriter.rolodex.models import Project, ProjectDataFile  # noqa: F401

from ghostwriter.rolodex.ip_artifacts import IP_ARTIFACT_DEFINITIONS, parse_ip_text
from ghostwriter.rolodex.workbook import AD_DOMAIN_METRICS


DEFAULT_DNS_RECOMMENDATION_MAP: Dict[str, str] = {
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

DEFAULT_DNS_CAP_MAP: Dict[str, str] = {
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

DEFAULT_PASSWORD_CAP_MAP: Dict[str, str] = {
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

_CAP_PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

DEFAULT_GENERAL_CAP_MAP: Dict[str, Tuple[str, int]] = {
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
        "Change the PSK's to be of sufficient length & entropy; ensure PSK's are not "
        "based on Company information or dictionary words",
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

DEFAULT_PASSWORD_COMPLIANCE_MATRIX: Dict[str, Dict[str, Any]] = {
    "max_age": {
        "data_type": "numeric",
        "rule": {
            "operator": "any",
            "rules": [
                {"operator": "ne", "value": 0},
                {"operator": "lt", "value": 365},
            ],
        },
    },
    "min_age": {
        "data_type": "numeric",
        "rule": {
            "operator": "any",
            "rules": [
                {"operator": "lt", "value": 1},
                {"operator": "gt", "value": 7},
            ],
        },
    },
    "min_length": {
        "data_type": "numeric",
        "rule": {"operator": "lt", "value": 8},
    },
    "history": {
        "data_type": "numeric",
        "rule": {"operator": "lt", "value": 10},
    },
    "lockout_threshold": {
        "data_type": "numeric",
        "rule": {
            "operator": "any",
            "rules": [
                {"operator": "eq", "value": 0},
                {"operator": "gt", "value": 6},
            ],
        },
    },
    "lockout_duration": {
        "data_type": "numeric",
        "rule": {
            "operator": "all",
            "rules": [
                {"operator": "gte", "value": 1},
                {"operator": "lte", "value": 29},
            ],
        },
    },
    "lockout_reset": {
        "data_type": "numeric",
        "rule": {"operator": "lt", "value": 30},
    },
    "complexity_enabled": {
        "data_type": "string",
        "rule": {
            "operator": "any",
            "rules": [
                {"operator": "eq", "value": "TRUE"},
                {"operator": "eq", "value": "YES"},
            ],
        },
    },
}

DEFAULT_DNS_SOA_CAP_MAP: Dict[str, str] = {
    "serial": "Update to match the 'YYYYMMDDnn' scheme",
    "expire": "Update to a value between 1209600 to 2419200",
    "mname": "Update to a value that is an authoritative name server",
    "minimum": "Update to a value greater than 300",
    "refresh": "Update to a value between 1200 and 43200 seconds",
    "retry": "Update to a value less than or equal to half the REFRESH",
}

DEFAULT_DNS_FINDING_MAP: Dict[str, str] = {
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

DNS_IMPACT_MAP: Dict[str, str] = {
    "One or more SOA fields are outside recommended ranges": "Incorrect SOA settings can disrupt DNS propagation, caching, and zone transfers, leading to stale or inconsistent domain data.",
    "Less than 2 nameservers exist": "Having fewer than two nameservers creates a single point of failure, increasing risk of domain outage if the sole server becomes unreachable.",
    "More than 8 nameservers exist": "Excessive nameservers increase administrative complexity and the likelihood of inconsistent configurations or stale records.",
    "Some nameservers have duplicate addresses": "Duplicate nameserver IPs reduce redundancy and can lead to query failures during DNS resolution.",
    "Some nameservers did not respond": "Non-responsive nameservers degrade DNS availability and can cause intermittent domain resolution failures.",
    "Some nameservers respond recursive queries": "Allowing recursion on authoritative servers exposes them to cache poisoning and amplification attacks.",
    "Some nameservers do not respond to TCP queries": "Failure to handle TCP queries can break large DNS responses (e.g., DNSSEC), reducing reliability and availability.",
    "Some nameservers return version numbers": "Exposing version information allows attackers to identify and exploit known vulnerabilities in the DNS software.",
    "Some nameservers provide a differing list of nameservers": "Inconsistent NS records cause DNS resolution instability and may enable spoofing or cache corruption.",
    "Some nameserver addresses are private": "Private IP addresses make external resolution impossible and indicate misconfigured or non-routable infrastructure.",
    "Some nameservers do not provide a SOA record for the zone": "Missing SOA records prevent proper zone management and replication, causing inconsistencies between servers.",
    "Some nameserver SOAs have differing serial numbers": "Mismatched SOA serials suggest replication issues that can result in outdated or inconsistent zone data.",
    "No MX records exist within the zone": "Without MX records, the domain cannot receive email, potentially disrupting communication or business operations.",
    "Only one MX record exists within the zone": "A single MX record creates a single point of failure for mail delivery, reducing availability and redundancy.",
    "MX record resolves to a single IP address": "A single IP for mail delivery increases the likelihood of downtime or delivery failure if that host becomes unavailable.",
    "Some addresses referenced by MX records do not have matching reverse DNS entries": "Missing PTR records can cause mail rejection by spam filters and lower sender reputation.",
    "Some mailserver IP addresses are private": "Private IPs on mailservers prevent delivery from external networks and indicate improper public DNS configuration.",
    "Some connections to Mailservers port 25 failed": "Unreachable mailservers degrade or halt inbound email delivery, impacting availability and communication.",
    "Some mailservers appear to be open relays": "Open relays allow unauthorized third parties to send spam, risking blacklisting and abuse of the domain.",
    "This domain does not have DNSSEC records": "Without DNSSEC, DNS responses can be forged, enabling cache poisoning and redirection attacks.",
    "The DNSKEY does not appear to be valid for the domain": "Invalid DNSSEC keys undermine trust and cause validation failures for secure resolvers.",
    "The domain does not have an SPF record": "Lack of SPF allows attackers to spoof emails from the domain, enabling phishing or spam campaigns.",
    "The SPF value does not allow mail delivery from all mailservers in the domain": "An incomplete SPF record causes legitimate emails to be rejected or marked as spam.",
    "The SPF record contains the overly permissive modifier '+all'": "The '+all' modifier allows any host to send mail for the domain, enabling spoofing and abuse.",
}


def _load_mapping(
    model_name: str,
    value_field: str,
    default_map: Dict[str, str],
    *,
    key_field: str = "issue_text",
) -> Dict[str, str]:
    """Return mappings from the database, falling back to defaults."""

    try:
        model = apps.get_model("rolodex", model_name)
    except LookupError:
        return default_map

    try:
        values = model.objects.all().values_list(key_field, value_field)
    except (OperationalError, ProgrammingError):  # pragma: no cover - defensive guard
        return default_map

    mapping = {issue: text for issue, text in values if issue}
    return mapping or default_map


def _default_general_cap_map() -> Dict[str, Dict[str, Any]]:
    """Return a sanitized copy of the default general CAP mapping."""

    return {
        issue: {"recommendation": recommendation, "score": score}
        for issue, (recommendation, score) in DEFAULT_GENERAL_CAP_MAP.items()
    }


def load_general_cap_map() -> Dict[str, Dict[str, Any]]:
    """Return general CAP mappings from the database or fall back to defaults."""

    try:
        model = apps.get_model("rolodex", "GeneralCapMapping")
    except LookupError:
        return _default_general_cap_map()

    try:
        entries = model.objects.all().values(
            "issue_text", "recommendation_text", "score"
        )
    except (OperationalError, ProgrammingError):  # pragma: no cover - defensive guard
        return _default_general_cap_map()

    mapping: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        issue = entry.get("issue_text")
        if not issue:
            continue
        mapping[issue] = {
            "recommendation": entry.get("recommendation_text", ""),
            "score": entry.get("score"),
        }

    return mapping or _default_general_cap_map()


def load_dns_soa_cap_map() -> Dict[str, str]:
    """Return SOA field CAP mappings from the database or fall back to defaults."""

    return _load_mapping(
        "DNSSOACapMapping",
        "cap_text",
        DEFAULT_DNS_SOA_CAP_MAP,
        key_field="soa_field",
    )


def load_password_cap_map() -> Dict[str, str]:
    """Return password policy CAP mappings from the database or fall back to defaults."""

    return _load_mapping(
        "PasswordCapMapping",
        "cap_text",
        DEFAULT_PASSWORD_CAP_MAP,
        key_field="setting",
    )


def _default_password_compliance_matrix() -> Dict[str, Dict[str, Any]]:
    """Return a sanitized copy of the default password compliance matrix."""

    return {
        setting: {
            "data_type": str(definition.get("data_type", "numeric")).lower()
            if isinstance(definition, dict)
            else "numeric",
            "rule": definition.get("rule", {}) if isinstance(definition, dict) else {},
        }
        for setting, definition in DEFAULT_PASSWORD_COMPLIANCE_MATRIX.items()
    }


def load_password_compliance_matrix() -> Dict[str, Dict[str, Any]]:
    """Return password compliance rules from the database or fall back to defaults."""

    try:
        model = apps.get_model("reporting", "PasswordComplianceMapping")
    except LookupError:
        return _default_password_compliance_matrix()

    try:
        entries = model.objects.all().values("setting", "data_type", "rule")
    except (OperationalError, ProgrammingError):  # pragma: no cover - defensive guard
        return _default_password_compliance_matrix()

    matrix: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        setting = entry.get("setting")
        if not setting:
            continue
        data_type = str(entry.get("data_type", "numeric") or "numeric").lower()
        if data_type not in {"numeric", "string"}:
            data_type = "numeric"
        rule = entry.get("rule") if isinstance(entry.get("rule"), (dict, list)) else {}
        matrix[setting] = {"data_type": data_type, "rule": rule}

    return matrix or _default_password_compliance_matrix()


AD_RISK_CONTRIBUTION_PHRASES: Dict[str, str] = {
    "domain_admins": "the number of Domain Admin accounts",
    "enterprise_admins": "the number of Enterprise Admin accounts",
    "expired_passwords": "the number of accounts with expired passwords",
    "passwords_never_expire": "the number of accounts set with passwords that never expire",
    "inactive_accounts": "the number of potentially inactive accounts",
    "generic_accounts": "the number of potentially generic accounts",
    "generic_logins": "the number of generic accounts logged into systems",
    "old_passwords": "the number of accounts with 'old' passwords",
    "disabled_accounts": "the number of disabled accounts",
}


def _get_nested_value(data: Any, path: Iterable[str]) -> Any:
    """Safely fetch a nested value from ``data`` using ``path`` of keys."""

    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def build_ad_risk_contrib(
    workbook_data: Optional[Dict[str, Any]],
    entries: Optional[Iterable[Dict[str, Any]]],
) -> List[str]:
    """Return risk contribution phrases derived from AD response entries."""

    source_data: Dict[str, Any] = workbook_data if isinstance(workbook_data, dict) else {}

    risk_value = _get_nested_value(
        source_data,
        ("external_internal_grades", "internal", "iam", "risk"),
    )
    risk_text = str(risk_value).strip().lower() if risk_value is not None else ""
    if risk_text not in ("medium", "high"):
        return []

    allowed_values = {"high", "medium"} if risk_text == "medium" else {"high"}

    if isinstance(entries, dict):
        candidate = entries.get("entries")
        if isinstance(candidate, (list, tuple)):
            potential_entries: Iterable[Dict[str, Any]] = candidate
        else:
            potential_entries = []
    elif isinstance(entries, (list, tuple)):
        potential_entries = entries
    elif isinstance(entries, abc.Iterable) and not isinstance(entries, (str, bytes)):
        potential_entries = entries
    else:
        potential_entries = []

    matched_metrics = set()
    for entry in potential_entries:
        if not isinstance(entry, dict):
            continue
        for metric_key in AD_RISK_CONTRIBUTION_PHRASES:
            value = entry.get(metric_key)
            if value is None:
                continue
            text = str(value).strip().lower()
            if text in allowed_values:
                matched_metrics.add(metric_key)

    if not matched_metrics:
        return []

    ordered_metrics = [
        metric_key
        for metric_key, _ in AD_DOMAIN_METRICS
        if metric_key in matched_metrics
    ]

    return [AD_RISK_CONTRIBUTION_PHRASES[key] for key in ordered_metrics]


def _decode_file(file_obj: File) -> Iterable[Dict[str, str]]:
    """Return a DictReader for the provided file object."""

    file_obj.open("rb")
    try:
        raw_bytes = file_obj.read() or b""
    finally:
        file_obj.close()

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = raw_bytes.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw_bytes.decode("utf-8", errors="ignore")

    stream = io.StringIO(text)
    return csv.DictReader(stream)


def _parse_ip_list(file_obj: File) -> List[str]:
    """Parse a newline-delimited text file into a list of IP entries."""

    file_obj.open("rb")
    try:
        raw_bytes = file_obj.read() or b""
    finally:
        file_obj.close()

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("utf-8", errors="ignore")

    return parse_ip_text(text)


FIREWALL_REPORT_FIELD_SPECS: Tuple[Tuple[str, str], ...] = (
    ("risk", "Risk"),
    ("issue", "Issue"),
    ("devices", "Devices"),
    ("solution", "Solution"),
    ("impact", "Impact"),
    ("details", "Details"),
    ("reference", "Reference"),
    ("accepted", "Accepted"),
    ("type", "Type"),
)


def _get_case_insensitive(row: Dict[str, Any], key: str) -> Any:
    """Return the value for ``key`` in ``row`` using case-insensitive matching."""

    if key in row:
        return row[key]
    lowered = key.lower()
    for candidate_key, value in row.items():
        if candidate_key.lower() == lowered:
            return value
    return ""


def _parse_firewall_score(raw_value: Any) -> Optional[float]:
    """Convert the provided value into a floating point score if possible."""

    text = str(raw_value).strip() if raw_value is not None else ""
    if not text:
        return None
    normalized = text.replace(",", "")
    try:
        return float(normalized)
    except (TypeError, ValueError):  # pragma: no cover - defensive guard
        return None


def _parse_severity_level(raw_value: Any) -> Optional[float]:
    """Normalize a Nexpose severity level value to a floating point score."""

    text = str(raw_value).strip() if raw_value is not None else ""
    if not text:
        return None
    try:
        return float(text)
    except (TypeError, ValueError):
        upper_text = text.upper()
        if upper_text == "HIGH":
            return 9.0
        if upper_text == "MEDIUM":
            return 6.0
        if upper_text == "LOW":
            return 2.0
    return None


def _categorize_severity(score: Optional[float]) -> Optional[str]:
    """Return the severity bucket for the provided Nexpose score."""

    if score is None:
        return None
    if score >= 8:
        return "High"
    if score >= 4:
        return "Medium"
    if score >= 0:
        return "Low"
    return None


def _coerce_int(value: Any) -> Optional[int]:
    """Best-effort conversion of ``value`` to ``int`` or ``None`` if conversion fails."""

    if value is None:
        return None

    if isinstance(value, int):
        return value

    text = str(value).strip()
    if not text:
        return None

    normalized = text.replace(",", "")
    try:
        return int(normalized)
    except (TypeError, ValueError):
        try:
            return int(float(normalized))
        except (TypeError, ValueError):
            return None


def _normalize_policy_string(value: Any) -> str:
    """Return a normalized string representation for password policy values."""

    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip().upper()
    return str(value).strip().upper()


def _evaluate_compliance_rule(rule: Any, value: Any, data_type: str) -> bool:
    """Evaluate a compliance rule against ``value`` using the provided ``data_type``."""

    if isinstance(rule, list):
        return any(_evaluate_compliance_rule(entry, value, data_type) for entry in rule)

    if not isinstance(rule, dict):
        return False

    operator = str(rule.get("operator", "")).lower()

    if operator in {"any", "or"}:
        sub_rules = rule.get("rules") or rule.get("conditions") or []
        return any(
            _evaluate_compliance_rule(sub_rule, value, data_type)
            for sub_rule in sub_rules
            if isinstance(sub_rule, (dict, list))
        )

    if operator in {"all", "and"}:
        sub_rules = rule.get("rules") or rule.get("conditions") or []
        relevant = [
            sub_rule
            for sub_rule in sub_rules
            if isinstance(sub_rule, (dict, list))
        ]
        if not relevant:
            return False
        return all(
            _evaluate_compliance_rule(sub_rule, value, data_type)
            for sub_rule in relevant
        )

    if value is None:
        return False

    if data_type == "numeric":
        try:
            numeric_value = float(value)
            comparator = float(rule.get("value"))
        except (TypeError, ValueError):
            return False

        if operator in {"lt", "<"}:
            return numeric_value < comparator
        if operator in {"lte", "<="}:
            return numeric_value <= comparator
        if operator in {"gt", ">"}:
            return numeric_value > comparator
        if operator in {"gte", ">="}:
            return numeric_value >= comparator
        if operator in {"eq", "=="}:
            return numeric_value == comparator
        if operator in {"ne", "!=", "<>"}:
            return numeric_value != comparator
        return False

    normalized_value = _normalize_policy_string(value)
    comparator_text = _normalize_policy_string(rule.get("value"))

    if operator in {"eq", "=="}:
        return normalized_value == comparator_text
    if operator in {"ne", "!=", "<>"}:
        return normalized_value != comparator_text

    return False


def _calculate_percentage(numerator: Optional[int], denominator: Optional[int]) -> Optional[float]:
    """Return ``numerator`` / ``denominator`` as a percentage rounded to one decimal place."""

    if numerator is None or denominator in (None, 0):
        return None

    return round((numerator / denominator) * 100, 1)


def parse_firewall_report(file_obj: File) -> List[Dict[str, Any]]:
    """Parse a firewall_csv.csv export into normalized issue entries."""

    findings: List[Dict[str, Any]] = []
    for row in _decode_file(file_obj):
        normalized_entry: Dict[str, Any] = {}
        has_content = False

        for field_key, header in FIREWALL_REPORT_FIELD_SPECS:
            value = _get_case_insensitive(row, header)
            text_value = str(value).strip() if value is not None else ""
            normalized_entry[field_key] = text_value
            if text_value:
                has_content = True

        score_value = _parse_firewall_score(_get_case_insensitive(row, "Score"))
        normalized_entry["score"] = score_value
        if score_value is not None:
            has_content = True

        if has_content:
            findings.append(normalized_entry)

    return findings


def _normalize_firewall_risk(value: str) -> Optional[str]:
    """Map textual firewall risk levels to ``high``/``med``/``low`` buckets."""

    if not value:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    if normalized.startswith("crit") or normalized.startswith("high"):
        return "high"
    if normalized.startswith("med") or normalized.startswith("moder"):
        return "med"
    if normalized.startswith("low"):
        return "low"
    return None


_SENTENCE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+")


def _first_sentence(value: str) -> str:
    """Return the first sentence from the provided ``value`` string."""

    text = (value or "").strip()
    if not text:
        return ""

    normalized = " ".join(text.split())
    parts = _SENTENCE_BOUNDARY_RE.split(normalized, maxsplit=1)
    return parts[0].strip()


def _summarize_firewall_vulnerabilities(
    findings: Iterable[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Aggregate firewall findings into severity summaries."""

    severity_counters: Dict[str, Counter[Tuple[str, str]]] = {
        "high": Counter(),
        "med": Counter(),
        "low": Counter(),
    }

    for entry in findings:
        if not isinstance(entry, dict):
            continue

        risk_value = _normalize_firewall_risk(str(entry.get("risk") or ""))
        if not risk_value:
            continue

        issue_text = (entry.get("issue") or "").strip()
        impact_text = _first_sentence(entry.get("impact") or "")

        if not issue_text and not impact_text:
            continue

        severity_counters[risk_value][(issue_text, impact_text)] += 1

    summaries: Dict[str, Dict[str, Any]] = {}
    for severity, counter in severity_counters.items():
        sorted_items = sorted(
            counter.items(),
            key=lambda item: (
                -item[1],
                item[0][0].lower(),
                item[0][1].lower(),
            ),
        )
        top_items = [
            {"issue": issue, "impact": impact, "count": count}
            for (issue, impact), count in sorted_items[:5]
        ]
        summaries[severity] = {
            "total_unique": len(counter),
            "items": top_items,
        }

    return summaries


def parse_dns_report(file_obj: File) -> List[Dict[str, str]]:
    """Parse a dns_report.csv file, returning issue metadata for failed checks."""

    finding_map = _load_mapping(
        "DNSFindingMapping",
        "finding_text",
        DEFAULT_DNS_FINDING_MAP,
    )
    recommendation_map = _load_mapping(
        "DNSRecommendationMapping",
        "recommendation_text",
        DEFAULT_DNS_RECOMMENDATION_MAP,
    )
    cap_map = _load_mapping(
        "DNSCapMapping",
        "cap_text",
        DEFAULT_DNS_CAP_MAP,
    )

    issues: List[Dict[str, str]] = []
    for row in _decode_file(file_obj):
        status = (row.get("Status") or row.get("status") or "").strip().upper()
        if status != "FAIL":
            continue
        info = (row.get("Info") or row.get("info") or "").strip()
        if not info:
            continue
        issue_text = info.splitlines()[0].strip()
        if not issue_text:
            continue
        finding = finding_map.get(issue_text, "")
        recommendation = recommendation_map.get(issue_text, "")
        cap = cap_map.get(issue_text, "")
        impact = DNS_IMPACT_MAP.get(issue_text, "")
        issues.append(
            {
                "issue": issue_text,
                "finding": finding,
                "recommendation": recommendation,
                "cap": cap,
                "impact": impact,
            }
        )
    return issues


class _SeverityItemsAccessor:
    """Provide dual behaviour for severity ``items`` access."""

    __slots__ = ("_data",)

    def __init__(self, data: "_SeverityGroup") -> None:
        self._data = data

    def __call__(self, *args, **kwargs):  # pragma: no cover - compatibility shim
        return dict.items(self._data, *args, **kwargs)

    def __iter__(self):
        return iter(dict.get(self._data, "items", []))

    def __len__(self):  # pragma: no cover - defensive guard
        return len(dict.get(self._data, "items", []))

    def __bool__(self):
        return bool(dict.get(self._data, "items", []))

    def __repr__(self):  # pragma: no cover - used for debugging
        return repr(dict.get(self._data, "items", []))


class _SeverityGroup(dict):
    """Dictionary subclass exposing list-like ``items`` attribute access."""

    __slots__ = ()

    def __getattribute__(self, name):
        if name == "items":
            return _SeverityItemsAccessor(self)
        return dict.__getattribute__(self, name)


def _coerce_severity_group(value: Any) -> _SeverityGroup:
    """Normalize a severity mapping into a ``_SeverityGroup`` instance."""

    if isinstance(value, _SeverityGroup):
        return value
    total_unique = 0
    items: List[Dict[str, Any]] = []
    if isinstance(value, dict):
        raw_total = value.get("total_unique", 0)
        try:
            total_unique = int(raw_total)
        except (TypeError, ValueError):  # pragma: no cover - defensive guard
            total_unique = 0
        raw_items = value.get("items", [])
        if isinstance(raw_items, list):
            items = list(raw_items)
        elif raw_items:  # pragma: no cover - defensive guard
            items = list(raw_items)
    return _SeverityGroup(total_unique=total_unique, items=items)


def _empty_severity_group() -> _SeverityGroup:
    """Return a severity group with zero findings."""

    return _SeverityGroup(total_unique=0, items=[])


def _default_nexpose_artifact(label: str) -> Dict[str, Any]:
    """Return a default Nexpose artifact payload for the provided label."""

    return {
        "label": label,
        "high": _empty_severity_group(),
        "med": _empty_severity_group(),
        "low": _empty_severity_group(),
    }


def normalize_nexpose_artifact_payload(payload: Any) -> Dict[str, Any]:
    """Return a copy of ``payload`` with severity buckets wrapped for templates."""

    if not isinstance(payload, dict):
        return payload
    normalized: Dict[str, Any] = dict(payload)
    for severity_key in ("high", "med", "low"):
        if severity_key in normalized:
            normalized[severity_key] = _coerce_severity_group(normalized[severity_key])
    return normalized


def _normalize_web_site_payload(payload: Any, site_name: Optional[str] = None) -> Any:
    """Normalize a single web issue site payload for template access."""

    if not isinstance(payload, dict):
        return payload

    normalized: Dict[str, Any] = dict(payload)
    if site_name and not normalized.get("site"):
        normalized["site"] = site_name

    for severity_key in ("high", "med", "low"):
        normalized[severity_key] = _coerce_severity_group(normalized.get(severity_key, {}))

    return normalized


def _coerce_web_issue_summary(value: Any) -> Dict[str, Any]:
    """Return a normalized mapping of aggregate web issue severities."""

    low_sample_string = ""
    med_sample_string = ""
    severity_groups = {
        key: _coerce_severity_group({}) for key in ("high", "med", "low")
    }

    if isinstance(value, dict):
        low_sample_string = str(value.get("low_sample_string") or "")
        med_sample_string = str(value.get("med_sample_string") or "")
        has_explicit_summary = False

        for severity_key in ("high", "med", "low"):
            if severity_key in value:
                severity_groups[severity_key] = _coerce_severity_group(
                    value.get(severity_key, {})
                )
                has_explicit_summary = True

        if has_explicit_summary:
            return {
                "low_sample_string": low_sample_string,
                "med_sample_string": med_sample_string,
                **severity_groups,
            }

        raw_sites = value.get("sites")
        if isinstance(raw_sites, list):
            site_entries = [
                _normalize_web_site_payload(site_payload)
                for site_payload in raw_sites
                if isinstance(site_payload, dict)
            ]
        else:
            site_entries = [
                _normalize_web_site_payload(site_payload, site)
                for site, site_payload in sorted(
                    value.items(), key=lambda item: (item[0] or "").lower()
                )
                if site
                not in {"low_sample_string", "med_sample_string", "high", "med", "low"}
                and isinstance(site_payload, dict)
            ]
    elif isinstance(value, list):
        site_entries = [
            _normalize_web_site_payload(site_payload)
            for site_payload in value
            if isinstance(site_payload, dict)
        ]
    else:
        site_entries = []

    if site_entries:
        aggregated: Dict[str, Counter[Tuple[str, str]]] = {
            "high": Counter(),
            "med": Counter(),
            "low": Counter(),
        }
        fallback_totals = {"high": 0, "med": 0, "low": 0}
        for site_payload in site_entries:
            for severity_key in ("high", "med", "low"):
                group = _coerce_severity_group(site_payload.get(severity_key, {}))
                total_unique = group.get("total_unique")
                try:
                    total_value = int(total_unique)
                except (TypeError, ValueError):  # pragma: no cover - defensive guard
                    total_value = 0
                fallback_totals[severity_key] = max(
                    fallback_totals[severity_key], max(total_value, 0)
                )
                for item in group.get("items", []):
                    issue = str(item.get("issue", "") or "").strip()
                    impact = str(item.get("impact", "") or "").strip()
                    count = item.get("count", 1)
                    try:
                        count_value = int(count)
                    except (TypeError, ValueError):  # pragma: no cover - defensive guard
                        count_value = 1
                    aggregated[severity_key][(issue, impact)] += max(count_value, 0)
        severity_groups = {
            severity_key: _summarize_severity_counter(counter)
            for severity_key, counter in aggregated.items()
        }
        for severity_key, fallback_total in fallback_totals.items():
            group = severity_groups.get(severity_key)
            if group.get("total_unique", 0) or not fallback_total:
                continue
            group["total_unique"] = fallback_total

    return {
        "low_sample_string": low_sample_string,
        "med_sample_string": med_sample_string,
        **severity_groups,
    }


def normalize_nexpose_artifacts_map(artifacts: Any) -> Any:
    """Normalize Nexpose and web issue artifact entries for template access."""

    if not isinstance(artifacts, dict):
        return artifacts
    normalized: Dict[str, Any] = dict(artifacts)

    for legacy_key, new_key in LEGACY_NEXPOSE_ARTIFACT_ALIASES.items():
        if legacy_key not in normalized:
            continue
        if new_key not in normalized:
            normalized[new_key] = normalized[legacy_key]
        normalized.pop(legacy_key, None)

    for key, value in list(normalized.items()):
        if isinstance(key, str) and key.endswith("_nexpose_vulnerabilities"):
            normalized[key] = normalize_nexpose_artifact_payload(value)
        elif key == "web_issues":
            normalized[key] = _coerce_web_issue_summary(value)
    return normalized


def parse_nexpose_vulnerability_report(file_obj: File) -> Dict[str, Dict[str, Any]]:
    """Parse a Nexpose CSV export into grouped vulnerability summaries."""

    grouped: Dict[str, Counter] = {
        "High": Counter(),
        "Medium": Counter(),
        "Low": Counter(),
    }

    for row in _decode_file(file_obj):
        severity_value = _parse_severity_level(
            _get_case_insensitive(row, "Vulnerability Severity Level")
        )
        severity_bucket = _categorize_severity(severity_value)
        if not severity_bucket:
            continue

        title = str(_get_case_insensitive(row, "Vulnerability Title") or "").strip()
        impact = str(_get_case_insensitive(row, "Impact") or "").strip()
        if not title and not impact:
            continue

        grouped[severity_bucket][(title, impact)] += 1

    summaries: Dict[str, Dict[str, Any]] = {}
    severity_map = {
        "High": "high",
        "Medium": "med",
        "Low": "low",
    }

    for severity in ("High", "Medium", "Low"):
        counter = grouped.get(severity, Counter())
        ordered = sorted(
            counter.items(),
            key=lambda item: (
                -item[1],
                (item[0][0] or "").lower(),
                (item[0][1] or "").lower(),
            ),
        )
        items: List[Dict[str, Any]] = []
        for (title, impact), count in ordered[:5]:
            items.append({"title": title, "impact": impact, "count": count})

        summaries[severity_map[severity]] = _SeverityGroup(
            total_unique=len(counter),
            items=items,
        )

    return summaries


NEXPOSE_ARTIFACT_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "external_nexpose_csv.csv": {
        "artifact_key": "external_nexpose_vulnerabilities",
        "label": "External Nexpose Vulnerabilities",
    },
    "internal_nexpose_csv.csv": {
        "artifact_key": "internal_nexpose_vulnerabilities",
        "label": "Internal Nexpose Vulnerabilities",
    },
    "iot_nexpose_csv.csv": {
        "artifact_key": "iot_iomt_nexpose_vulnerabilities",
        "label": "IoT/IoMT Nexpose Vulnerabilities",
    },
}

LEGACY_NEXPOSE_ARTIFACT_ALIASES: Dict[str, str] = {
    "iot_nexpose_vulnerabilities": "iot_iomt_nexpose_vulnerabilities",
}

NEXPOSE_ARTIFACT_KEYS = {
    definition["artifact_key"] for definition in NEXPOSE_ARTIFACT_DEFINITIONS.values()
}.union(LEGACY_NEXPOSE_ARTIFACT_ALIASES.keys())


def _categorize_web_risk(raw_value: str) -> Optional[str]:
    """Return the severity bucket for a Burp risk string."""

    text = (raw_value or "").strip()
    if not text:
        return None

    normalized = text.upper().replace("-", " ")
    if "(" in normalized:
        normalized = normalized.split("(", 1)[0]
    normalized = normalized.strip()

    if normalized in {"CRITICAL", "HIGH"}:
        return "high"
    if normalized in {"MEDIUM", "MODERATE"}:
        return "med"
    if normalized in {"LOW", "INFO", "INFORMATION", "INFORMATIONAL"}:
        return "low"

    try:
        score = float(text)
    except (TypeError, ValueError):  # pragma: no cover - defensive guard
        return None

    if score >= 8:
        return "high"
    if score >= 4:
        return "med"
    if score >= 0:
        return "low"
    return None


def _summarize_severity_counter(counter: Counter[Tuple[str, str]]) -> _SeverityGroup:
    """Convert a counter of issue/impact pairs into a severity summary."""

    ordered = sorted(
        counter.items(),
        key=lambda item: (
            -item[1],
            (item[0][0] or "").lower(),
            (item[0][1] or "").lower(),
        ),
    )
    items: List[Dict[str, Any]] = []
    for (issue, impact), count in ordered[:5]:
        items.append({"issue": issue, "impact": impact, "count": count})

    return _SeverityGroup(total_unique=len(counter), items=items)


def _clean_impact_sample(raw_value: Any) -> str:
    """Return an impact sample with helper phrases removed."""

    text = str(raw_value or "").strip()
    lowered = text.lower()
    for prefix in ("this may", "this can"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :].lstrip(" \t-:,;")
            break
    return text


def _select_top_samples(counter: Counter[str]) -> List[str]:
    """Return up to three samples ordered by descending frequency then alphabetically."""

    ordered = sorted(
        (
            (sample, count)
            for sample, count in counter.items()
            if sample
        ),
        key=lambda item: (-item[1], item[0].lower()),
    )
    return [sample for sample, _count in ordered[:3]]


def _format_sample_string(samples: List[str]) -> str:
    """Return a grammatically correct representation of the provided samples."""

    samples = [sample for sample in samples if sample]
    if not samples:
        return ""
    quoted = [f"'{sample}'" for sample in samples]
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} and {quoted[1]}"
    return ", ".join(quoted[:-1]) + f" and {quoted[-1]}"


def _format_slash_separated_string(values: Iterable[str]) -> str:
    """Return a slash-delimited string of single-quoted values."""

    entries = [str(value).strip() for value in values if str(value).strip()]
    if not entries:
        return ""
    quoted = [f"'{entry}'" for entry in entries]
    return "/".join(quoted)


def _format_oxford_quoted_list(values: List[str]) -> str:
    """Return a quoted list that includes an Oxford comma when needed."""

    entries = [str(value).strip() for value in values if str(value).strip()]
    if not entries:
        return ""
    quoted = [f"'{entry}'" for entry in entries]
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} and {quoted[1]}"
    return ", ".join(quoted[:-1]) + f", and {quoted[-1]}"


def _format_plain_list(values: List[str]) -> str:
    """Return a human-readable string for a list of pre-formatted values."""

    entries = [value for value in values if value]
    if not entries:
        return ""
    if len(entries) == 1:
        return entries[0]
    if len(entries) == 2:
        return f"{entries[0]} and {entries[1]}"
    return ", ".join(entries[:-1]) + f" and {entries[-1]}"


def summarize_password_cap_details(
    domain_values: Dict[str, Dict[str, Any]]
) -> Tuple[List[str], Dict[str, Any]]:
    """Return ordered password CAP fields and associated context values."""

    unique_fields: List[str] = []
    seen_fields: Set[str] = set()
    context: Dict[str, Any] = {}

    for domain, values in domain_values.items():
        if not isinstance(values, dict):
            continue

        domain_context: Dict[str, Any] = {}

        policy_fields = values.get("policy_cap_fields")
        policy_values = values.get("policy_cap_values")
        if isinstance(policy_fields, list) and policy_fields:
            policy_context: Dict[str, Any] = {}
            for field in policy_fields:
                if field not in seen_fields:
                    seen_fields.add(field)
                    unique_fields.append(field)
                field_value = (
                    policy_values.get(field)
                    if isinstance(policy_values, dict)
                    else None
                )
                policy_context[field] = field_value
            if policy_context:
                domain_context["policy"] = policy_context

        fgpp_fields = values.get("fgpp_cap_fields")
        fgpp_values = values.get("fgpp_cap_values")
        if isinstance(fgpp_fields, dict) and fgpp_fields:
            fgpp_context: Dict[str, Dict[str, Any]] = {}
            for name, field_list in fgpp_fields.items():
                if not isinstance(field_list, list) or not field_list:
                    continue
                per_policy_context: Dict[str, Any] = {}
                for field in field_list:
                    if field not in seen_fields:
                        seen_fields.add(field)
                        unique_fields.append(field)
                    value_map = (
                        fgpp_values.get(name)
                        if isinstance(fgpp_values, dict)
                        else None
                    )
                    per_policy_context[field] = (
                        value_map.get(field) if isinstance(value_map, dict) else None
                    )
                if per_policy_context:
                    fgpp_context[name] = per_policy_context
            if fgpp_context:
                domain_context["fgpp"] = fgpp_context

        if domain_context:
            context[domain] = domain_context

    return unique_fields, context


def _stringify_cap_value(value: Any) -> str:
    """Return a string representation suitable for CAP placeholder substitution."""

    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _render_cap_template(template: str, values: Dict[str, Any]) -> str:
    """Render ``template`` by replacing ``{{ key }}`` placeholders with ``values``."""

    if not template:
        return ""

    def _replace(match: "re.Match[str]") -> str:
        key = match.group(1)
        for candidate in (key, key.lower(), key.upper()):
            if candidate in values:
                return _stringify_cap_value(values[candidate])
        return ""

    return _CAP_PLACEHOLDER_PATTERN.sub(_replace, template)


def build_password_cap_display_map(
    context: Dict[str, Any], template_map: Dict[str, str]
) -> Dict[str, Any]:
    """Return domain-scoped CAP guidance using ``template_map`` and ``context`` values."""

    domain_map: Dict[str, Any] = {}

    for domain, domain_context in context.items():
        if not isinstance(domain_context, dict):
            continue

        domain_entry: Dict[str, Any] = {}

        policy_values = domain_context.get("policy")
        if isinstance(policy_values, dict) and policy_values:
            policy_map: Dict[str, str] = {}
            for field, value in policy_values.items():
                template = template_map.get(field, "")
                replacements = {
                    field: value,
                    field.lower(): value,
                    field.upper(): value,
                }
                policy_map[field] = _render_cap_template(template, replacements)
            if policy_map:
                domain_entry["policy"] = {"score": 4, **policy_map}

        fgpp_values = domain_context.get("fgpp")
        if isinstance(fgpp_values, dict) and fgpp_values:
            fgpp_map: Dict[str, Dict[str, str]] = {}
            for name, fgpp_field_values in fgpp_values.items():
                if not isinstance(fgpp_field_values, dict) or not fgpp_field_values:
                    continue
                per_policy_map: Dict[str, str] = {}
                for field, value in fgpp_field_values.items():
                    template = template_map.get(field, "")
                    replacements = {
                        field: value,
                        field.lower(): value,
                        field.upper(): value,
                    }
                    per_policy_map[field] = _render_cap_template(template, replacements)
                if per_policy_map:
                    fgpp_map[name] = {"score": 4, **per_policy_map}
            if fgpp_map:
                domain_entry["fgpp"] = fgpp_map

        if domain_entry:
            domain_map[domain] = domain_entry

    return domain_map


def _format_integer_value(value: Optional[int]) -> str:
    """Normalize integer-like values to strings while preserving zeroes."""

    if value in (None, ""):
        return "0"
    return str(value)


def _format_percentage_text(value: Optional[float]) -> str:
    """Render a percentage value with up to one decimal place."""

    if value is None:
        return "0%"

    text = f"{value:.1f}".rstrip("0").rstrip(".")
    return f"{text}%"


def parse_web_report(file_obj: File) -> Dict[str, Dict[str, Counter[Tuple[str, str]]]]:
    """Parse a burp.csv export into counters grouped by site and severity bucket."""

    results: Dict[str, Dict[str, Counter[Tuple[str, str]]]] = {}
    for row in _decode_file(file_obj):
        host = (row.get("Host") or row.get("host") or "").strip() or "Unknown Site"
        risk_raw = (row.get("Risk") or row.get("risk") or "").strip()
        severity_bucket = _categorize_web_risk(risk_raw)
        if not severity_bucket:
            continue

        issue = (row.get("Issue") or row.get("issue") or "").strip()
        impact = (row.get("Impact") or row.get("impact") or "").strip()
        if not issue and not impact:
            continue

        host_entry = results.setdefault(host, {})
        counter = host_entry.setdefault(severity_bucket, Counter())
        counter[(issue, impact)] += 1

    return results


def build_project_artifacts(project: "Project") -> Dict[str, Any]:
    """Aggregate parsed artifacts for the provided project."""

    artifacts: Dict[str, Any] = {}
    dns_results: Dict[str, List[Dict[str, str]]] = {}
    web_results: Dict[str, Dict[str, Counter[Tuple[str, str]]]] = {}
    ip_results: Dict[str, List[str]] = {
        definition.artifact_key: [] for definition in IP_ARTIFACT_DEFINITIONS.values()
    }

    firewall_results: List[Dict[str, Any]] = []
    nexpose_definitions_by_key: Dict[str, str] = {
        definition["artifact_key"]: definition["label"]
        for definition in NEXPOSE_ARTIFACT_DEFINITIONS.values()
    }
    nexpose_results: Dict[str, Dict[str, Any]] = {
        artifact_key: _default_nexpose_artifact(label)
        for artifact_key, label in nexpose_definitions_by_key.items()
    }

    for data_file in project.data_files.all():
        label = (data_file.requirement_label or "").strip().lower()
        if label == "dns_report.csv":
            domain = (data_file.requirement_context or data_file.description or data_file.filename).strip()
            domain = domain or "Unknown Domain"
            parsed_dns = parse_dns_report(data_file.file)
            if parsed_dns:
                dns_results.setdefault(domain, []).extend(parsed_dns)
        elif label in {"burp.csv", "burp_csv.csv"}:
            parsed_web = parse_web_report(data_file.file)
            for site, severity_map in parsed_web.items():
                combined_risks = web_results.setdefault(site, {})
                for severity_key, counter in severity_map.items():
                    if not counter:
                        continue
                    combined_counter = combined_risks.setdefault(severity_key, Counter())
                    combined_counter.update(counter)
        elif label == "firewall_csv.csv":
            parsed_firewall = parse_firewall_report(data_file.file)
            if parsed_firewall:
                firewall_results.extend(parsed_firewall)
        elif label in NEXPOSE_ARTIFACT_DEFINITIONS:
            parsed_vulnerabilities = parse_nexpose_vulnerability_report(data_file.file)
            if any(details.get("items") for details in parsed_vulnerabilities.values()):
                definition = NEXPOSE_ARTIFACT_DEFINITIONS[label]
                artifact_key = definition["artifact_key"]
                nexpose_results[artifact_key] = {
                    "label": definition["label"],
                    **parsed_vulnerabilities,
                }
        else:
            requirement_slug = (data_file.requirement_slug or "").strip()
            if requirement_slug:
                for definition in IP_ARTIFACT_DEFINITIONS.values():
                    if requirement_slug != definition.slug:
                        continue
                    parsed_ips = _parse_ip_list(data_file.file)
                    if not parsed_ips:
                        break
                    entries = ip_results.setdefault(definition.artifact_key, [])
                    for ip in parsed_ips:
                        if ip not in entries:
                            entries.append(ip)
                    break

    if dns_results:
        artifacts["dns_issues"] = [
            {"domain": domain, "issues": issues}
            for domain, issues in dns_results.items()
        ]

    if web_results:
        low_issue_counter: Counter[str] = Counter()
        med_impact_counter: Counter[str] = Counter()
        aggregated_severity: Dict[str, Counter[Tuple[str, str]]] = {
            "high": Counter(),
            "med": Counter(),
            "low": Counter(),
        }

        for severity_map in web_results.values():
            for severity_key in ("high", "med", "low"):
                counter = severity_map.get(severity_key, Counter())
                if not counter:
                    continue
                aggregated_severity[severity_key].update(counter)
                if severity_key == "low":
                    for (issue, _impact), count in counter.items():
                        issue_sample = (issue or "").strip()
                        if issue_sample:
                            low_issue_counter[issue_sample] += count
                elif severity_key == "med":
                    for (_issue, impact), count in counter.items():
                        impact_sample = _clean_impact_sample(impact)
                        if impact_sample:
                            med_impact_counter[impact_sample] += count

        if any(counter for counter in aggregated_severity.values()):
            severity_summaries = {
                severity_key: _summarize_severity_counter(counter)
                for severity_key, counter in aggregated_severity.items()
            }
            artifacts["web_issues"] = {
                "low_sample_string": _format_sample_string(
                    _select_top_samples(low_issue_counter)
                ),
                "med_sample_string": _format_sample_string(
                    _select_top_samples(med_impact_counter)
                ),
                **severity_summaries,
            }

    for artifact_key, values in ip_results.items():
        if values:
            artifacts[artifact_key] = values

    if firewall_results:
        artifacts["firewall_findings"] = {
            "findings": firewall_results,
            "vulnerabilities": _summarize_firewall_vulnerabilities(firewall_results),
        }

    for artifact_key, details in nexpose_results.items():
        artifacts[artifact_key] = {
            "label": details.get(
                "label", nexpose_definitions_by_key.get(artifact_key, artifact_key.replace("_", " ").title())
            ),
            "high": _coerce_severity_group(details.get("high")),
            "med": _coerce_severity_group(details.get("med")),
            "low": _coerce_severity_group(details.get("low")),
        }

    return artifacts


def build_workbook_ad_response(workbook_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate Active Directory response data sourced from workbook details."""

    if not isinstance(workbook_data, dict):
        return {}

    ad_data = workbook_data.get("ad", {})
    domains = ad_data.get("domains", []) if isinstance(ad_data, dict) else []
    if not isinstance(domains, list):
        return {}

    legacy_domains: List[str] = []
    domain_metrics: List[Dict[str, Any]] = []
    disabled_counts: List[str] = []
    disabled_percentages: List[str] = []
    old_password_counts: List[str] = []
    old_password_percentages: List[str] = []
    inactive_counts: List[str] = []
    inactive_percentages: List[str] = []
    domain_admins_counts: List[str] = []
    ent_admins_counts: List[str] = []
    exp_password_counts: List[str] = []
    never_expire_counts: List[str] = []
    generic_account_counts: List[str] = []
    generic_login_counts: List[str] = []

    for entry in domains:
        if isinstance(entry, dict):
            domain_value = entry.get("domain") or entry.get("name") or ""
            functionality_value = entry.get("functionality_level")
            total_accounts = _coerce_int(entry.get("total_accounts"))
            enabled_accounts = _coerce_int(entry.get("enabled_accounts"))
            old_passwords = _coerce_int(entry.get("old_passwords"))
            inactive_accounts = _coerce_int(entry.get("inactive_accounts"))
            domain_admins = _coerce_int(entry.get("domain_admins"))
            ent_admins = _coerce_int(entry.get("ent_admins"))
            exp_passwords = _coerce_int(entry.get("exp_passwords"))
            never_expires = _coerce_int(entry.get("passwords_never_exp"))
            generic_accounts = _coerce_int(entry.get("generic_accounts"))
            generic_logins = _coerce_int(entry.get("generic_logins"))
        else:
            domain_value = entry
            functionality_value = None
            total_accounts = None
            enabled_accounts = None
            old_passwords = None
            inactive_accounts = None
            domain_admins = None
            ent_admins = None
            exp_passwords = None
            never_expires = None
            generic_accounts = None
            generic_logins = None

        domain_text = str(domain_value).strip() if domain_value else ""
        if not domain_text:
            continue

        disabled_count: Optional[int] = None
        if total_accounts is not None and enabled_accounts is not None:
            disabled_count = max(total_accounts - enabled_accounts, 0)

        disabled_counts.append(_format_integer_value(disabled_count))
        disabled_percentages.append(
            _format_percentage_text(_calculate_percentage(disabled_count, total_accounts))
        )

        old_password_counts.append(_format_integer_value(old_passwords))
        old_password_percentages.append(
            _format_percentage_text(_calculate_percentage(old_passwords, enabled_accounts))
        )

        inactive_counts.append(_format_integer_value(inactive_accounts))
        inactive_percentages.append(
            _format_percentage_text(_calculate_percentage(inactive_accounts, enabled_accounts))
        )

        domain_admins_counts.append(_format_integer_value(domain_admins))
        ent_admins_counts.append(_format_integer_value(ent_admins))
        exp_password_counts.append(_format_integer_value(exp_passwords))
        never_expire_counts.append(_format_integer_value(never_expires))
        generic_account_counts.append(_format_integer_value(generic_accounts))
        generic_login_counts.append(_format_integer_value(generic_logins))

        domain_metrics.append(
            {
                "domain_name": domain_text,
                "disabled_count": disabled_count,
                "disabled_pct": _calculate_percentage(disabled_count, total_accounts),
                "old_pass_pct": _calculate_percentage(old_passwords, enabled_accounts),
                "ia_pct": _calculate_percentage(inactive_accounts, enabled_accounts),
            }
        )

        functionality_text = ""
        if functionality_value is not None:
            functionality_text = str(functionality_value)

        if "2000" in functionality_text or "2003" in functionality_text:
            if domain_text not in legacy_domains:
                legacy_domains.append(domain_text)

    response: Dict[str, Any] = {
        "old_domains_count": len(legacy_domains),
        "old_domains_str": None,
    }

    if legacy_domains:
        response["old_domains_string"] = _format_sample_string(legacy_domains)
        old_domains_str = _format_slash_separated_string(legacy_domains)
        response["old_domains_str"] = old_domains_str if old_domains_str else None

    if domain_metrics:
        response["domain_metrics"] = domain_metrics

    if domain_metrics:
        response.update(
            {
                "disabled_account_string": _format_plain_list(disabled_counts),
                "disabled_account_pct_string": _format_plain_list(disabled_percentages),
                "old_password_string": _format_plain_list(old_password_counts),
                "old_password_pct_string": _format_plain_list(old_password_percentages),
                "inactive_accounts_string": _format_plain_list(inactive_counts),
                "inactive_accounts_pct_string": _format_plain_list(inactive_percentages),
                "domain_admins_string": _format_plain_list(domain_admins_counts),
                "ent_admins_string": _format_plain_list(ent_admins_counts),
                "exp_passwords_string": _format_plain_list(exp_password_counts),
                "never_expire_string": _format_plain_list(never_expire_counts),
                "generic_accounts_string": _format_plain_list(generic_account_counts),
                "generic_logins_string": _format_plain_list(generic_login_counts),
            }
        )

    return response


def build_workbook_password_response(
    workbook_data: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]], List[str]]:
    """Generate password policy summary data sourced from workbook details."""

    if not isinstance(workbook_data, dict):
        return {"bad_pass_count": 0}, {}, []

    password_data = workbook_data.get("password", {})
    policies = password_data.get("policies", []) if isinstance(password_data, dict) else []
    if not isinstance(policies, list):
        return {"bad_pass_count": 0}, {}, []

    ad_data = workbook_data.get("ad", {})
    ad_domains = ad_data.get("domains", []) if isinstance(ad_data, dict) else []
    ad_domain_order: List[str] = []
    if isinstance(ad_domains, list):
        for record in ad_domains:
            if isinstance(record, dict):
                domain_value = record.get("domain") or record.get("name")
            else:
                domain_value = record
            domain_text = str(domain_value).strip() if domain_value else ""
            if domain_text and domain_text not in ad_domain_order:
                ad_domain_order.append(domain_text)

    domain_values: Dict[str, Dict[str, Any]] = {}
    policy_domain_order: List[str] = []
    domain_bad_flags: Dict[str, bool] = {}
    bad_pass_total = 0
    total_cracked = 0

    def _is_yes(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() == "yes"
        if isinstance(value, bool):
            return value
        return False

    def _normalize_admin_count(entry: Dict[str, Any]) -> Optional[int]:
        raw_admin = entry.get("admin_cracked")
        if isinstance(raw_admin, dict):
            confirm_value = raw_admin.get("confirm")
            count_value = raw_admin.get("count")
        else:
            confirm_value = entry.get("admin_cracked_confirm")
            count_value = raw_admin
        if not _is_yes(confirm_value):
            return 0
        coerced = _coerce_int(count_value)
        return coerced if coerced is not None else 0

    def _normalize_fgpp(entry: Dict[str, Any]) -> bool:
        raw_fgpp = entry.get("fgpp")
        if isinstance(raw_fgpp, dict):
            fgpp_count = _coerce_int(raw_fgpp.get("count"))
        else:
            fgpp_count = _coerce_int(raw_fgpp)
        return fgpp_count is not None and fgpp_count < 1

    compliance_matrix = load_password_compliance_matrix()
    policy_field_order: List[str] = list(compliance_matrix.keys())
    policy_fields: Set[str] = set(policy_field_order)
    numeric_policy_fields: Set[str] = {
        field
        for field, definition in compliance_matrix.items()
        if definition.get("data_type") == "numeric"
    }

    def _normalize_policy_value(entry: Dict[str, Any], key: str) -> Any:
        value = entry.get(key)
        if key in numeric_policy_fields:
            return _coerce_int(value)
        return _normalize_policy_string(value)

    def _value_is_non_compliant(setting: str, normalized_value: Any) -> bool:
        definition = compliance_matrix.get(setting) or {}
        data_type = definition.get("data_type", "numeric")
        rule = definition.get("rule")
        return _evaluate_compliance_rule(rule, normalized_value, data_type)

    def _collect_policy_failures(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            return {}

        failures: Dict[str, Any] = {}

        for setting in policy_field_order:
            normalized_value = _normalize_policy_value(entry, setting)
            if setting in numeric_policy_fields and normalized_value is None:
                continue
            if _value_is_non_compliant(setting, normalized_value):
                failures[setting] = normalized_value

        return failures

    def _iter_fgpp_entries(entry: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        raw_fgpp = entry.get("fgpp")
        if isinstance(raw_fgpp, list):
            for item in raw_fgpp:
                if isinstance(item, dict):
                    yield item
        elif isinstance(raw_fgpp, dict):
            if any(key in raw_fgpp for key in policy_fields):
                yield raw_fgpp

    for policy in policies:
        if isinstance(policy, dict):
            domain_value = (
                policy.get("domain_name")
                or policy.get("domain")
                or policy.get("name")
                or ""
            )
            entry = policy
        else:
            domain_value = policy
            entry = {}

        domain_text = str(domain_value).strip()
        if not domain_text:
            domain_text = "Unnamed Domain"

        if domain_text not in policy_domain_order:
            policy_domain_order.append(domain_text)

        normalized_entry = entry if isinstance(entry, dict) else {}
        domain_entry = domain_values.setdefault(domain_text, {})

        cracked_value = _coerce_int(normalized_entry.get("passwords_cracked"))
        if cracked_value is not None:
            total_cracked += cracked_value
        enabled_value = _coerce_int(normalized_entry.get("enabled_accounts"))
        admin_cracked_value = _normalize_admin_count(normalized_entry)

        policy_failures = _collect_policy_failures(normalized_entry)
        policy_is_bad = bool(policy_failures)
        if policy_is_bad:
            bad_pass_total += 1
            policy_field_list = domain_entry.setdefault("policy_cap_fields", [])
            for field in policy_failures:
                if field not in policy_field_list:
                    policy_field_list.append(field)
            domain_entry.setdefault("policy_cap_values", {}).update(policy_failures)

        fgpp_is_bad = False
        for index, fgpp_entry in enumerate(
            _iter_fgpp_entries(normalized_entry), start=1
        ):
            fgpp_failures = _collect_policy_failures(fgpp_entry)
            if not fgpp_failures:
                continue
            bad_pass_total += 1
            fgpp_is_bad = True
            fgpp_name_value = (
                fgpp_entry.get("fgpp_name")
                or fgpp_entry.get("name")
                or fgpp_entry.get("policy_name")
            )
            fgpp_name = str(fgpp_name_value).strip() if fgpp_name_value else ""
            if not fgpp_name:
                fgpp_name = f"Policy {index}"
            fgpp_fields_map = domain_entry.setdefault("fgpp_cap_fields", {})
            fgpp_field_list = fgpp_fields_map.setdefault(fgpp_name, [])
            for field in fgpp_failures:
                if field not in fgpp_field_list:
                    fgpp_field_list.append(field)
            fgpp_values_map = domain_entry.setdefault("fgpp_cap_values", {})
            fgpp_value_entry = fgpp_values_map.setdefault(fgpp_name, {})
            fgpp_value_entry.update(fgpp_failures)

        combined_bad = policy_is_bad or fgpp_is_bad
        if combined_bad or domain_text not in domain_bad_flags:
            domain_bad_flags[domain_text] = domain_bad_flags.get(domain_text, False) or combined_bad

        domain_entry.update(
            {
                "passwords_cracked": _format_integer_value(cracked_value),
                "enabled_accounts": _format_integer_value(enabled_value),
                "admin_cracked": _format_integer_value(admin_cracked_value),
                "lanman": _is_yes(normalized_entry.get("lanman_stored")),
                "no_fgpp": _normalize_fgpp(normalized_entry),
                "bad_pass": domain_bad_flags.get(domain_text, False),
            }
        )

    summary_domains: List[str] = []
    for domain in ad_domain_order:
        if domain in domain_values and domain not in summary_domains:
            summary_domains.append(domain)
    for domain in policy_domain_order:
        if domain in domain_values and domain not in summary_domains:
            summary_domains.append(domain)

    policy_cap_fields, policy_cap_context = summarize_password_cap_details(domain_values)
    password_cap_templates = load_password_cap_map() if policy_cap_fields else {}

    def _inject_cap_details(summary_dict: Dict[str, Any]) -> Dict[str, Any]:
        if policy_cap_fields:
            summary_dict["policy_cap_fields"] = list(policy_cap_fields)
            if policy_cap_context:
                summary_dict["policy_cap_context"] = policy_cap_context
                domain_cap_map = build_password_cap_display_map(
                    policy_cap_context, password_cap_templates
                )
                if domain_cap_map:
                    summary_dict["policy_cap_map"] = domain_cap_map
                else:
                    summary_dict.pop("policy_cap_map", None)
            else:
                summary_dict.pop("policy_cap_context", None)
                summary_dict.pop("policy_cap_map", None)
        else:
            summary_dict.pop("policy_cap_fields", None)
            summary_dict.pop("policy_cap_map", None)
            summary_dict.pop("policy_cap_context", None)
        return summary_dict

    summary: Dict[str, Any] = {"bad_pass_count": bad_pass_total, "total_cracked": total_cracked}

    if not summary_domains:
        return _inject_cap_details(summary), domain_values, summary_domains

    cracked_counts = [domain_values[domain]["passwords_cracked"] for domain in summary_domains]
    enabled_counts = [domain_values[domain]["enabled_accounts"] for domain in summary_domains]
    admin_cracked_counts = [domain_values[domain]["admin_cracked"] for domain in summary_domains]
    lanman_domains = [domain for domain in summary_domains if domain_values[domain]["lanman"]]
    no_fgpp_domains = [domain for domain in summary_domains if domain_values[domain]["no_fgpp"]]

    summary_domains_str = _format_slash_separated_string(summary_domains)
    summary.update(
        {
            "domains_str": summary_domains_str,
            "cracked_count_str": "/".join(cracked_counts),
            "cracked_finding_string": _format_plain_list(cracked_counts),
            "enabled_count_string": _format_plain_list(enabled_counts),
            "admin_cracked_string": _format_plain_list(admin_cracked_counts),
            "admin_cracked_doms": _format_sample_string(summary_domains),
            "lanman_list_string": _format_sample_string(lanman_domains),
            "no_fgpp_string": _format_sample_string(no_fgpp_domains),
        }
    )

    return _inject_cap_details(summary), domain_values, summary_domains


def build_workbook_dns_response(workbook_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate supplemental DNS details derived from workbook metadata."""

    if not isinstance(workbook_data, dict):
        return {}

    dns_data = workbook_data.get("dns", {})
    if not isinstance(dns_data, dict):
        return {}

    records = dns_data.get("records")
    if not isinstance(records, list) or not records:
        return {}

    def _is_yes(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"yes", "y", "true", "1"}

    total_records = 0
    zone_transfer_count = 0

    for record in records:
        if not isinstance(record, dict):
            continue
        total_records += 1
        if _is_yes(record.get("zone_transfer")):
            zone_transfer_count += 1

    if total_records == 0:
        return {}

    return {"zone_trans": zone_transfer_count}


def build_workbook_firewall_response(workbook_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate supplemental firewall details derived from workbook metadata."""

    if not isinstance(workbook_data, dict):
        return {}

    firewall_data = workbook_data.get("firewall", {})
    if not isinstance(firewall_data, dict):
        return {}

    devices = firewall_data.get("devices", [])
    if not isinstance(devices, list):
        return {}

    def _normalize_name(raw_value: Any, index: int) -> str:
        if raw_value is None:
            return f"Device {index}"
        text = str(raw_value).strip()
        return text or f"Device {index}"

    def _normalize_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        text = str(value).strip().lower()
        return text in {"yes", "true", "1", "y"}

    ood_names: List[str] = []
    seen_names: set[str] = set()

    for index, record in enumerate(devices, start=1):
        if not isinstance(record, dict):
            continue
        if not _normalize_bool(record.get("ood")):
            continue
        name_value = record.get("name") or record.get("device") or record.get("hostname")
        normalized_name = _normalize_name(name_value, index)
        if normalized_name not in seen_names:
            seen_names.add(normalized_name)
            ood_names.append(normalized_name)

    formatted_names = _format_oxford_quoted_list(ood_names)
    if not formatted_names:
        return {}

    return {"ood_name_list": formatted_names, "ood_count": len(ood_names)}
