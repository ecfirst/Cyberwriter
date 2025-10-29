"""Utilities for parsing uploaded project data files."""

from __future__ import annotations

# Standard Libraries
import csv
import io
from collections import Counter
from collections import abc
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.core.files.base import File

if False:  # pragma: no cover - typing only
    from ghostwriter.rolodex.models import Project, ProjectDataFile  # noqa: F401

from ghostwriter.rolodex.ip_artifacts import IP_ARTIFACT_DEFINITIONS, parse_ip_text
from ghostwriter.rolodex.workbook import AD_DOMAIN_METRICS


DNS_RECOMMENDATION_MAP: Dict[str, str] = {
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

DNS_FINDING_MAP: Dict[str, str] = {
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


def parse_dns_report(file_obj: File) -> List[Dict[str, str]]:
    """Parse a dns_report.csv file, returning issue metadata for failed checks."""

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
        finding = DNS_FINDING_MAP.get(issue_text, "")
        recommendation = DNS_RECOMMENDATION_MAP.get(issue_text, "")
        impact = DNS_IMPACT_MAP.get(issue_text, "")
        issues.append(
            {
                "issue": issue_text,
                "finding": finding,
                "recommendation": recommendation,
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
        artifacts["firewall_findings"] = firewall_results

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

    response: Dict[str, Any] = {"old_domains_count": len(legacy_domains)}

    if legacy_domains:
        response["old_domains_string"] = _format_sample_string(legacy_domains)

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
