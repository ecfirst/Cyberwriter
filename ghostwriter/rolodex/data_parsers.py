"""Utilities for parsing uploaded project data files."""

from __future__ import annotations

# Standard Libraries
import csv
import io
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.core.files.base import File

if False:  # pragma: no cover - typing only
    from ghostwriter.rolodex.models import Project, ProjectDataFile  # noqa: F401

from ghostwriter.rolodex.ip_artifacts import IP_ARTIFACT_DEFINITIONS, parse_ip_text


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


def normalize_nexpose_artifact_payload(payload: Any) -> Dict[str, Any]:
    """Return a copy of ``payload`` with severity buckets wrapped for templates."""

    if not isinstance(payload, dict):
        return payload
    normalized: Dict[str, Any] = dict(payload)
    for severity_key in ("high", "med", "low"):
        if severity_key in normalized:
            normalized[severity_key] = _coerce_severity_group(normalized[severity_key])
    return normalized


def _normalize_web_site_payload(payload: Any) -> Any:
    """Normalize a single web issue site payload for template access."""

    if not isinstance(payload, dict):
        return payload
    normalized: Dict[str, Any] = dict(payload)
    for severity_key in ("high", "med", "low"):
        if severity_key in normalized:
            normalized[severity_key] = _coerce_severity_group(normalized[severity_key])
    return normalized


def normalize_nexpose_artifacts_map(artifacts: Any) -> Any:
    """Normalize Nexpose and web issue artifact entries for template access."""

    if not isinstance(artifacts, dict):
        return artifacts
    normalized: Dict[str, Any] = dict(artifacts)
    for key, value in list(normalized.items()):
        if isinstance(key, str) and key.endswith("_nexpose_vulnerabilities"):
            normalized[key] = normalize_nexpose_artifact_payload(value)
        elif key == "web_issues":
            if isinstance(value, dict):
                normalized[key] = {
                    site: _normalize_web_site_payload(site_payload)
                    for site, site_payload in value.items()
                }
            elif isinstance(value, list):  # pragma: no cover - legacy support
                normalized[key] = [
                    _normalize_web_site_payload(site_payload) for site_payload in value
                ]
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
        "artifact_key": "iot_nexpose_vulnerabilities",
        "label": "IoT/IoMT Nexpose Vulnerabilities",
    },
}

NEXPOSE_ARTIFACT_KEYS = {
    definition["artifact_key"] for definition in NEXPOSE_ARTIFACT_DEFINITIONS.values()
}


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
    nexpose_results: Dict[str, Dict[str, Any]] = {}

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
        web_entries: Dict[str, Dict[str, Any]] = {}
        for site, severity_map in web_results.items():
            site_entry: Dict[str, Any] = {"site": site}
            for severity_key in ("high", "med", "low"):
                counter = severity_map.get(severity_key, Counter())
                site_entry[severity_key] = _summarize_severity_counter(counter)
            web_entries[site] = site_entry
        if web_entries:
            artifacts["web_issues"] = web_entries

    for artifact_key, values in ip_results.items():
        if values:
            artifacts[artifact_key] = values

    if firewall_results:
        artifacts["firewall_findings"] = firewall_results

    for artifact_key, details in nexpose_results.items():
        artifacts[artifact_key] = {
            "label": details.get("label", artifact_key.replace("_", " ").title()),
            "high": details.get("high", {"total_unique": 0, "items": []}),
            "med": details.get("med", {"total_unique": 0, "items": []}),
            "low": details.get("low", {"total_unique": 0, "items": []}),
        }

    return artifacts
