"""Utilities for parsing uploaded project data files."""

from __future__ import annotations

# Standard Libraries
import csv
import io
from typing import Any, Dict, Iterable, List

from django.core.files.base import File

if False:  # pragma: no cover - typing only
    from ghostwriter.rolodex.models import Project, ProjectDataFile  # noqa: F401


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
        issues.append(
            {
                "issue": issue_text,
                "finding": finding,
                "recommendation": recommendation,
            }
        )
    return issues


def build_project_artifacts(project: "Project") -> Dict[str, Any]:
    """Aggregate parsed artifacts for the provided project."""

    artifacts: Dict[str, Any] = {}
    dns_results: Dict[str, List[Dict[str, str]]] = {}

    for data_file in project.data_files.all():
        label = (data_file.requirement_label or "").strip().lower()
        if label == "dns_report.csv":
            domain = (data_file.requirement_context or data_file.description or data_file.filename).strip()
            domain = domain or "Unknown Domain"
            parsed = parse_dns_report(data_file.file)
            if parsed:
                dns_results.setdefault(domain, []).extend(parsed)

    if dns_results:
        artifacts["dns_issues"] = [
            {"domain": domain, "issues": issues}
            for domain, issues in dns_results.items()
        ]

    return artifacts
