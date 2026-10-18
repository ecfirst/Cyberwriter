"""Default AI review prompt text and section metadata.

This module is intentionally free of Django imports so that both
``ghostwriter.rolodex.views`` and ``ghostwriter.commandcenter.models`` can
import it without creating an import cycle. The admin-editable
``AIReviewPromptTemplate`` rows are seeded from ``AI_REVIEW_PROMPT_DEFAULTS``
and fall back to it when a row is missing.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Optional

RISK_PLACEHOLDER = "{risk}"

# (section key, label, scoping category, scoping key)
AI_REVIEW_SECTIONS = (
    ("osint_rt", "OSINT", "external", "osint"),
    ("dns_rt", "DNS", "external", "dns"),
    ("external_nexpose_rt", "External Nexpose", "external", "nexpose"),
    ("web_rt", "Web", "external", "web"),
    ("ad_rt", "AD", "iam", "ad"),
    ("ad_attack_paths_rt", "AD Attack Paths", "iam", "ad_attack_paths"),
    ("password_rt", "Password", "iam", "password"),
    ("internal_nexpose_rt", "Internal Nexpose", "internal", "nexpose"),
    ("iot_iomt_nexpose_rt", "IoT/IoMT Nexpose", "internal", "iot_iomt"),
    ("endpoint_rt", "Endpoint", "internal", "endpoint"),
    ("snmp_rt", "SNMP", "internal", "snmp"),
    ("sql_rt", "SQL", "internal", "sql"),
    ("wireless_rt", "Wireless", "wireless", "selected"),
    ("firewall_rt", "Firewall", "firewall", "selected"),
    ("cloud_management_rt", "Cloud Management", "cloud", "cloud_management"),
    ("iam_management_rt", "IAM Management", "cloud", "iam_management"),
    ("system_configuration_rt", "System Configuration", "cloud", "system_configuration"),
)

AI_REVIEW_SECTION_CHOICES = [(key, label) for key, label, _category, _scoping_key in AI_REVIEW_SECTIONS]

AI_REVIEW_SECTION_LABELS = {key: label for key, label, _category, _scoping_key in AI_REVIEW_SECTIONS}

DEFAULT_INSTRUCTION_TEMPLATE = (
    "Provide an executive summary in a single paragraph for the {description}. Use the following project "
    "data as context and keep the response concise."
)

DEFAULT_FOOTER_PREFIX = "End the paragraph with this risk statement: "

PASSWORD_NIST_PROMPT_GUIDANCE = (
    " Frame all findings and recommendations according to current NIST SP 800-63B digital identity "
    "guidance, which has moved away from the legacy password controls many organizations still enforce. "
    "Specifically: (1) Do not recommend periodic or forced password expiration. A 'Maximum Age' of 0 "
    "(passwords do not expire on a schedule) is the desired end state; credential changes should be "
    "forced only on evidence of compromise. (2) Do not recommend enabling character-composition or "
    "complexity requirements. 'Complexity Required' set to FALSE is the desired end state. (3) Treat "
    "minimum length, screening candidate passwords against blocklists of known-breached and commonly "
    "used passwords, and multi-factor authentication as the primary controls that reduce "
    "credential-compromise risk. Where the assessed policy already disables expiration or complexity, "
    "describe that as alignment with current guidance rather than as a weakness, and do not recommend "
    "re-enabling either control."
)

PASSWORD_PRIORITY_GUIDANCE = (
    " Prioritize cracked password results and administrator credentials when present; address policy and "
    "FGPP settings as supporting details."
)

# Fully expanded instruction/footer text per section. ``{risk}`` is replaced
# with the area risk label (or "unknown") when the prompt is built.
AI_REVIEW_PROMPT_DEFAULTS: "OrderedDict[str, Dict[str, str]]" = OrderedDict(
    (
        (
            "osint_rt",
            {
                "label": "OSINT",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Open Source Intel metrics. Use the "
                    "following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined these exposures represent a "
                    "{risk} risk of sensitive information exposure."
                ),
            },
        ),
        (
            "dns_rt",
            {
                "label": "DNS",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the DNS configuration best practice checks. "
                    "Use the following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined these issues represent a {risk} "
                    "risk to the availability of external systems and services."
                ),
            },
        ),
        (
            "external_nexpose_rt",
            {
                "label": "External Nexpose",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Vulnerability scanning results for "
                    "externally accessible systems. Use the following project data as context and keep the response "
                    "concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: Based on the vulnerabilities discovered, ecfirst rates "
                    "the overall risk of the external network and systems as a {risk} risk."
                ),
            },
        ),
        (
            "web_rt",
            {
                "label": "Web",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Web application vulnerability scan "
                    "results. Use the following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined these issues represent a {risk} "
                    "risk for web sites/applications."
                ),
            },
        ),
        (
            "ad_rt",
            {
                "label": "AD",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Active Directory metrics covering "
                    "privileged groups and user account hygiene. Use the following project data as context and keep the "
                    "response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the deviations from best "
                    "practice identified create a {risk} risk to IAM."
                ),
            },
        ),
        (
            "ad_attack_paths_rt",
            {
                "label": "AD Attack Paths",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Active Directory attack path findings "
                    "covering Kerberoasting, delegation abuse, ADCS misconfiguration, and related identity attack "
                    "surface. Use the following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the identified AD attack "
                    "paths create a {risk} risk of domain compromise."
                ),
            },
        ),
        (
            "password_rt",
            {
                "label": "Password",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Password policy effectiveness, cracked "
                    "credentials, and related controls. Use the following project data as context and keep the response "
                    "concise. Prioritize cracked password results and administrator credentials when present; address "
                    "policy and FGPP settings as supporting details. Frame all findings and recommendations according to "
                    "current NIST SP 800-63B digital identity guidance, which has moved away from the legacy password "
                    "controls many organizations still enforce. Specifically: (1) Do not recommend periodic or forced "
                    "password expiration. A 'Maximum Age' of 0 (passwords do not expire on a schedule) is the desired "
                    "end state; credential changes should be forced only on evidence of compromise. (2) Do not recommend "
                    "enabling character-composition or complexity requirements. 'Complexity Required' set to FALSE is "
                    "the desired end state. (3) Treat minimum length, screening candidate passwords against blocklists "
                    "of known-breached and commonly used passwords, and multi-factor authentication as the primary "
                    "controls that reduce credential-compromise risk. Where the assessed policy already disables "
                    "expiration or complexity, describe that as alignment with current guidance rather than as a "
                    "weakness, and do not recommend re-enabling either control."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that, based on the defined and "
                    "implemented password policy, along with the number of accounts using weak passwords, the risk of "
                    "account compromise is {risk}."
                ),
            },
        ),
        (
            "internal_nexpose_rt",
            {
                "label": "Internal Nexpose",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Vulnerability scanning results for "
                    "internal systems. Use the following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: Based on the vulnerabilities discovered, ecfirst rates "
                    "the overall risk of the internal network and systems as a {risk} risk."
                ),
            },
        ),
        (
            "iot_iomt_nexpose_rt",
            {
                "label": "IoT/IoMT Nexpose",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Vulnerability scanning results for IoT "
                    "systems/devices. Use the following project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: Based on the vulnerabilities discovered, ecfirst rates "
                    "the overall risk of the IoT/IoMT systems as a {risk} risk."
                ),
            },
        ),
        (
            "endpoint_rt",
            {
                "label": "Endpoint",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of accessible AD registered "
                    "computers for current Security Software and past connections to insecure WiFi. Use the following "
                    "project data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the number of devices "
                    "without current, active security software present, along with the number of connections to Open "
                    "wireless networks, creates a {risk} risk of data loss and/or malware infection."
                ),
            },
        ),
        (
            "snmp_rt",
            {
                "label": "SNMP",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of internal systems using SNMP "
                    "for default or easy to guess Strings. Use the following project data as context and keep the "
                    "response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the number of systems "
                    "utilizing default SNMP strings creates a {risk} risk to the security of the internal network and "
                    "systems."
                ),
            },
        ),
        (
            "sql_rt",
            {
                "label": "SQL",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of internal systems with database "
                    "servers listening on default ports with a test for default credentials. Use the following project "
                    "data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the number of database "
                    "instances allowing open access, coupled with the unsupported systems, creates a {risk} risk for "
                    "unauthorized data access or data loss."
                ),
            },
        ),
        (
            "wireless_rt",
            {
                "label": "Wireless",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of the Wireless networks "
                    "accessible at a location, a comparison to 'approved' SSIDs, a review of the wireless security and "
                    "wireless-to-internal network segmentation testing (when applicable). Use the following project data "
                    "as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined that the risk related to the "
                    "wireless networks is {risk}."
                ),
            },
        ),
        (
            "firewall_rt",
            {
                "label": "Firewall",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of firewall OS version, security "
                    "configuration setting best-practice adherence and rule configuration. Use the following project "
                    "data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined the risk related to the "
                    "Firewalls is {risk}."
                ),
            },
        ),
        (
            "cloud_management_rt",
            {
                "label": "Cloud Management",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of the applicable cloud provider "
                    "configuration settings as compared to the CIS Benchmark recommendations. Use the following project "
                    "data as context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined the risk related to cloud "
                    "management settings is {risk}."
                ),
            },
        ),
        (
            "iam_management_rt",
            {
                "label": "IAM Management",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of the M365 configuration "
                    "settings as compared to the CIS Benchmark recommendations. Use the following project data as "
                    "context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined the risk related to IAM "
                    "management settings is {risk}."
                ),
            },
        ),
        (
            "system_configuration_rt",
            {
                "label": "System Configuration",
                "instruction": (
                    "Provide an executive summary in a single paragraph for the Review of system configuration setting "
                    "as compared to the applicable CIS Benchmark recommendations. Use the following project data as "
                    "context and keep the response concise."
                ),
                "footer": (
                    "End the paragraph with this risk statement: ecfirst has determined the risk related to system "
                    "configuration is {risk}."
                ),
            },
        ),
    )
)

GENERIC_INSTRUCTION = DEFAULT_INSTRUCTION_TEMPLATE.format(description="Project review")


def normalize_section_key(section_key: str) -> str:
    """Return the ``*_rt`` section key for ``section_key`` (accepts bare keys)."""

    key = (section_key or "").strip()
    if key.endswith("_rt"):
        return key
    return f"{key}_rt" if key else key


def get_default_prompt_text(section_key: str) -> Dict[str, str]:
    """Return the default ``{"instruction", "footer"}`` for ``section_key``."""

    entry = AI_REVIEW_PROMPT_DEFAULTS.get(normalize_section_key(section_key))
    if entry is None:
        return {"instruction": GENERIC_INSTRUCTION, "footer": ""}
    return {"instruction": entry["instruction"], "footer": entry["footer"]}


def render_prompt_text(text: Optional[str], risk: Optional[str]) -> str:
    """Return ``text`` with ``{risk}`` replaced by ``risk`` (or ``unknown``)."""

    if not text or not str(text).strip():
        return ""
    return str(text).replace(RISK_PLACEHOLDER, risk or "unknown")


def render_prompt_footer(footer: Optional[str], risk: Optional[str]) -> str:
    """Return the rendered footer, or ``""`` when no footer is configured."""

    return render_prompt_text(footer, risk)
