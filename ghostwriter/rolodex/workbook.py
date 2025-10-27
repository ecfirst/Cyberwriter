"""Helpers for generating workbook-driven project questions."""

# Standard Libraries
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Django Imports
from django import forms
from django.utils.text import slugify

# Ghostwriter Libraries
from ghostwriter.rolodex.forms_workbook import MultiValueField

SECTION_DISPLAY_ORDER = [
    "client",
    "general",
    "report_card",
    "external_internal_grades",
    "osint",
    "dns",
    "external_nexpose",
    "web",
    "firewall",
    "ad",
    "password",
    "internal_nexpose",
    "iot-iomt_nexpose",
    "endpoint",
    "snmp",
    "sql",
    "wireless",
    "cloud_config",
    "system_config",
]

SECTION_ORDER_INDEX = {key: index for index, key in enumerate(SECTION_DISPLAY_ORDER)}

RISK_CHOICES = (
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
)

YES_NO_CHOICES = (
    ("yes", "Yes"),
    ("no", "No"),
)

WEAK_PSK_CHOICES = (
    ("too_short", "To short"),
    ("not_enough_entropy", "Not enough entropy"),
    ("dictionary_or_company", "Based on dictionary word or Company name"),
)

WIRELESS_NETWORK_TYPES = (
    ("open", "Open Networks"),
    ("psk", "PSK Networks"),
    ("hidden", "Hidden Networks (typically Medium)"),
    ("rogue", "Rogue Networks"),
)

AD_DOMAIN_METRICS = (
    ("domain_admins", "Domain Admins"),
    ("enterprise_admins", "Enterprise Admins"),
    ("expired_passwords", "Expired Passwords"),
    ("passwords_never_expire", "Passwords Never Expire"),
    ("inactive_accounts", "Inactive Accounts"),
    ("generic_accounts", "Generic Accounts"),
    ("generic_logins", "Generic Logins"),
    ("old_passwords", "Old Passwords"),
    ("disabled_accounts", "Disabled Accounts"),
)


def _as_int(value: Any) -> int:
    try:
        if isinstance(value, bool):  # pragma: no cover - defensive guard
            return int(value)
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _extract_domain(record: Any) -> Optional[str]:
    if isinstance(record, dict):
        for key in ("domain", "name"):
            candidate = record.get(key)
            if candidate:
                return _as_str(candidate)
    elif record:
        return _as_str(record)
    return None


def _slugify_identifier(*parts: Iterable[Any]) -> str:
    identifiers: List[str] = []
    for part in parts:
        if part is None:
            continue
        text = slugify(str(part))
        if text:
            identifiers.append(text)
    return "_".join(identifiers)


def _get_nested(data: Dict[str, Any], path: Iterable[str], default: Any = None) -> Any:
    result: Any = data
    for key in path:
        if not isinstance(result, dict):
            return default
        result = result.get(key)
    return result if result is not None else default


def _humanize_section_name(raw_key: str) -> str:
    text = (raw_key or "").replace("_", " ").replace("-", " ").strip()
    if not text:
        return "Section"
    return text.title()


def _format_leaf_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        # Cast numbers to strings so template sanitization handles them uniformly.
        return str(value)
    return str(value)


def _normalise_workbook_value(value: Any) -> Dict[str, Any]:
    """Return a structure suitable for recursive rendering in templates."""

    if isinstance(value, dict):
        items: List[Dict[str, Any]] = []
        for key, item in value.items():
            items.append(
                {
                    "label": _humanize_section_name(str(key)),
                    "raw_key": str(key),
                    "value": _normalise_workbook_value(item),
                }
            )
        return {"type": "dict", "items": items}

    if isinstance(value, list):
        items = []
        for index, item in enumerate(value, 1):
            formatted = _normalise_workbook_value(item)
            label: Optional[str] = None
            if isinstance(item, dict):
                for candidate_key in ("name", "domain", "title", "short_name", "url"):
                    candidate = item.get(candidate_key)
                    if candidate:
                        label = str(candidate)
                        break
            if not label and formatted.get("type") != "value":
                label = f"Item {index}"
            items.append({"label": label, "index": index, "value": formatted})
        return {"type": "list", "items": items}

    return {"type": "value", "display": _format_leaf_value(value)}


def build_workbook_sections(workbook_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return workbook content grouped by top-level keys for easier presentation."""

    if not isinstance(workbook_data, dict):
        return []

    sections: List[Dict[str, Any]] = []
    for position, (key, value) in enumerate(workbook_data.items()):
        slug = _slugify_identifier("workbook", key)
        slug = slug or "workbook-section"
        sections.append(
            {
                "key": key,
                "title": _humanize_section_name(str(key)),
                "slug": slug,
                "script_id": f"workbook-section-data-{slug}",
                "data": value,
                "tree": _normalise_workbook_value(value),
                "_position": position,
            }
        )

    sections.sort(
        key=lambda section: (
            SECTION_ORDER_INDEX.get(section["key"], len(SECTION_DISPLAY_ORDER)),
            section.pop("_position"),
        )
    )

    return sections


def build_data_configuration(workbook_data: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """Return dynamic questions and file requirements derived from workbook data."""

    data = workbook_data or {}
    questions: List[Dict[str, Any]] = []
    required_files: List[Dict[str, str]] = []
    required_file_index: Set[Tuple[str, Optional[str]]] = set()

    def add_required(label: str, context: Optional[str] = None) -> None:
        key = (label, context)
        if key not in required_file_index:
            required_file_index.add(key)
            slug = _slugify_identifier("required", label, context)
            if not slug:
                slug = f"required-{len(required_file_index)}"
            entry = {"label": label, "slug": slug}
            if context:
                entry["context"] = context
            required_files.append(entry)

    def add_question(
        *,
        key: str,
        label: str,
        field_class: type,
        section: str,
        subheading: Optional[str] = None,
        help_text: Optional[str] = None,
        choices: Optional[Iterable[Tuple[str, str]]] = None,
        widget: Optional[forms.Widget] = None,
        initial: Any = None,
    ) -> None:
        field_kwargs: Dict[str, Any] = {
            "label": label,
            "required": False,
        }
        if help_text:
            field_kwargs["help_text"] = help_text
        if choices is not None:
            field_kwargs["choices"] = tuple(choices)
        if widget is not None:
            field_kwargs["widget"] = widget
        if initial is not None:
            field_kwargs["initial"] = initial
        questions.append(
            {
                "key": key,
                "label": label,
                "section": section,
                "subheading": subheading,
                "field_class": field_class,
                "field_kwargs": field_kwargs,
            }
        )

    # Intelligence questions
    if _as_int(_get_nested(data, ("osint", "total_squat"), 0)) > 0:
        add_question(
            key="osint_squat_concern",
            label="Of the squatting domains found, which is the most concerning (single domain or comma-separated list)",
            field_class=forms.CharField,
            section="Intelligence",
            widget=forms.TextInput(attrs={"class": "form-control"}),
        )

    # Required DNS artifacts
    dns_records = _get_nested(data, ("dns", "records"), []) or []
    if isinstance(dns_records, list):
        for record in dns_records:
            domain = _extract_domain(record)
            if domain:
                add_required("dns_report.csv", domain)

    if _as_int(_get_nested(data, ("web", "combined_unique"), 0)) > 0:
        add_required("burp_csv.csv")
        add_required("burp-cap.csv")

    # Vulnerability artifacts
    nexpose_totals = [
        _as_int(_get_nested(data, ("external_nexpose", "total"), 0)),
        _as_int(_get_nested(data, ("internal_nexpose", "total"), 0)),
        _as_int(_get_nested(data, ("iot-iomt_nexpose",), 0)),
    ]
    if any(total > 0 for total in nexpose_totals):
        add_required("nexpose_cap.csv")

    firewall_source = _get_nested(data, ("fierwall",), None)
    if not isinstance(firewall_source, dict):
        firewall_source = _get_nested(data, ("firewall",), {})
    if _as_int(_get_nested(firewall_source or {}, ("unique",), 0)) > 0:
        add_required("firewall_csv.csv")

    firewall_devices = _get_nested(firewall_source or {}, ("devices",), []) or []
    if isinstance(firewall_devices, list):
        for index, device in enumerate(firewall_devices, start=1):
            if isinstance(device, dict):
                device_name = device.get("name") or device.get("device") or device.get("hostname")
            else:
                device_name = device
            display_name = _as_str(device_name).strip() or f"Device {index}"
            base_slug = _slugify_identifier("firewall", display_name)
            if not base_slug:
                base_slug = f"firewall_device_{index}"
            slug = f"{base_slug}_type"
            add_question(
                key=f"{slug}",
                label="Firewall Type",
                field_class=forms.CharField,
                section="Firewall",
                subheading=display_name,
                widget=forms.TextInput(attrs={"class": "form-control"}),
            )

    # Active Directory risk questions
    ad_domains = _get_nested(data, ("ad", "domains"), []) or []
    if isinstance(ad_domains, list):
        for record in ad_domains:
            domain = _extract_domain(record)
            if not domain:
                continue
            slug = _slugify_identifier("ad", domain)
            for metric_key, metric_label in AD_DOMAIN_METRICS:
                question_key = f"{slug}_{metric_key}"
                add_question(
                    key=question_key,
                    label=metric_label,
                    field_class=forms.ChoiceField,
                    section="Active Directory",
                    subheading=domain,
                    choices=RISK_CHOICES,
                    widget=forms.RadioSelect,
                )

    # Password policy risk
    password_policies = _get_nested(data, ("password", "policies"), []) or []
    if isinstance(password_policies, list):
        for policy in password_policies:
            domain_name = None
            if isinstance(policy, dict):
                domain_name = policy.get("domain_name") or policy.get("domain")
            domain_name = _as_str(domain_name) or "Unnamed Domain"
            slug = _slugify_identifier("password", domain_name)
            add_question(
                key=f"{slug}_risk",
                label=f"What is the risk you assign for the passwords cracked in the '{domain_name}' domain? (High, Medium or Low)",
                field_class=forms.ChoiceField,
                section="Password Policies",
                subheading=domain_name,
                choices=RISK_CHOICES,
                widget=forms.RadioSelect,
            )

    # Endpoint risk questions
    endpoint_domains = _get_nested(data, ("endpoint", "domains"), []) or []
    if isinstance(endpoint_domains, list):
        for entry in endpoint_domains:
            domain = None
            if isinstance(entry, dict):
                domain = entry.get("domain") or entry.get("name")
                if isinstance(domain, dict):
                    domain = domain.get("domain") or domain.get("name")
            domain = _as_str(domain) or "Unnamed Domain"
            slug = _slugify_identifier("endpoint", domain)
            add_question(
                key=f"{slug}_av_gap",
                label=(
                    f"What is the risk you associate with the number of systems without active, up-to-date security software "
                    f"found in the '{domain}' domain? (High, Medium, Low)"
                ),
                field_class=forms.ChoiceField,
                section="Endpoint",
                subheading=domain,
                choices=RISK_CHOICES,
                widget=forms.RadioSelect,
            )
            add_question(
                key=f"{slug}_open_wifi",
                label=(
                    f"What is the risk you associate with the Open WiFi networks accessed on machines in the '{domain}' domain? "
                    f"(High, Medium, Low)"
                ),
                field_class=forms.ChoiceField,
                section="Endpoint",
                subheading=domain,
                choices=RISK_CHOICES,
                widget=forms.RadioSelect,
            )

    # Wireless baseline questions
    for key_suffix, label in WIRELESS_NETWORK_TYPES:
        question_key = f"wireless_{key_suffix}_risk"
        add_question(
            key=question_key,
            label=label,
            field_class=forms.ChoiceField,
            section="Wireless",
            subheading="Wireless Network Risk",
            choices=RISK_CHOICES,
            widget=forms.RadioSelect,
        )

    add_question(
        key="wireless_psk_rotation_concern",
        label="Are you concerned the PSK(s) is not changed periodically (or when people leave the org)? (Yn)",
        field_class=forms.ChoiceField,
        section="Wireless",
        subheading="Wireless Network Risk",
        choices=YES_NO_CHOICES,
        widget=forms.RadioSelect,
    )

    weak_psk_value = _as_str(_get_nested(data, ("wireless", "weak_psks"), "")).lower()
    if weak_psk_value and weak_psk_value != "no":
        add_question(
            key="wireless_psk_weak_reasons",
            label="Why was the wireless PSK(s) weak?",
            field_class=forms.MultipleChoiceField,
            section="Wireless",
            subheading="PSK Analysis",
            choices=WEAK_PSK_CHOICES,
            widget=forms.CheckboxSelectMultiple,
        )
        add_question(
            key="wireless_psk_masterpass",
            label="Was the PSK(s) contained in masterpass? (yN)",
            field_class=forms.ChoiceField,
            section="Wireless",
            subheading="PSK Analysis",
            choices=YES_NO_CHOICES,
            widget=forms.RadioSelect,
            initial="no",
        )

    wep_confirm = _as_str(_get_nested(data, ("wireless", "wep_inuse", "confirm"), "")).lower()
    if wep_confirm == "yes":
        add_question(
            key="wireless_wep_crack_minutes",
            label="How many minutes did it take to crack the WEP key(s)?",
            field_class=forms.CharField,
            section="Wireless",
            subheading="WEP Networks",
            widget=forms.TextInput(attrs={"class": "form-control"}),
        )
        add_question(
            key="wireless_wep_ssids",
            label="Enter the WEP wireless network SSID(s)",
            field_class=MultiValueField,
            section="Wireless",
            subheading="WEP Networks",
        )

    add_question(
        key="wireless_segmentation_tested",
        label="Did you test open/guest wireless network segmentation?",
        field_class=forms.BooleanField,
        section="Wireless",
        subheading="Segmentation",
        help_text="Select if segmentation testing was performed.",
    )
    add_question(
        key="wireless_segmentation_ssids",
        label="Enter the Guest/Open wireless network SSID(s)",
        field_class=MultiValueField,
        section="Wireless",
        subheading="Segmentation",
        help_text="Provide one or more SSIDs discovered during segmentation testing.",
    )

    if _as_int(_get_nested(data, ("cloud_config", "fail"), 0)) > 0:
        add_question(
            key="cloud_config_risk",
            label="What is the risk you would assign to the Cloud Management fails? (High, Medium, Low)",
            field_class=forms.ChoiceField,
            section="Cloud Configuration",
            choices=RISK_CHOICES,
            widget=forms.RadioSelect,
        )

    if _as_int(_get_nested(data, ("system_config", "total_fail"), 0)) > 0:
        add_question(
            key="system_config_risk",
            label="What is the risk you would assign to the System Configuration fails? (High, Medium, Low)",
            field_class=forms.ChoiceField,
            section="System Configuration",
            choices=RISK_CHOICES,
            widget=forms.RadioSelect,
        )

    return questions, required_files
