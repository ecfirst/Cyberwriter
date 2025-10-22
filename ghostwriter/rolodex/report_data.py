"""Utilities for generating workbook-driven reporting requirements."""

# Standard Libraries
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


HIGH_MED_LOW_CHOICES = [
    {"value": "High", "label": "High"},
    {"value": "Medium", "label": "Medium"},
    {"value": "Low", "label": "Low"},
]

YES_NO_CHOICES = [
    {"value": "yes", "label": "Yes"},
    {"value": "no", "label": "No"},
]


def _safe_get(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    value = data
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, default)
        else:
            return default
    return value


def _normalize_domain(entry: Any, field: str = "domain") -> str:
    if isinstance(entry, dict):
        candidate = entry.get(field) or entry.get("name") or entry.get("domain_name")
        if candidate:
            return str(candidate)
    if isinstance(entry, str):
        return entry
    return str(entry)


def _high_medium_low_question(key: str, label: str, group: str, help_text: str | None = None) -> Dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "type": "choice",
        "choices": HIGH_MED_LOW_CHOICES,
        "group": group,
        "help_text": help_text,
    }


def _boolean_question(key: str, label: str, group: str, help_text: str | None = None) -> Dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "type": "boolean",
        "choices": YES_NO_CHOICES,
        "group": group,
        "help_text": help_text,
    }


def build_project_report_schema(workbook: Dict[str, Any] | None) -> Dict[str, Any]:
    """Return dynamic question and artifact requirements for a workbook."""

    if not isinstance(workbook, dict):
        workbook = {}

    questions: List[Dict[str, Any]] = []
    required_files: List[Dict[str, Any]] = []

    osint_total_squat = _safe_get(workbook, "osint", "total_squat", default=0) or 0
    if osint_total_squat > 0:
        questions.append(
            {
                "key": "osint_squat_concerns",
                "label": "Of the squatting domains found, which is the most concerning (single domain or comma-separated list)",
                "type": "text",
                "group": "OSINT",
            }
        )

    dns_records: Iterable[Any] = _safe_get(workbook, "dns", "records", default=[]) or []
    for record in dns_records:
        domain = _normalize_domain(record)
        slug = f"dns_report_{domain}".lower().replace(" ", "_")
        required_files.append(
            {
                "slug": slug,
                "label": f"dns_report.csv for {domain}",
                "filename": "dns_report.csv",
            }
        )

    external_nexpose = _safe_get(workbook, "external_nexpose", "total", default=0) or 0
    internal_nexpose = _safe_get(workbook, "internal_nexpose", "total", default=0) or 0
    iot_nexpose = _safe_get(workbook, "iot-iomt_nexpose", default=0) or 0
    if external_nexpose > 0 or internal_nexpose > 0 or iot_nexpose > 0:
        required_files.append(
            {
                "slug": "nexpose_cap",
                "label": "nexpose_cap.csv",
                "filename": "nexpose_cap.csv",
            }
        )

    web_unique = _safe_get(workbook, "web", "combined_unique", default=0) or 0
    if web_unique > 0:
        required_files.extend(
            [
                {
                    "slug": "burp_csv",
                    "label": "burp.csv",
                    "filename": "burp.csv",
                },
                {
                    "slug": "burp_cap_csv",
                    "label": "burp-cap.csv",
                    "filename": "burp-cap.csv",
                },
            ]
        )

    firewall_unique = _safe_get(workbook, "fierwall", "unique", default=0) or _safe_get(workbook, "firewall", "unique", default=0) or 0
    if firewall_unique > 0:
        required_files.append(
            {
                "slug": "firewall_csv",
                "label": "firewall_csv.csv",
                "filename": "firewall_csv.csv",
            }
        )

    ad_domains: Iterable[Any] = _safe_get(workbook, "ad", "domains", default=[]) or []
    ad_metrics = [
        "Domain Admins",
        "Enterprise Admins",
        "Expired Passwords",
        "Passwords Never Expire",
        "Inactive Accounts",
        "Generic Accounts",
        "Generic Logins",
        "Old Passwords",
        "Disabled Accounts",
    ]
    for entry in ad_domains:
        domain = _normalize_domain(entry)
        for metric in ad_metrics:
            key = f"ad_{domain}_{metric.lower().replace(' ', '_')}"
            questions.append(_high_medium_low_question(key, f"{metric}", f"Active Directory – {domain}"))

    password_policies: Iterable[Any] = _safe_get(workbook, "password", "policies", default=[]) or []
    for policy in password_policies:
        domain_name = _normalize_domain(policy, field="domain_name")
        key = f"password_policy_{domain_name}_risk"
        questions.append(
            _high_medium_low_question(
                key,
                f"What is the risk you assign for the passwords cracked in the '{domain_name}' domain?",
                "Password Policies",
            )
        )

    endpoint_domains: Iterable[Any] = _safe_get(workbook, "endpoint", "domains", default=[]) or []
    for entry in endpoint_domains:
        domain = _normalize_domain(entry)
        risk_key = f"endpoint_{domain}_av_risk"
        questions.append(
            _high_medium_low_question(
                risk_key,
                f"What is the risk you associate with the number of systems without active, up-to-date security software found in the '{domain}' domain?",
                "Endpoint",
            )
        )
        wifi_key = f"endpoint_{domain}_wifi_risk"
        questions.append(
            _high_medium_low_question(
                wifi_key,
                f"What is the risk you associate with the Open WiFi networks accessed on machines in the '{domain}' domain?",
                "Endpoint",
            )
        )

    questions.append(
        {
            "key": "wireless_network_risks",
            "label": "What is the risk you would assign to each of the following Wireless networks?",
            "type": "risk_matrix",
            "group": "Wireless",
            "rows": [
                {"key": "open_networks", "label": "Open Networks"},
                {"key": "psk_networks", "label": "PSK Networks"},
                {"key": "hidden_networks", "label": "Hidden Networks (typically Medium)"},
                {"key": "rogue_networks", "label": "Rogue Networks"},
            ],
            "choices": HIGH_MED_LOW_CHOICES,
        }
    )

    questions.append(
        _boolean_question(
            "wireless_psk_rotation_concern",
            "Are you concerned the PSK(s) is not changed periodically (or when people leave the org)?",
            "Wireless",
        )
    )

    weak_psks = str(_safe_get(workbook, "wireless", "weak_psks", default="no") or "no").lower()
    if weak_psks != "no":
        questions.append(
            {
                "key": "wireless_psk_weak_reasons",
                "label": "Why was the wireless PSK(s) weak?",
                "type": "multi_choice",
                "choices": [
                    {"value": "Too short", "label": "Too short"},
                    {"value": "Not enough entropy", "label": "Not enough entropy"},
                    {"value": "Based on dictionary word or Company name", "label": "Based on dictionary word or Company name"},
                ],
                "group": "Wireless",
            }
        )
        questions.append(
            _boolean_question(
                "wireless_psk_in_masterpass",
                "Was the PSK(s) contained in masterpass?",
                "Wireless",
            )
        )

    wep_confirm = str(_safe_get(workbook, "wireless", "wep_inuse", "confirm", default="no") or "no").lower()
    if wep_confirm == "yes":
        questions.append(
            {
                "key": "wireless_wep_crack_minutes",
                "label": "How many minutes did it take to crack the WEP key(s)?",
                "type": "number",
                "group": "Wireless",
                "min_value": 0,
            }
        )
        questions.append(
            {
                "key": "wireless_wep_ssids",
                "label": "Enter the WEP wireless network SSID(s)",
                "type": "list_text",
                "group": "Wireless",
            }
        )

    questions.append(
        {
            "key": "wireless_segmentation_tested",
            "label": "Did you test open/guest wireless network segmentation?",
            "type": "boolean_with_followup",
            "choices": YES_NO_CHOICES,
            "group": "Wireless",
            "followup": {
                "key": "wireless_segmentation_ssids",
                "label": "Enter the Guest/Open wireless network SSID(s)",
                "type": "list_text",
            },
        }
    )

    cloud_fail = _safe_get(workbook, "cloud_config", "fail", default=0) or 0
    if cloud_fail > 0:
        questions.append(
            _high_medium_low_question(
                "cloud_config_fail_risk",
                "What is the risk you would assign to the Cloud Management fails?",
                "Cloud",
            )
        )

    system_fail = _safe_get(workbook, "system_config", "total_fail", default=0) or 0
    if system_fail > 0:
        questions.append(
            _high_medium_low_question(
                "system_config_fail_risk",
                "What is the risk you would assign to the System Configuration fails?",
                "Configuration",
            )
        )

    return {
        "questions": questions,
        "required_files": required_files,
    }


def collect_responses(schema: Dict[str, Any], submitted: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Validate submitted values against the schema and return cleaned responses."""

    responses: Dict[str, Any] = {}
    errors: List[str] = []

    for question in schema.get("questions", []):
        try:
            cleaned = _extract_question_response(question, submitted)
        except ValueError as exc:
            errors.append(str(exc))
            continue

        # Remove keys that have ``None`` values to avoid storing noise
        for key, value in cleaned.items():
            if value is None:
                responses.pop(key, None)
            else:
                responses[key] = value

    return responses, errors


def _extract_question_response(question: Dict[str, Any], submitted: Any) -> Dict[str, Any]:
    key = question["key"]
    q_type = question.get("type", "text")
    choices = {choice["value"] for choice in question.get("choices", [])}

    if q_type == "text":
        value = (_get_value(submitted, key, "") or "").strip()
        return {key: value or None}

    if q_type in {"choice", "boolean"}:
        value = (_get_value(submitted, key, "") or "").strip()
        if value and choices and value not in choices:
            raise ValueError(f"Invalid option selected for '{question['label']}'.")
        return {key: value or None}

    if q_type == "multi_choice":
        values = [v for v in _get_list(submitted, key) if not choices or v in choices]
        return {key: values}

    if q_type == "number":
        raw_value = (_get_value(submitted, key, "") or "").strip()
        if raw_value == "":
            return {key: None}
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise ValueError(f"'{question['label']}' must be a whole number.") from exc

        min_value = question.get("min_value")
        if min_value is not None and value < min_value:
            raise ValueError(f"'{question['label']}' must be at least {min_value}.")
        return {key: value}

    if q_type == "list_text":
        values = [item.strip() for item in _get_list(submitted, key) if item.strip()]
        return {key: values}

    if q_type == "risk_matrix":
        row_values: Dict[str, Any] = {}
        for row in question.get("rows", []):
            row_key = f"{key}__{row['key']}"
            selected = (_get_value(submitted, row_key, "") or "").strip()
            if selected and choices and selected not in choices:
                raise ValueError(f"Invalid option selected for '{row['label']}'.")
            row_values[row["key"]] = selected or None
        return {key: row_values}

    if q_type == "boolean_with_followup":
        value = (_get_value(submitted, key, "") or "").strip()
        if value and choices and value not in choices:
            raise ValueError(f"Invalid option selected for '{question['label']}'.")
        cleaned = {key: value or None}
        followup = question.get("followup")
        if followup:
            followup_key = followup["key"]
            if value == "yes":
                cleaned[followup_key] = [item.strip() for item in _get_list(submitted, followup_key) if item.strip()]
            else:
                cleaned[followup_key] = None
        return cleaned

    return {key: _get_value(submitted, key, None)}


def _get_list(submitted: Any, key: str) -> List[str]:
    if hasattr(submitted, "getlist"):
        return list(submitted.getlist(key))
    value = submitted.get(key, []) if hasattr(submitted, "get") else []
    if isinstance(value, (list, tuple)):
        return list(value)
    if value in (None, ""):
        return []
    return [str(value)]


def _get_value(submitted: Any, key: str, default: Any = None) -> Any:
    if hasattr(submitted, "get"):
        return submitted.get(key, default)
    if isinstance(submitted, dict):
        return submitted.get(key, default)
    return default

