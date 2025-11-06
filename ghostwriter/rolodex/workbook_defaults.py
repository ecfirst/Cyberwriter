"""Default workbook schema utilities."""

from __future__ import annotations

from typing import Any, Mapping, MutableMapping

WORKBOOK_DATA_SCHEMA: Mapping[str, Any] = {
    "ad": {"domains": []},
    "client": {
        "name": None,
        "primary_contact": None,
        "primary_contact_email": None,
        "short_name": None,
    },
    "cloud_config": {"fail": None, "pass": None},
    "dns": {"records": [], "unique": None},
    "endpoint": {"domains": []},
    "external_internal_grades": {
        "external": {
            "dns": {"risk": None, "score": None},
            "grade": None,
            "nexpose": {"risk": None, "score": None},
            "osint": {"risk": None, "score": None},
            "total": None,
            "web": {"risk": None, "score": None},
        },
        "internal": {
            "cloud": {"risk": None, "score": None},
            "configuration": {"risk": None, "score": None},
            "endpoint": {"risk": None, "score": None},
            "grade": None,
            "iam": {"risk": None, "score": None},
            "nexpose": {"risk": None, "score": None},
            "password": {"risk": None, "score": None},
            "snmp": {"risk": None, "score": None},
            "sql": {"risk": None, "score": None},
            "total": None,
        },
    },
    "external_nexpose": {
        "majority_type": None,
        "minority_type": None,
        "total": None,
        "total_high": None,
        "total_low": None,
        "total_med": None,
        "unique": None,
        "unique_high_med": None,
        "unique_majority": None,
        "unique_majority_sub": None,
        "unique_majority_sub_info": None,
        "unique_minority": None,
    },
    "firewall": {
        "complexity_count": None,
        "devices": [],
        "majority_count": None,
        "majority_type": None,
        "minority_count": None,
        "minority_type": None,
        "unique": None,
        "unique_high": None,
        "unique_low": None,
        "unique_med": None,
    },
    "general": {
        "cloud_provider": None,
        "external_end": None,
        "external_start": None,
        "firewall": None,
        "internal_end": None,
        "internal_start": None,
        "internal_subnets": None,
        "wireless": None,
    },
    "internal_nexpose": {
        "majority_type": None,
        "minority_type": None,
        "total": None,
        "total_high": None,
        "total_low": None,
        "total_med": None,
        "unique": None,
        "unique_high_med": None,
        "unique_majority": None,
        "unique_majority_sub": None,
        "unique_majority_sub_info": None,
        "unique_minority": None,
    },
    "iot_iomt_nexpose": {
        "majority_type": None,
        "minority_type": None,
        "total": None,
        "total_high": None,
        "total_low": None,
        "total_med": None,
        "unique": None,
        "unique_high_med": None,
        "unique_majority": None,
        "unique_majority_sub": None,
        "unique_majority_sub_info": None,
        "unique_minority": None,
    },
    "osint": {
        "total_buckets": None,
        "total_cloud": None,
        "total_domains": None,
        "total_hostnames": None,
        "total_ips": None,
        "total_leaks": None,
        "total_squat": None,
    },
    "password": {"policies": []},
    "report_card": {
        "external": None,
        "firewall": None,
        "internal": None,
        "overall": None,
        "wireless": None,
    },
    "snmp": {
        "read_write_access": None,
        "subnets": None,
        "total_strings": None,
        "total_systems": None,
    },
    "sql": {
        "db_types": None,
        "subnets": None,
        "total_open": None,
        "unsupported_dbs": {"confirm": None, "count": None},
        "weak_creds": None,
    },
    "system_config": {
        "total_fail": None,
        "total_pass": None,
        "unique_fail": None,
        "unique_pass": None,
    },
    "web": {
        "combined_unique": None,
        "combined_unique_high": None,
        "combined_unique_low": None,
        "combined_unique_med": None,
        "sites": None,
    },
    "wireless": {
        "802_1x_used": None,
        "hidden_count": None,
        "internal_access": None,
        "open_count": None,
        "psk_count": None,
        "rogue_count": None,
        "rogue_signals": None,
        "weak_psks": None,
        "wep_inuse": {"confirm": None, "key_cracked": None},
    },
}


def _build_default_from_schema(schema_value: Any) -> Any:
    if isinstance(schema_value, Mapping):
        return {key: _build_default_from_schema(value) for key, value in schema_value.items()}
    if isinstance(schema_value, list):
        return []
    return None


def apply_workbook_defaults(workbook_data: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Ensure ``workbook_data`` contains all schema keys with appropriate defaults."""

    for key, schema_value in WORKBOOK_DATA_SCHEMA.items():
        current_value = workbook_data.get(key)
        if current_value is None:
            workbook_data[key] = _build_default_from_schema(schema_value)
        elif isinstance(schema_value, Mapping) and isinstance(current_value, MutableMapping):
            _ensure_nested_defaults(current_value, schema_value)
    return workbook_data


def _ensure_nested_defaults(target: MutableMapping[str, Any], schema: Mapping[str, Any]) -> None:
    for nested_key, nested_schema in schema.items():
        current = target.get(nested_key)
        if current is None:
            target[nested_key] = _build_default_from_schema(nested_schema)
        elif isinstance(nested_schema, Mapping) and isinstance(current, MutableMapping):
            _ensure_nested_defaults(current, nested_schema)
