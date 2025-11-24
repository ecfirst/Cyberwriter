"""Helpers for capturing workbook data via inline entry forms."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from decimal import Decimal
import math
from typing import Any, Dict, Mapping, MutableMapping, Optional, Sequence

from ghostwriter.reporting.models import RiskScoreRangeMapping
from ghostwriter.rolodex.models import normalize_project_scoping
from ghostwriter.rolodex.workbook_defaults import normalize_workbook_payload


_SCORE_PRECISION = Decimal("0.1")
_SCORE_MIN = Decimal("0.0")
_SCORE_MAX = Decimal("6.0")

GENERAL_FIELDS = {
    "external_start",
    "external_end",
    "internal_start",
    "internal_end",
    "cloud_start",
    "cloud_end",
    "wireless",
    "firewall",
    "internal_subnets",
    "cloud_provider",
}

OSINT_FIELDS = {
    "total_domains",
    "total_hostnames",
    "total_ips",
    "total_cloud",
    "total_buckets",
    "total_squat",
    "total_leaks",
}

AREA_FIELDS = {"osint": OSINT_FIELDS, "dns": set()}


def _as_decimal(value: Any) -> Optional[Decimal]:
    if value in (None, ""):
        return None
    try:
        decimal_value = Decimal(str(value)).quantize(_SCORE_PRECISION)
    except Exception:
        return None
    if decimal_value < _SCORE_MIN:
        return _SCORE_MIN
    if decimal_value > _SCORE_MAX:
        return _SCORE_MAX
    return decimal_value


def _score_to_risk(score: Optional[Decimal], score_map: Mapping[str, Any]) -> Optional[str]:
    if score is None:
        return None
    for risk, bounds in score_map.items():
        lower, upper = bounds
        if lower is None or upper is None:
            continue
        if lower <= score <= upper:
            return risk
    return None


def _as_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, Decimal)):
        return int(value)
    if isinstance(value, float):
        if math.isnan(value):
            return None
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(float(text))
        except ValueError:
            return None
    return None


def _normalize_general_payload(payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    if not isinstance(payload, Mapping):
        return normalized
    for field in GENERAL_FIELDS:
        value = payload.get(field)
        if value in (None, ""):
            normalized[field] = None
        else:
            normalized[field] = str(value)
    return normalized


def _normalize_dns_payload(payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {"records": []}
    if not isinstance(payload, Mapping):
        return normalized

    records = payload.get("records")
    if isinstance(records, Sequence):
        for record in records:
            if not isinstance(record, Mapping):
                continue
            normalized_record: Dict[str, Any] = {}
            domain = record.get("domain")
            if domain not in (None, ""):
                domain_text = str(domain).strip()
                if domain_text:
                    normalized_record["domain"] = domain_text
            total = _as_int(record.get("total"))
            if total is not None:
                normalized_record["total"] = total
            zone_transfer = record.get("zone_transfer")
            if zone_transfer not in (None, ""):
                if isinstance(zone_transfer, bool):
                    normalized_record["zone_transfer"] = zone_transfer
                else:
                    zone_text = str(zone_transfer).strip()
                    if zone_text:
                        normalized_record["zone_transfer"] = zone_text
            if normalized_record:
                normalized["records"].append(normalized_record)

    if "unique" in payload:
        normalized["unique"] = _as_int(payload.get("unique"))

    return normalized


def _normalize_area_payload(area: str, payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    if area == "dns":
        return _normalize_dns_payload(payload)
    allowed_fields = AREA_FIELDS.get(area, set())
    if not allowed_fields or not isinstance(payload, Mapping):
        return normalized
    for field in allowed_fields:
        if field in payload:
            normalized[field] = _as_int(payload.get(field))
    return normalized


def _calculate_category_total(
    *, scores: Mapping[str, Optional[Decimal]], weights: Mapping[str, Decimal]
) -> Optional[Decimal]:
    if not scores:
        return None
    if not weights:
        provided = [score for score in scores.values() if score is not None]
        if not provided:
            return None
        return sum(provided) / Decimal(len(provided))

    total = Decimal("0")
    for option, weight in weights.items():
        score = scores.get(option) or Decimal("0")
        total += score * weight
    return total.quantize(_SCORE_PRECISION)


def _normalize_score_map(score_map: Mapping[str, Mapping[str, Any]]) -> OrderedDict[str, tuple[Decimal, Decimal]]:
    normalized: "OrderedDict[str, tuple[Decimal, Decimal]]" = OrderedDict()
    for risk, bounds in score_map.items():
        try:
            lower, upper = bounds
        except Exception:
            continue
        try:
            normalized[risk] = (Decimal(lower), Decimal(upper))
        except Exception:
            continue
    return normalized


def _compute_overall_grade(
    *,
    category_scores: Mapping[str, Optional[Decimal]],
    risk_score_map: Mapping[str, Any],
    scoping: Mapping[str, Mapping[str, Any]],
) -> Optional[str]:
    totals: list[Decimal] = []
    for category, score in category_scores.items():
        if score is None:
            continue
        scope_state = scoping.get(category, {})
        if not scope_state.get("selected"):
            continue
        adjusted = score
        if category == "wireless":
            adjusted = score * Decimal("0.9")
        totals.append(adjusted)
    if not totals:
        return None
    average = (sum(totals) / Decimal(len(totals))).quantize(_SCORE_PRECISION)
    return _score_to_risk(average, risk_score_map)


def build_workbook_entry_payload(
    *,
    project,
    general: Optional[Mapping[str, Any]] = None,
    scores: Optional[Mapping[str, Any]] = None,
    grades: Optional[Mapping[str, Any]] = None,
    areas: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return updated workbook data for inline workbook entry."""

    normalized_workbook = normalize_workbook_payload(getattr(project, "workbook_data", {}))
    scoping_state = normalize_project_scoping(getattr(project, "scoping", {}))
    risk_score_map = _normalize_score_map(RiskScoreRangeMapping.get_risk_score_map())

    if general:
        normalized_general = _normalize_general_payload(general)
        normalized_workbook.setdefault("general", {}).update(normalized_general)

    if isinstance(areas, Mapping):
        for area_key, area_payload in areas.items():
            normalized_area = _normalize_area_payload(area_key, area_payload)
            if normalized_area:
                normalized_workbook.setdefault(area_key, {}).update(normalized_area)

    score_updates: MutableMapping[str, MutableMapping[str, Any]] = {}
    category_scores: Dict[str, Optional[Decimal]] = {}
    if isinstance(scores, Mapping):
        score_updates = deepcopy(normalized_workbook.get("external_internal_grades", {}))
        scoping_weights = getattr(project, "scoping_weights", {}) or {}
        for category, option_payload in scores.items():
            if not isinstance(option_payload, Mapping):
                continue
            category_entry = score_updates.setdefault(category, {})
            option_scores: Dict[str, Optional[Decimal]] = {}
            for option_key, value in option_payload.items():
                score_value = _as_decimal(value)
                option_scores[option_key] = score_value
                if isinstance(category_entry.get(option_key), Mapping):
                    category_entry[option_key]["score"] = None if score_value is None else float(score_value)
                    category_entry[option_key]["risk"] = _score_to_risk(score_value, risk_score_map)
                else:
                    category_entry[option_key] = {
                        "score": None if score_value is None else float(score_value),
                        "risk": _score_to_risk(score_value, risk_score_map),
                    }
            weights = scoping_weights.get(category, {}) or {}
            total = _calculate_category_total(scores=option_scores, weights=weights)
            category_scores[category] = total
            category_entry["total"] = None if total is None else float(total)
            category_entry["grade"] = _score_to_risk(total, risk_score_map)
        normalized_workbook["external_internal_grades"] = score_updates

    grade_updates: Dict[str, Any] = {}
    if isinstance(grades, Mapping):
        for key, value in grades.items():
            if value in (None, ""):
                continue
            grade_updates[key] = str(value)

    if category_scores and not grade_updates:
        grade_updates = {category: details.get("grade") for category, details in score_updates.items()}

    if category_scores:
        overall_grade = _compute_overall_grade(
            category_scores=category_scores,
            risk_score_map=risk_score_map,
            scoping=scoping_state,
        )
        if overall_grade:
            grade_updates.setdefault("overall", overall_grade)

    if grade_updates:
        normalized_workbook.setdefault("report_card", {}).update(grade_updates)

    return normalized_workbook
