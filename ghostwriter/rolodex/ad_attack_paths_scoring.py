"""Rubric-based 1-6 risk scoring for the AD Attack Paths (AAP) workbook metrics.

Implements the per-check scoring rules from the "AD Attack-Path Risk Scoring
Rubric" reference document. Each function scores one metric from the raw CSV
rows uploaded for that metric (see ``ATTACK_PATHS_CSV_HEADER_MAP`` in
``ghostwriter/rolodex/views.py`` for the canonical column labels), combined
across every domain in the project. Where the rubric's top tier requires data
this tool doesn't have (e.g. a curated "tier-0 asset" list, or whether a
recovered password still authenticates somewhere), scoring is capped at the
highest tier computable from the CSV's own columns rather than guessed.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

_ESC_PATTERN = re.compile(r"ESC\s*(\d+)", re.IGNORECASE)

_HIGH_ESC_CLASSES = {"1", "3", "4", "8", "15"}
_MEDIUM_ESC_CLASSES = {"2"}
_LOW_ESC_CLASSES = {"9", "13"}
_CA_CONFIG_ESC_CLASSES = {"6", "7", "8"}


def _text(row: Mapping[str, Any], field: str) -> str:
    """Return a row field as a stripped string, tolerant of missing/None values."""

    value = row.get(field) if isinstance(row, Mapping) else None
    return (value or "").strip()


def _is_yes(row: Mapping[str, Any], field: str) -> bool:
    return _text(row, field).lower() == "yes"


def _safe_number(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _parse_esc_classes(text: str) -> set:
    return {match.group(1) for match in _ESC_PATTERN.finditer(text or "")}


def score_kerberoastable(rows: Sequence[Mapping[str, Any]]) -> int:
    """Shared logic for both ``kerberoastable`` and ``asrep_roastable``."""

    if not rows:
        return 1

    privileged_rows = [row for row in rows if _is_yes(row, "Privileged")]
    if privileged_rows:
        for row in privileged_rows:
            days = _safe_number(row.get("Days Since Pwd Set"))
            if days is not None and days > 365:
                return 6
        return 5

    non_privileged_count = len(rows)
    if non_privileged_count <= 3:
        return 2
    if non_privileged_count <= 10:
        return 3
    return 4


# AS-REP Roastable uses the exact same columns and tiers as Kerberoastable.
score_asrep_roastable = score_kerberoastable


def score_unconstrained_delegation(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    user_rows = [row for row in rows if _text(row, "Type").lower() == "user"]
    if len(user_rows) >= 2:
        return 6
    if len(user_rows) >= 1:
        return 5
    # Any other rows (Computer, or an unrecognized/blank Type) land on the
    # lower defined tier rather than being escalated on ambiguous data.
    return 4


def score_constrained_delegation(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    t2a4d_rows = [row for row in rows if _is_yes(row, "ProtocolTransition")]
    t2a4d_count = len(t2a4d_rows)
    standard_count = len(rows) - t2a4d_count

    if t2a4d_count >= 10:
        return 6
    if t2a4d_count >= 3:
        return 5
    if t2a4d_count >= 1 or standard_count >= 21:
        return 4
    if standard_count >= 6:
        return 3
    if standard_count >= 1:
        return 2
    return 1


def score_rbcd(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    count = len(rows)
    has_undecodable = any(
        "unable to decode" in _text(row, "AllowedPrincipal").lower() for row in rows
    )
    # Tier 6 ("target is a DC or tier-0 asset") needs a curated asset list
    # this tool doesn't have, so scoring is capped at 4.
    if count >= 11 or has_undecodable:
        return 4
    if count >= 3:
        return 3
    return 2


def score_shadow_credentials(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    # Tiers 4 ("> 5% of enabled accounts") and 6 ("any on a privileged
    # account") need data this CSV doesn't carry, so scoring is capped at 3.
    if len(rows) <= 3:
        return 2
    return 3


def score_privileged_not_protected(
    rows: Sequence[Mapping[str, Any]], total_privileged: int
) -> int:
    not_protected_count = len(rows)
    if not_protected_count == 0:
        return 1

    if total_privileged and not_protected_count >= total_privileged and total_privileged >= 5:
        return 6

    if total_privileged and total_privileged > 0:
        coverage = 1 - (not_protected_count / total_privileged)
        if coverage >= 0.75:
            return 2
        if coverage >= 0.50:
            return 3
        if coverage >= 0.25:
            return 4
        return 5

    # AD's domain_admins/ent_admins counts weren't available to compute a
    # real percentage; approximate off the raw not-protected count instead.
    if not_protected_count <= 2:
        return 3
    if not_protected_count <= 4:
        return 4
    return 5


_LAPS_SCHEMA_ABSENT_TEXT = "laps schema not found in ad"


def score_laps_coverage(rows: Sequence[Mapping[str, Any]]) -> int:
    if len(rows) == 1 and _text(rows[0], "Expiration").lower() == _LAPS_SCHEMA_ABSENT_TEXT:
        return 6

    if not rows:
        return 1

    covered = [
        row for row in rows if _is_yes(row, "LegacyLAPS") or _is_yes(row, "WindowsLAPS")
    ]
    coverage = len(covered) / len(rows)

    if coverage <= 0:
        return 5
    if coverage >= 0.90:
        return 1
    if coverage >= 0.75:
        return 2
    if coverage >= 0.50:
        return 3
    if coverage >= 0.25:
        return 4
    return 5


def score_gpp_passwords(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1
    # Tier 6 ("decrypted password still authenticates somewhere") needs
    # cross-referencing live/active accounts, which this tool doesn't do.
    return 5


def score_ldap_bind_test(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    total = len(rows)
    anonymous_yes = [row for row in rows if _is_yes(row, "AnonymousBind")]
    if anonymous_yes:
        return 6 if len(anonymous_yes) == total else 5

    unsigned_yes = [row for row in rows if _is_yes(row, "UnsignedBind")]
    if unsigned_yes:
        return 4 if len(unsigned_yes) == total else 3

    return 1


def score_adcs_vulnerable_templates(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    per_row_classes = [_parse_esc_classes(_text(row, "ESCFindings")) for row in rows]
    all_classes: set = set()
    for classes in per_row_classes:
        all_classes |= classes
    templates_with_findings = sum(1 for classes in per_row_classes if classes)

    if all_classes & _HIGH_ESC_CLASSES:
        return 6
    if templates_with_findings >= 2 or len(all_classes) >= 2:
        return 6
    if all_classes & _MEDIUM_ESC_CLASSES:
        return 5
    if all_classes & _LOW_ESC_CLASSES:
        return 4
    return 1


def score_adcs_ca_config(rows: Sequence[Mapping[str, Any]]) -> int:
    if not rows:
        return 1

    matching_rows = [
        row
        for row in rows
        if _parse_esc_classes(_text(row, "Findings")) & _CA_CONFIG_ESC_CLASSES
    ]
    if len(matching_rows) >= 2:
        return 6
    if len(matching_rows) >= 1:
        return 5
    return 1


# Metrics that don't need any cross-referenced context beyond their own rows.
_SIMPLE_SCORE_FUNCTIONS: Dict[str, Callable[[Sequence[Mapping[str, Any]]], int]] = {
    "kerberoastable": score_kerberoastable,
    "asrep_roastable": score_asrep_roastable,
    "unconstrained_delegation": score_unconstrained_delegation,
    "constrained_delegation": score_constrained_delegation,
    "rbcd": score_rbcd,
    "shadow_credentials": score_shadow_credentials,
    "laps_coverage": score_laps_coverage,
    "gpp_passwords": score_gpp_passwords,
    "ldap_bind_test": score_ldap_bind_test,
    "adcs_vulnerable_templates": score_adcs_vulnerable_templates,
    "adcs_ca_config": score_adcs_ca_config,
}

# All 12 metric keys this scorer understands, in rubric-table order.
ATTACK_PATHS_METRIC_KEYS: List[str] = [
    "kerberoastable",
    "asrep_roastable",
    "unconstrained_delegation",
    "constrained_delegation",
    "rbcd",
    "shadow_credentials",
    "privileged_not_protected",
    "laps_coverage",
    "gpp_passwords",
    "ldap_bind_test",
    "adcs_vulnerable_templates",
    "adcs_ca_config",
]


def _combined_rows(artifacts: Mapping[str, Any], metric_key: str) -> List[Mapping[str, Any]]:
    """Concatenate a metric's uploaded rows across every domain."""

    combined: List[Mapping[str, Any]] = []
    if not isinstance(artifacts, Mapping):
        return combined
    for domain_entry in artifacts.values():
        if not isinstance(domain_entry, Mapping):
            continue
        rows = domain_entry.get(metric_key)
        if isinstance(rows, list):
            combined.extend(row for row in rows if isinstance(row, Mapping))
    return combined


def _total_privileged_accounts(ad_domains: Optional[Sequence[Mapping[str, Any]]]) -> int:
    """Sum domain_admins + ent_admins across every AD domain in the project."""

    total = 0
    if not isinstance(ad_domains, Sequence):
        return total
    for domain_entry in ad_domains:
        if not isinstance(domain_entry, Mapping):
            continue
        for field in ("domain_admins", "ent_admins"):
            value = domain_entry.get(field)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                total += int(value)
    return total


def compute_aggregate(metric_scores: Mapping[str, int]) -> Optional[float]:
    """Aggregate = max of the per-check scores, +0.5 (capped at 6) if 2+ checks scored >=5."""

    scores = [score for score in metric_scores.values() if isinstance(score, (int, float))]
    if not scores:
        return None

    aggregate = float(max(scores))
    high_count = sum(1 for score in scores if score >= 5)
    if high_count >= 2:
        aggregate = min(aggregate + 0.5, 6.0)
    return aggregate


def score_attack_paths(
    artifacts: Optional[Mapping[str, Any]],
    ad_domains: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Score every AD Attack Paths metric and return the per-check scores + aggregate.

    ``artifacts`` is ``Project.data_artifacts["ad_attack_paths"]`` (domain -> metric
    -> parsed CSV rows). ``ad_domains`` is ``workbook_data["ad"]["domains"]``,
    used only to cross-reference the Privileged-NotProtected denominator.
    """

    artifacts = artifacts if isinstance(artifacts, Mapping) else {}

    metric_scores: Dict[str, int] = {}
    for metric_key, score_fn in _SIMPLE_SCORE_FUNCTIONS.items():
        rows = _combined_rows(artifacts, metric_key)
        metric_scores[metric_key] = score_fn(rows)

    privileged_not_protected_rows = _combined_rows(artifacts, "privileged_not_protected")
    total_privileged = _total_privileged_accounts(ad_domains)
    metric_scores["privileged_not_protected"] = score_privileged_not_protected(
        privileged_not_protected_rows, total_privileged
    )

    aggregate = compute_aggregate(metric_scores)

    return {"metric_scores": metric_scores, "aggregate": aggregate}
