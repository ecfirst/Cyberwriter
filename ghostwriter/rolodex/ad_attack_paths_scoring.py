"""Rubric-based 1-6 risk scoring for the AD Attack Paths (AAP) workbook metrics.

Implements the per-check scoring rules from the "AD Attack-Path Risk Scoring
Rubric" reference document. Each function scores one metric from the raw CSV
rows uploaded for that metric (see ``ATTACK_PATHS_CSV_HEADER_MAP`` in
``ghostwriter/rolodex/views.py`` for the canonical column labels), for a
single domain at a time — mirroring how AD's own risk questionnaire rates
each domain independently rather than combining them. Where the rubric's top
tier requires data this tool doesn't have (e.g. a curated "tier-0 asset"
list, or whether a recovered password still authenticates somewhere),
scoring is capped at the highest tier computable from the CSV's own columns
rather than guessed.

An assessor can override any per-domain, per-metric score directly (see
``score_attack_paths_domain``); the override wins over the auto-computed
value whenever present. The project-wide summary (``score_attack_paths``)
rolls per-domain scores up by taking the worst (maximum) value across
domains, both per metric and for the overall aggregate — consistent with the
rubric's own philosophy that an attacker only needs the single easiest path.
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


# The 12 assessor-override field names, one per metric, stored alongside each
# domain's count fields in workbook_data["ad_attack_paths"]["domains"][i].
ATTACK_PATHS_SCORE_OVERRIDE_FIELDS: List[str] = [
    f"{metric_key}_score_override" for metric_key in ATTACK_PATHS_METRIC_KEYS
]


def _domain_key(entry: Optional[Mapping[str, Any]]) -> str:
    """Return a normalized (lowercased, stripped) domain name for matching."""

    if not isinstance(entry, Mapping):
        return ""
    value = entry.get("domain") or entry.get("name") or ""
    return str(value).strip().lower()


def _domain_rows(
    artifacts: Mapping[str, Any], domain_key: str, metric_key: str
) -> List[Mapping[str, Any]]:
    """Return the uploaded CSV rows for one domain's one metric."""

    domain_entry = artifacts.get(domain_key) if isinstance(artifacts, Mapping) else None
    if not isinstance(domain_entry, Mapping):
        return []
    rows = domain_entry.get(metric_key)
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _domain_privileged_count(ad_domain_entry: Optional[Mapping[str, Any]]) -> int:
    """Sum domain_admins + ent_admins for a single AD domain entry."""

    total = 0
    if not isinstance(ad_domain_entry, Mapping):
        return total
    for field in ("domain_admins", "ent_admins"):
        value = ad_domain_entry.get(field)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def _score_override(domain_entry: Mapping[str, Any], metric_key: str) -> Optional[int]:
    """Return a valid 1-6 assessor override for a metric, or None if not set."""

    if not isinstance(domain_entry, Mapping):
        return None
    value = domain_entry.get(f"{metric_key}_score_override")
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and 1 <= value <= 6:
        return int(value)
    return None


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


def score_attack_paths_domain(
    artifacts: Mapping[str, Any],
    domain_entry: Mapping[str, Any],
    ad_domain_entry: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Score one domain's 12 AD Attack Paths metrics, honoring any assessor overrides.

    ``artifacts`` is ``Project.data_artifacts["ad_attack_paths"]``. ``domain_entry``
    is this domain's entry from ``workbook_data["ad_attack_paths"]["domains"]``
    (carries any ``{metric}_score_override`` values). ``ad_domain_entry`` is the
    matching (by domain name) entry from ``workbook_data["ad"]["domains"]``, used
    only for the Privileged-NotProtected denominator.
    """

    domain_key = _domain_key(domain_entry)

    metric_scores: Dict[str, int] = {}
    for metric_key, score_fn in _SIMPLE_SCORE_FUNCTIONS.items():
        override = _score_override(domain_entry, metric_key)
        if override is not None:
            metric_scores[metric_key] = override
            continue
        rows = _domain_rows(artifacts, domain_key, metric_key)
        metric_scores[metric_key] = score_fn(rows)

    override = _score_override(domain_entry, "privileged_not_protected")
    if override is not None:
        metric_scores["privileged_not_protected"] = override
    else:
        rows = _domain_rows(artifacts, domain_key, "privileged_not_protected")
        total_privileged = _domain_privileged_count(ad_domain_entry)
        metric_scores["privileged_not_protected"] = score_privileged_not_protected(
            rows, total_privileged
        )

    return {"metric_scores": metric_scores, "aggregate": compute_aggregate(metric_scores)}


def score_attack_paths(
    artifacts: Optional[Mapping[str, Any]],
    attack_paths_domains: Optional[Sequence[Mapping[str, Any]]] = None,
    ad_domains: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Score every AD Attack Paths domain and roll up a project-wide summary.

    ``artifacts`` is ``Project.data_artifacts["ad_attack_paths"]`` (domain -> metric
    -> parsed CSV rows). ``attack_paths_domains`` is
    ``workbook_data["ad_attack_paths"]["domains"]`` — drives which domains get
    scored and carries any assessor score overrides. ``ad_domains`` is
    ``workbook_data["ad"]["domains"]``, matched by domain name to cross-reference
    the Privileged-NotProtected denominator for that same domain.

    Returns ``{"domains": {name: {"metric_scores": ..., "aggregate": ...}},
    "metric_scores": {...}, "aggregate": ...}`` — the top-level ``metric_scores``/
    ``aggregate`` are project-wide roll-ups (the worst value across domains, per
    metric and overall), kept at the same keys the Scoring card and IAM grading
    already read.
    """

    artifacts = artifacts if isinstance(artifacts, Mapping) else {}

    ad_domains_by_key: Dict[str, Mapping[str, Any]] = {}
    if isinstance(ad_domains, Sequence):
        for entry in ad_domains:
            if isinstance(entry, Mapping):
                key = _domain_key(entry)
                if key:
                    ad_domains_by_key[key] = entry

    domains_result: Dict[str, Any] = {}
    if isinstance(attack_paths_domains, Sequence):
        for domain_entry in attack_paths_domains:
            if not isinstance(domain_entry, Mapping):
                continue
            domain_name = (domain_entry.get("domain") or domain_entry.get("name") or "").strip()
            if not domain_name:
                continue
            ad_domain_entry = ad_domains_by_key.get(_domain_key(domain_entry))
            domains_result[domain_name] = score_attack_paths_domain(
                artifacts, domain_entry, ad_domain_entry
            )

    if not domains_result:
        # No domains configured at all: fall back to the same "everything
        # clean" baseline every individual check already returns for 0 rows.
        baseline_scores = {metric_key: 1 for metric_key in ATTACK_PATHS_METRIC_KEYS}
        return {
            "domains": {},
            "metric_scores": baseline_scores,
            "aggregate": compute_aggregate(baseline_scores),
        }

    rollup_metric_scores: Dict[str, int] = {}
    for metric_key in ATTACK_PATHS_METRIC_KEYS:
        rollup_metric_scores[metric_key] = max(
            result["metric_scores"][metric_key] for result in domains_result.values()
        )

    domain_aggregates = [
        result["aggregate"]
        for result in domains_result.values()
        if result["aggregate"] is not None
    ]
    aggregate = max(domain_aggregates) if domain_aggregates else None

    return {
        "domains": domains_result,
        "metric_scores": rollup_metric_scores,
        "aggregate": aggregate,
    }
