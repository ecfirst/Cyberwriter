"""Tests for the AD Attack Paths rubric scoring engine."""

from django.test import SimpleTestCase

from ghostwriter.rolodex.ad_attack_paths_scoring import (
    compute_aggregate,
    score_adcs_ca_config,
    score_adcs_vulnerable_templates,
    score_attack_paths,
    score_constrained_delegation,
    score_gpp_passwords,
    score_kerberoastable,
    score_laps_coverage,
    score_ldap_bind_test,
    score_privileged_not_protected,
    score_rbcd,
    score_shadow_credentials,
    score_unconstrained_delegation,
)


def _rows(n, **fields):
    return [dict(fields) for _ in range(n)]


class KerberoastableScoringTests(SimpleTestCase):
    """Also covers AS-REP Roastable, which shares the same logic/columns."""

    def test_zero_rows_scores_low(self):
        self.assertEqual(score_kerberoastable([]), 1)

    def test_non_privileged_tiers(self):
        self.assertEqual(score_kerberoastable(_rows(2, Privileged="No")), 2)
        self.assertEqual(score_kerberoastable(_rows(3, Privileged="No")), 2)
        self.assertEqual(score_kerberoastable(_rows(4, Privileged="No")), 3)
        self.assertEqual(score_kerberoastable(_rows(10, Privileged="No")), 3)
        self.assertEqual(score_kerberoastable(_rows(11, Privileged="No")), 4)

    def test_any_privileged_row_scores_five(self):
        rows = [{"Privileged": "Yes", "Days Since Pwd Set": "100"}]
        self.assertEqual(score_kerberoastable(rows), 5)

    def test_privileged_and_stale_password_scores_six(self):
        rows = [{"Privileged": "Yes", "Days Since Pwd Set": "400"}]
        self.assertEqual(score_kerberoastable(rows), 6)

    def test_privileged_takes_priority_over_non_privileged_count(self):
        rows = _rows(20, Privileged="No") + [{"Privileged": "Yes", "Days Since Pwd Set": "1"}]
        self.assertEqual(score_kerberoastable(rows), 5)


class UnconstrainedDelegationScoringTests(SimpleTestCase):
    def test_tiers(self):
        self.assertEqual(score_unconstrained_delegation([]), 1)
        self.assertEqual(score_unconstrained_delegation(_rows(1, Type="Computer")), 4)
        self.assertEqual(score_unconstrained_delegation(_rows(1, Type="User")), 5)
        self.assertEqual(score_unconstrained_delegation(_rows(2, Type="User")), 6)

    def test_unrecognized_type_does_not_escalate(self):
        self.assertEqual(score_unconstrained_delegation(_rows(3, Type="")), 4)


class ConstrainedDelegationScoringTests(SimpleTestCase):
    def test_standard_tiers(self):
        self.assertEqual(score_constrained_delegation([]), 1)
        self.assertEqual(score_constrained_delegation(_rows(3, ProtocolTransition="No")), 2)
        self.assertEqual(score_constrained_delegation(_rows(10, ProtocolTransition="No")), 3)
        self.assertEqual(score_constrained_delegation(_rows(21, ProtocolTransition="No")), 4)

    def test_t2a4d_tiers(self):
        self.assertEqual(score_constrained_delegation(_rows(1, ProtocolTransition="Yes")), 4)
        self.assertEqual(score_constrained_delegation(_rows(3, ProtocolTransition="Yes")), 5)
        self.assertEqual(score_constrained_delegation(_rows(10, ProtocolTransition="Yes")), 6)


class RbcdScoringTests(SimpleTestCase):
    def test_row_count_tiers(self):
        self.assertEqual(score_rbcd([]), 1)
        self.assertEqual(score_rbcd(_rows(2, AllowedPrincipal="S-1-5-21")), 2)
        self.assertEqual(score_rbcd(_rows(3, AllowedPrincipal="S-1-5-21")), 3)
        self.assertEqual(score_rbcd(_rows(11, AllowedPrincipal="S-1-5-21")), 4)

    def test_undecodable_principal_caps_at_four(self):
        rows = [{"AllowedPrincipal": "Unable to decode security descriptor"}]
        self.assertEqual(score_rbcd(rows), 4)


class ShadowCredentialsScoringTests(SimpleTestCase):
    def test_tiers_capped_below_percentage_and_privileged_criteria(self):
        self.assertEqual(score_shadow_credentials([]), 1)
        self.assertEqual(score_shadow_credentials(_rows(3)), 2)
        self.assertEqual(score_shadow_credentials(_rows(4)), 3)
        self.assertEqual(score_shadow_credentials(_rows(100)), 3)


class PrivilegedNotProtectedScoringTests(SimpleTestCase):
    def test_no_rows_is_fully_covered(self):
        self.assertEqual(score_privileged_not_protected([], 10), 1)

    def test_percentage_tiers(self):
        self.assertEqual(score_privileged_not_protected(_rows(1), 10), 2)  # 90% coverage
        self.assertEqual(score_privileged_not_protected(_rows(3), 10), 3)  # 70% coverage
        self.assertEqual(score_privileged_not_protected(_rows(6), 10), 4)  # 40% coverage
        self.assertEqual(score_privileged_not_protected(_rows(9), 10), 5)  # 10% coverage

    def test_group_empty_or_missing(self):
        self.assertEqual(score_privileged_not_protected(_rows(5), 5), 6)

    def test_group_empty_but_below_five_does_not_hit_top_tier(self):
        self.assertEqual(score_privileged_not_protected(_rows(3), 3), 5)

    def test_falls_back_to_raw_count_when_total_unknown(self):
        self.assertEqual(score_privileged_not_protected(_rows(2), 0), 3)
        self.assertEqual(score_privileged_not_protected(_rows(4), 0), 4)
        self.assertEqual(score_privileged_not_protected(_rows(5), 0), 5)


class LapsCoverageScoringTests(SimpleTestCase):
    def test_schema_absent(self):
        rows = [{"Expiration": "LAPS schema not found in AD"}]
        self.assertEqual(score_laps_coverage(rows), 6)

    def test_no_computers_tracked(self):
        self.assertEqual(score_laps_coverage([]), 1)

    def test_coverage_tiers(self):
        covered = _rows(9, LegacyLAPS="Yes")
        uncovered = _rows(1, LegacyLAPS="No")
        self.assertEqual(score_laps_coverage(covered + uncovered), 1)  # 90%
        self.assertEqual(score_laps_coverage(_rows(10, LegacyLAPS="No")), 5)  # 0%
        self.assertEqual(
            score_laps_coverage(_rows(3, LegacyLAPS="Yes") + _rows(7, LegacyLAPS="No")), 4
        )  # 30%

    def test_windows_laps_also_counts_as_covered(self):
        rows = _rows(10, LegacyLAPS="No", WindowsLAPS="Yes")
        self.assertEqual(score_laps_coverage(rows), 1)


class GppPasswordsScoringTests(SimpleTestCase):
    def test_tiers(self):
        self.assertEqual(score_gpp_passwords([]), 1)
        self.assertEqual(score_gpp_passwords(_rows(1)), 5)


class LdapBindTestScoringTests(SimpleTestCase):
    def test_clean(self):
        rows = _rows(2, AnonymousBind="No", UnsignedBind="No")
        self.assertEqual(score_ldap_bind_test(rows), 1)

    def test_unsigned_bind_tiers(self):
        rows = [
            {"AnonymousBind": "No", "UnsignedBind": "Yes"},
            {"AnonymousBind": "No", "UnsignedBind": "No"},
        ]
        self.assertEqual(score_ldap_bind_test(rows), 3)
        self.assertEqual(score_ldap_bind_test(_rows(2, AnonymousBind="No", UnsignedBind="Yes")), 4)

    def test_anonymous_bind_tiers(self):
        rows = [
            {"AnonymousBind": "Yes", "UnsignedBind": "No"},
            {"AnonymousBind": "No", "UnsignedBind": "No"},
        ]
        self.assertEqual(score_ldap_bind_test(rows), 5)
        self.assertEqual(score_ldap_bind_test(_rows(2, AnonymousBind="Yes")), 6)


class AdcsVulnerableTemplatesScoringTests(SimpleTestCase):
    def test_tiers(self):
        self.assertEqual(score_adcs_vulnerable_templates([]), 1)
        self.assertEqual(score_adcs_vulnerable_templates([{"ESCFindings": "ESC9"}]), 4)
        self.assertEqual(score_adcs_vulnerable_templates([{"ESCFindings": "ESC2"}]), 5)
        self.assertEqual(score_adcs_vulnerable_templates([{"ESCFindings": "ESC1"}]), 6)

    def test_multiple_templates_with_findings_scores_six(self):
        rows = [{"ESCFindings": "ESC9"}, {"ESCFindings": "ESC13"}]
        self.assertEqual(score_adcs_vulnerable_templates(rows), 6)

    def test_unrecognized_findings_text_does_not_escalate(self):
        self.assertEqual(score_adcs_vulnerable_templates([{"ESCFindings": ""}]), 1)


class AdcsCaConfigScoringTests(SimpleTestCase):
    def test_tiers(self):
        self.assertEqual(score_adcs_ca_config([]), 1)
        self.assertEqual(score_adcs_ca_config([{"Findings": "ESC6 detected"}]), 5)
        self.assertEqual(
            score_adcs_ca_config([{"Findings": "ESC6"}, {"Findings": "ESC7"}]), 6
        )

    def test_every_row_treated_as_a_real_finding(self):
        # No "housekeeping row" detection: any row without a matching ESC token
        # simply doesn't contribute, but isn't excluded/nulled either.
        self.assertEqual(score_adcs_ca_config([{"Findings": "no issues"}]), 1)


class AggregateScoringTests(SimpleTestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(compute_aggregate({}))

    def test_max_of_scores(self):
        self.assertEqual(compute_aggregate({"a": 6, "b": 1, "c": 1}), 6.0)

    def test_compounding_bump_when_two_or_more_high(self):
        self.assertEqual(compute_aggregate({"a": 5, "b": 5, "c": 1}), 5.5)

    def test_compounding_bump_capped_at_six(self):
        self.assertEqual(compute_aggregate({"a": 6, "b": 5, "c": 5}), 6.0)

    def test_single_high_does_not_bump(self):
        self.assertEqual(compute_aggregate({"a": 5, "b": 1}), 5.0)


class ScoreAttackPathsEntryPointTests(SimpleTestCase):
    def test_combines_rows_across_domains(self):
        artifacts = {
            "corp.example.com": {
                "kerberoastable": [{"Privileged": "No"}, {"Privileged": "No"}],
            },
            "child.example.com": {
                "kerberoastable": [{"Privileged": "No"}, {"Privileged": "No"}],
            },
        }
        result = score_attack_paths(artifacts, ad_domains=[])
        # 4 combined non-privileged rows -> tier 3, not tier 2 (which a
        # per-domain-only view of 2+2 would incorrectly produce).
        self.assertEqual(result["metric_scores"]["kerberoastable"], 3)

    def test_privileged_not_protected_cross_references_ad_domain_admin_counts(self):
        artifacts = {
            "corp.example.com": {
                "privileged_not_protected": [{"Account": "svc-da"}],
            }
        }
        ad_domains = [{"domain": "corp.example.com", "domain_admins": 8, "ent_admins": 2}]
        result = score_attack_paths(artifacts, ad_domains=ad_domains)
        # 1 of 10 not protected -> 90% coverage -> tier 2.
        self.assertEqual(result["metric_scores"]["privileged_not_protected"], 2)

    def test_no_data_scores_everything_low_and_aggregate_is_one(self):
        result = score_attack_paths({}, ad_domains=[])
        self.assertTrue(all(score == 1 for score in result["metric_scores"].values()))
        self.assertEqual(result["aggregate"], 1.0)

    def test_missing_artifacts_does_not_raise(self):
        result = score_attack_paths(None, ad_domains=None)
        self.assertEqual(result["aggregate"], 1.0)
