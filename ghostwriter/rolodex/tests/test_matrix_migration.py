"""Regression tests for the 0101_normalize_matrix_entry_text data migration.

These call the migration's helper function directly against the current
model classes rather than going through Django's migration executor, since
the behavior under test (collision-safe normalization) doesn't depend on
historical model state.
"""

import importlib

# Django Imports
from django.test import TestCase

# Ghostwriter Libraries
from ghostwriter.rolodex.models import VulnerabilityMatrixEntry, WebIssueMatrixEntry

_migration = importlib.import_module("ghostwriter.rolodex.migrations.0101_normalize_matrix_entry_text")


class NormalizeMatrixModelTests(TestCase):
    """Tests for :func:`_normalize_model` in the 0101 data migration."""

    def test_strips_html_when_no_collision(self):
        entry = VulnerabilityMatrixEntry.objects.create(
            vulnerability="<p>Outdated TLS Configuration</p>",
            action_required="<p>Disable weak cipher suites.</p>",
            remediation_impact="Low",
            vulnerability_threat="<p>Attackers &lt;EC&gt; intercept traffic.</p>",
            category="OOD",
        )

        _migration._normalize_model(
            VulnerabilityMatrixEntry,
            "vulnerability",
            ["vulnerability", "action_required", "remediation_impact", "vulnerability_threat"],
        )

        entry.refresh_from_db()
        self.assertEqual(entry.vulnerability, "Outdated TLS Configuration")
        self.assertEqual(entry.action_required, "Disable weak cipher suites.")
        self.assertEqual(entry.vulnerability_threat, "Attackers <EC> intercept traffic.")

    def test_skips_row_whose_literal_value_would_collide_after_normalization(self):
        # Regression test: a row can already be exactly clean (no HTML,
        # nothing for _key() to differ on) while another row's *literal*
        # value differs only by trailing whitespace. normalize_matrix_text
        # strips that whitespace, making the two rows byte-for-byte
        # identical -- but _key() (used as a cheap "did this row's key
        # change" shortcut) collapses whitespace on both sides and reports
        # no change, since it already strips trailing whitespace on its own.
        # The collision check must not rely on that shortcut, or it misses
        # this exact case and hits the database's unique constraint.
        title = "Adobe Flash Player: APSB15-32 (CVE-2015-8403): Security updates available for Adobe Flash Player"
        clean_entry = VulnerabilityMatrixEntry.objects.create(
            vulnerability=title,
            action_required="Apply the vendor patch.",
            remediation_impact="High",
            vulnerability_threat="Attackers <EC> execute arbitrary code.",
            category="OOD",
        )
        trailing_space_entry = VulnerabilityMatrixEntry.objects.create(
            vulnerability=title + " ",
            action_required="Apply the vendor patch.",
            remediation_impact="High",
            vulnerability_threat="Attackers <EC> execute arbitrary code.",
            category="OOD",
        )

        # Must not raise IntegrityError.
        _migration._normalize_model(
            VulnerabilityMatrixEntry,
            "vulnerability",
            ["vulnerability", "action_required", "remediation_impact", "vulnerability_threat"],
        )

        clean_entry.refresh_from_db()
        trailing_space_entry.refresh_from_db()
        self.assertEqual(clean_entry.vulnerability, title)
        # Left untouched -- normalizing it would collide with clean_entry.
        self.assertEqual(trailing_space_entry.vulnerability, title + " ")

    def test_web_issue_title_collision_is_skipped(self):
        title = "Missing Content-Security-Policy Header"
        clean_entry = WebIssueMatrixEntry.objects.create(
            title=title,
            impact="Attackers can inject scripts.",
            fix="Add a Content-Security-Policy header.",
        )
        newline_entry = WebIssueMatrixEntry.objects.create(
            title=title + "\n",
            impact="Attackers can inject scripts.",
            fix="Add a Content-Security-Policy header.",
        )

        _migration._normalize_model(WebIssueMatrixEntry, "title", ["title", "impact", "fix"])

        clean_entry.refresh_from_db()
        newline_entry.refresh_from_db()
        self.assertEqual(clean_entry.title, title)
        self.assertEqual(newline_entry.title, title + "\n")

    def test_unrelated_field_still_normalized_despite_case_variant_sharing_key(self):
        # A row sharing a _key() bucket with another row only because of
        # case differences (a pre-existing, legitimate distinct pair under
        # Postgres's case-sensitive unique constraint) must still get its
        # *other* fields cleaned up -- the collision guard only applies to
        # the unique field itself.
        VulnerabilityMatrixEntry.objects.create(
            vulnerability="SQL INJECTION",
            action_required="Already clean.",
            remediation_impact="High",
            vulnerability_threat="Attackers <EC> exfiltrate data.",
            category="Injection",
        )
        lowercase_entry = VulnerabilityMatrixEntry.objects.create(
            vulnerability="sql injection",
            action_required="<p>Update all input validation.</p>",
            remediation_impact="High",
            vulnerability_threat="Attackers <EC> exfiltrate data.",
            category="Injection",
        )

        _migration._normalize_model(
            VulnerabilityMatrixEntry,
            "vulnerability",
            ["vulnerability", "action_required", "remediation_impact", "vulnerability_threat"],
        )

        lowercase_entry.refresh_from_db()
        self.assertEqual(lowercase_entry.vulnerability, "sql injection")
        self.assertEqual(lowercase_entry.action_required, "Update all input validation.")
