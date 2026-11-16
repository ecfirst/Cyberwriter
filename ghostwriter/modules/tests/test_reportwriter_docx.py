from django.test import SimpleTestCase

from ghostwriter.modules.linting_utils import LINTER_CONTEXT
from ghostwriter.modules.reportwriter.base.docx import _lint_context_has_variable


class LintContextHasVariableTests(SimpleTestCase):
    """Validate context lookup helper used during DOCX linting."""

    def test_nested_dict_path_is_detected(self):
        context = {"project": {"data_responses": {"general": {"scope_count": 3}}}}
        self.assertTrue(
            _lint_context_has_variable(
                context, "project.data_responses.general.scope_count"
            )
        )

    def test_list_index_path_is_detected(self):
        context = {"findings": [{"title": "Example"}]}
        self.assertTrue(_lint_context_has_variable(context, "findings[0].title"))

    def test_missing_path_returns_false(self):
        context = {}
        self.assertFalse(
            _lint_context_has_variable(context, "project.data_responses.general.scope_count")
        )

    def test_password_policy_rich_text_fields_present_for_linting(self):
        self.assertTrue(
            _lint_context_has_variable(
                LINTER_CONTEXT, "project.workbook_data.password.policies[0].history_rt"
            )
        )
        self.assertTrue(
            _lint_context_has_variable(
                LINTER_CONTEXT,
                "project.workbook_data.password.policies[0].fgpp[1].lockout_threshold_rt",
            )
        )


class LintContextWorkbookCoverageTests(SimpleTestCase):
    """The linter sample must expose every workbook key a template can reference."""

    @staticmethod
    def _leaf_paths(node, prefix=""):
        paths = set()
        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}{key}"
                paths.add(path)
                paths |= LintContextWorkbookCoverageTests._leaf_paths(value, path + ".")
        elif isinstance(node, list) and node and isinstance(node[0], dict):
            paths |= LintContextWorkbookCoverageTests._leaf_paths(node[0], prefix + "[0].")
        return paths

    def test_workbook_defaults_are_covered_by_linter_sample(self):
        from ghostwriter.rolodex.workbook_defaults import WORKBOOK_DEFAULTS

        expected = self._leaf_paths(WORKBOOK_DEFAULTS)
        # ``area_updates`` is an upload-time input, not a template-facing section.
        expected = {path for path in expected if not path.startswith("area_updates")}
        sample = self._leaf_paths(LINTER_CONTEXT["project"]["workbook_data"])
        missing = sorted(expected - sample)
        self.assertEqual(missing, [], f"LINTER_CONTEXT workbook_data is missing: {missing}")

    def test_cloud_assessment_dates_present_for_linting(self):
        for key in ("cloud_start", "cloud_end"):
            self.assertTrue(
                _lint_context_has_variable(LINTER_CONTEXT, f"project.workbook_data.general.{key}"),
                key,
            )
