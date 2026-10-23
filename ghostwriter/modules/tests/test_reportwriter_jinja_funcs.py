from django.test import SimpleTestCase

from ghostwriter.modules.reportwriter import prepare_jinja2_env


class DefaultFilterNoneTests(SimpleTestCase):
    """The ``default``/``d`` filter must treat ``None`` like an undefined value."""

    def render(self, template, **context):
        env, _ = prepare_jinja2_env(debug=True)
        return env.from_string(template).render(**context)

    def test_none_plus_none_with_default_renders_zero(self):
        # Reproduces the Report 61 failure: out-of-scope workbook values are None
        self.assertEqual(self.render("{{ a|default(0) + b|default(0) }}", a=None, b=None), "0")

    def test_none_with_default_and_gt_test_does_not_raise(self):
        out = self.render("{% if a|default(0) is gt(0) %}yes{% else %}no{% endif %}", a=None)
        self.assertEqual(out, "no")

    def test_d_alias_replaces_none(self):
        self.assertEqual(self.render("{{ a|d('N/A') }}", a=None), "N/A")

    def test_undefined_still_replaced(self):
        self.assertEqual(self.render("{{ a|default('N/A') }}"), "N/A")

    def test_real_values_pass_through(self):
        self.assertEqual(self.render("{{ a|default('N/A') }}", a=5), "5")
        self.assertEqual(self.render("{{ a|default('N/A') }}", a=0), "0")
        self.assertEqual(self.render("{{ a|default('N/A') }}", a=""), "")

    def test_boolean_mode_preserved(self):
        self.assertEqual(self.render("{{ a|default('x', true) }}", a=""), "x")
        self.assertEqual(self.render("{{ a|default('x', true) }}", a=0), "x")

    def test_none_is_still_defined(self):
        # Documents why templates should guard with `is not none` rather than `is defined`
        self.assertEqual(self.render("{{ a is defined }}", a=None), "True")
