# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.rolodex.matrix_text import normalize_matrix_text


class NormalizeMatrixTextTests(SimpleTestCase):
    """Tests for :func:`ghostwriter.rolodex.matrix_text.normalize_matrix_text`."""

    def test_strips_simple_paragraph_wrapper(self):
        self.assertEqual(
            normalize_matrix_text("<p>Update input validation.</p>"),
            "Update input validation.",
        )

    def test_multiple_paragraphs_become_blank_line_separated(self):
        self.assertEqual(
            normalize_matrix_text("<p>One</p>\n<p>Two</p>"),
            "One\n\nTwo",
        )

    def test_preserves_ec_placeholder_when_html_escaped(self):
        self.assertEqual(
            normalize_matrix_text("<p>Attackers &lt;EC&gt; exfiltrate data.</p>"),
            "Attackers <EC> exfiltrate data.",
        )

    def test_leaves_plain_text_with_ec_placeholder_untouched(self):
        value = "Attackers <EC> exfiltrate data."
        self.assertEqual(normalize_matrix_text(value), value)

    def test_does_not_double_decode_entities(self):
        self.assertEqual(normalize_matrix_text("a &amp;&amp; b"), "a && b")

    def test_converts_nbsp_to_space(self):
        self.assertEqual(normalize_matrix_text("<p>a&nbsp;b</p>"), "a b")

    def test_empty_string_unchanged(self):
        self.assertEqual(normalize_matrix_text(""), "")

    def test_none_unchanged(self):
        self.assertIsNone(normalize_matrix_text(None))

    def test_trims_plain_whitespace(self):
        self.assertEqual(normalize_matrix_text("  plain text  "), "plain text")

    def test_br_becomes_newline(self):
        self.assertEqual(normalize_matrix_text("Line one<br>Line two"), "Line one\nLine two")

    def test_collapses_excess_blank_lines(self):
        self.assertEqual(
            normalize_matrix_text("<p>One</p><p></p><p></p><p>Two</p>"),
            "One\n\nTwo",
        )
