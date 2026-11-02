# Django Imports
from django.test import SimpleTestCase

# Ghostwriter Libraries
from ghostwriter.modules.reportwriter import prepare_jinja2_env
from ghostwriter.modules.reportwriter.base.html_rich_text import (
    EvidenceRichText,
    LazilyRenderedTemplate,
    RenderedRichTextDict,
    RichTextBase,
    rich_text_template,
)

EVIDENCE = {
    "id": 7,
    "friendly_name": "login_page",
    "caption": "Login page with verbose errors",
    "description": "",
    "path": "evidence/1/login.png",
}


class EvidenceRichTextTests(SimpleTestCase):
    def test_fields_remain_readable(self):
        evi = EvidenceRichText(EVIDENCE)
        self.assertEqual(evi["caption"], EVIDENCE["caption"])
        self.assertEqual(dict(evi), EVIDENCE)

    def test_html_is_evidence_marker(self):
        evi = EvidenceRichText(EVIDENCE)
        self.assertEqual(evi.__html__(), '<p><span data-gw-evidence="7"></span></p>')

    def test_renders_in_rich_text_field(self):
        env, _ = prepare_jinja2_env(debug=True)
        template = rich_text_template(env, "<p>Before</p>{{ finding.evidence[0] }}<p>{{ finding.evidence[0].caption }}</p>")
        out = template.render({"finding": {"evidence": [EvidenceRichText(EVIDENCE)]}})
        self.assertEqual(
            out,
            '<p>Before</p><p><span data-gw-evidence="7"></span></p><p>Login page with verbose errors</p>',
        )

    def test_deep_copy_process_html_keeps_fields_and_rendered_object(self):
        class Rendered:
            def __str__(self):
                return "RENDERED"

            def __html__(self):
                return "<w:p>RENDERED</w:p>"

        seen = []

        def process(rt):
            seen.append(rt)
            return Rendered()

        context = {"findings": [{"evidence": [EvidenceRichText(EVIDENCE)]}]}
        out = RichTextBase.deep_copy_process_html(context, process)
        e = out["findings"][0]["evidence"][0]

        self.assertEqual(len(seen), 1)
        self.assertIsInstance(e, RenderedRichTextDict)
        self.assertIsInstance(e, dict)
        self.assertEqual(e["caption"], EVIDENCE["caption"])
        self.assertEqual(str(e), "RENDERED")
        self.assertEqual(e.__html__(), "<w:p>RENDERED</w:p>")

    def test_deep_copy_process_html_maps_nested_description_rt(self):
        env, _ = prepare_jinja2_env(debug=True)
        evi = EvidenceRichText(EVIDENCE)
        evi["description_rt"] = LazilyRenderedTemplate(
            rich_text_template(env, "<p>Hello {{ name }}</p>"), "the description", {"name": "world"}
        )

        def process(rt):
            return "RENDERED:" + str(rt.__html__())

        out = RichTextBase.deep_copy_process_html({"evidence": [evi]}, process)
        e = out["evidence"][0]
        self.assertEqual(e["description_rt"], "RENDERED:<p>Hello world</p>")
        self.assertEqual(e["caption"], EVIDENCE["caption"])
        self.assertEqual(str(e), 'RENDERED:<p><span data-gw-evidence="7"></span></p>')
