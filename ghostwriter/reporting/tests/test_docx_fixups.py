# Standard Libraries
from io import BytesIO

# Django Imports
from django.test import SimpleTestCase

# 3rd Party Libraries
import docx
from docxtpl import DocxTemplate

# Ghostwriter Libraries
from ghostwriter.modules.reportwriter.base import ReportExportTemplateError
from ghostwriter.modules.reportwriter.base.docx_fixups import check_and_fix_docx_element
from ghostwriter.modules.reportwriter.base.html_rich_text import LazySubdocRender


def _render(template_paragraphs, context_factory, in_table=False):
    """
    Builds a one-off template from `template_paragraphs`, renders it with the context produced by
    `context_factory(tpl)`, and returns the rendered python-docx document.
    """
    doc = docx.Document()
    if in_table:
        cell = doc.add_table(rows=1, cols=1).cell(0, 0)
        cell.paragraphs[0].text = template_paragraphs[0]
        for text in template_paragraphs[1:]:
            cell.add_paragraph(text)
    else:
        for text in template_paragraphs:
            doc.add_paragraph(text)
    buf = BytesIO()
    doc.save(buf)
    buf.seek(0)

    tpl = DocxTemplate(buf)
    tpl.render(context_factory(tpl), autoescape=True)
    return tpl.docx


def _subdoc_with_text(tpl, text):
    def render():
        sub = tpl.new_subdoc()
        sub.add_paragraph(text)
        return sub
    return LazySubdocRender(render)


def _empty_subdoc(tpl):
    return LazySubdocRender(lambda: tpl.new_subdoc())


class DocxFixupsTests(SimpleTestCase):
    def test_inline_subdoc_is_rejected(self):
        rendered = _render(["{{ e }}"], lambda tpl: {"e": _subdoc_with_text(tpl, "Figure 1 caption")})
        self.assertTrue(rendered.element.xpath(".//w:t//w:p"), "test setup should nest a paragraph in a run")

        with self.assertRaises(ReportExportTemplateError) as ctx:
            check_and_fix_docx_element(rendered.element)
        self.assertIn("{{p ... }}", str(ctx.exception))
        self.assertIn("Figure 1 caption", str(ctx.exception))

    def test_paragraph_tag_subdoc_is_accepted(self):
        rendered = _render(["{{p e }}"], lambda tpl: {"e": _subdoc_with_text(tpl, "Figure 1 caption")})
        self.assertEqual(check_and_fix_docx_element(rendered.element), 0)
        self.assertFalse(rendered.element.xpath(".//w:t//w:p"))

    def test_empty_table_cell_gets_a_paragraph(self):
        rendered = _render(["{{p empty_rt }}"], lambda tpl: {"empty_rt": _empty_subdoc(tpl)}, in_table=True)
        cell = rendered.element.xpath(".//w:tc")[0]
        self.assertFalse(cell.xpath("./w:p"), "test setup should leave the cell with no paragraph")

        self.assertEqual(check_and_fix_docx_element(rendered.element), 1)
        self.assertEqual(len(cell.xpath("./w:p")), 1)
        # Running again is a no-op
        self.assertEqual(check_and_fix_docx_element(rendered.element), 0)

    def test_undefined_value_in_table_cell_gets_a_paragraph(self):
        rendered = _render(["Result: {{p missing_rt }}"], lambda tpl: {}, in_table=True)
        cell = rendered.element.xpath(".//w:tc")[0]
        self.assertEqual(check_and_fix_docx_element(rendered.element), 1)
        self.assertEqual(len(cell.xpath("./w:p")), 1)
