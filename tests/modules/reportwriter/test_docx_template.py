"""Tests for the extended DOCX templating behaviour."""

from __future__ import annotations

from importlib import util
from pathlib import Path

from docx.opc.packuri import PackURI
from docx.oxml import parse_xml
from lxml import etree

MODULE_PATH = Path(__file__).resolve().parents[3] / "ghostwriter" / "modules" / "reportwriter" / "base" / "docx_template.py"
SPEC = util.spec_from_file_location("gw_docx_template", MODULE_PATH)
docx_template = util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(docx_template)
GhostwriterDocxTemplate = docx_template.GhostwriterDocxTemplate


DIAGRAM_XML = (
    '<dgm:data xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
    "<dgm:t>{}</dgm:t>"
    "</dgm:data>"
)

DIAGRAM_SPLIT_XML = (
    '<dgm:data xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
    "<dgm:t>{{{{</dgm:t><dgm:t>{}</dgm:t><dgm:t>}}}}</dgm:t>"
    "</dgm:data>"
)


class FakeXmlPart:
    """Minimal XML part used to exercise templating helpers."""

    def __init__(self, partname: str, xml: str):
        self.partname = PackURI(partname)
        self._element = parse_xml(xml.encode("utf-8"))
        self._blob = etree.tostring(self._element)

    @property
    def blob(self) -> bytes:
        return self._blob


def test_iter_additional_parts_filters_to_smart_art(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    matching = FakeXmlPart("/word/diagrams/data1.xml", DIAGRAM_XML.format("value"))
    other = FakeXmlPart("/word/charts/chart1.xml", DIAGRAM_XML.format("value"))

    monkeypatch.setattr(
        template.docx.part.package,
        "iter_parts",
        lambda: iter([matching, other]),
    )

    assert list(template._iter_additional_parts()) == [matching]


def test_render_additional_parts_updates_diagram_xml(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    part = FakeXmlPart("/word/diagrams/data1.xml", DIAGRAM_SPLIT_XML.format(" item "))
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"item": "Rendered"}, None)

    text = etree.tostring(part._element, encoding="unicode")
    assert "Rendered" in text


def test_get_undeclared_variables_includes_diagram_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    part = FakeXmlPart("/word/diagrams/drawing1.xml", DIAGRAM_SPLIT_XML.format(" missing "))
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))
    monkeypatch.setattr(template, "get_xml", lambda: "")
    monkeypatch.setattr(template, "get_headers_footers", lambda _uri: [])

    variables = template.get_undeclared_template_variables()

    assert "missing" in variables


def test_patch_xml_removes_namespaced_tags_inside_jinja():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(DIAGRAM_SPLIT_XML.format(" value "))

    assert "{{ value }}" in cleaned
    assert "{{<" not in cleaned

