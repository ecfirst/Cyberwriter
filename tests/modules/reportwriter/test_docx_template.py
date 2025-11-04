"""Tests for the extended DOCX templating behaviour."""

from __future__ import annotations

import io
import zipfile
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

WORKSHEET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    "<row r=\"1\">"
    "<c r=\"A1\" t=\"inlineStr\"><is><t>{{ number }}</t></is></c>"
    "<c r=\"A2\" t=\"s\"><v>0</v></c>"
    "</row>"
    "</sheetData>"
    "</worksheet>"
)

SHARED_STRINGS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    "count=\"1\" uniqueCount=\"1\">"
    "<si><t>{{ chart_value }}</t></si>"
    "</sst>"
)

WORKBOOK_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    "<sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\"/></sheets>"
    "</workbook>"
)

WORKBOOK_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
    'Target="worksheets/sheet1.xml"/>'
    "</Relationships>"
)

CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
    "</Types>"
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


class FakeXlsxPart:
    """Embedded Excel part for exercising templating."""

    def __init__(self, partname: str, worksheet_xml: str, shared_xml: str | None = None):
        self.partname = PackURI(partname)
        self._blob = self._build_blob(worksheet_xml, shared_xml)

    @staticmethod
    def _build_blob(worksheet_xml: str, shared_xml: str | None) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
            archive.writestr("xl/workbook.xml", WORKBOOK_XML)
            archive.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
            archive.writestr("xl/worksheets/sheet1.xml", worksheet_xml)
            if shared_xml is not None:
                archive.writestr("xl/sharedStrings.xml", shared_xml)
        return buffer.getvalue()

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


def test_iter_additional_parts_includes_excel_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_XML,
        SHARED_STRINGS_XML,
    )

    monkeypatch.setattr(template.docx.part.package, "iter_parts", lambda: iter([excel]))

    assert list(template._iter_additional_parts()) == [excel]


def test_render_additional_parts_updates_excel_data(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_XML,
        SHARED_STRINGS_XML,
    )
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    template._render_additional_parts({"number": 7, "chart_value": 21}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        shared = archive.read("xl/sharedStrings.xml").decode("utf-8")

    assert "<c r=\"A1\"><v>7</v></c>" in sheet
    assert "<c r=\"A2\"><v>21</v></c>" in sheet
    assert "{{" not in shared


def test_get_undeclared_variables_includes_diagram_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    part = FakeXmlPart("/word/diagrams/drawing1.xml", DIAGRAM_SPLIT_XML.format(" missing "))
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))
    monkeypatch.setattr(template, "get_xml", lambda: "")
    monkeypatch.setattr(template, "get_headers_footers", lambda _uri: [])

    variables = template.get_undeclared_template_variables()

    assert "missing" in variables


def test_get_undeclared_variables_includes_excel_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    worksheet = WORKSHEET_XML.replace("{{ number }}", "{{ missing_excel }}")
    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        worksheet,
        None,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))
    monkeypatch.setattr(template, "get_xml", lambda: "")
    monkeypatch.setattr(template, "get_headers_footers", lambda _uri: [])

    variables = template.get_undeclared_template_variables()

    assert "missing_excel" in variables


def test_patch_xml_removes_namespaced_tags_inside_jinja():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(DIAGRAM_SPLIT_XML.format(" value "))

    assert "{{ value }}" in cleaned
    assert "{{<" not in cleaned

