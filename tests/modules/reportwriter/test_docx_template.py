"""Tests for the extended DOCX templating behaviour."""

from __future__ import annotations

from importlib import util
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

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


class FakeXlsxPart:
    """Minimal XLSX part stored inside the DOCX package."""

    def __init__(self, partname: str, files: dict[str, str]):
        self.partname = PackURI(partname)
        self._blob = self._build_blob(files)

    @staticmethod
    def _build_blob(files: dict[str, str]) -> bytes:
        buffer = BytesIO()
        with ZipFile(buffer, "w") as archive:
            for filename, contents in files.items():
                archive.writestr(filename, contents)
        return buffer.getvalue()

    @property
    def blob(self) -> bytes:
        return self._blob

    def read_xml(self, filename: str) -> str:
        with ZipFile(BytesIO(self._blob), "r") as archive:
            return archive.read(filename).decode("utf-8")


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


def test_iter_additional_parts_includes_embedded_excel(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    matching = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {"xl/worksheets/sheet1.xml": "<worksheet>{{ value }}</worksheet>"},
    )

    monkeypatch.setattr(
        template.docx.part.package,
        "iter_parts",
        lambda: iter([matching]),
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


def test_render_additional_parts_updates_excel_xml(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {"xl/worksheets/sheet1.xml": "<worksheet>{{ item }}</worksheet>"},
    )
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"item": "Rendered"}, None)

    sheet_xml = part.read_xml("xl/worksheets/sheet1.xml")
    assert "Rendered" in sheet_xml


def test_render_excel_part_coerces_numeric_cells(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    sheet_xml = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        '<row r="1">'
        '<c r="A1" t="inlineStr"><is><t>{{ number }}</t></is></c>'
        '<c r="A2" t="str"><v>{{ number }}</v></c>'
        '<c r="A3" t="inlineStr"><is><t>{{ text }}</t></is></c>'
        "</row>"
        "</sheetData>"
        "</worksheet>"
    )
    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {"xl/worksheets/sheet1.xml": sheet_xml},
    )
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"number": 42, "text": "not numeric"}, None)

    sheet_xml = part.read_xml("xl/worksheets/sheet1.xml")
    root = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

    cells = root.findall(".//x:c", ns)
    assert len(cells) == 3

    assert cells[0].get("t") is None
    assert cells[0].find("x:v", ns).text == "42"

    assert cells[1].get("t") is None
    assert cells[1].find("x:v", ns).text == "42"

    assert cells[2].get("t") == "inlineStr"
    assert cells[2].find(".//x:t", ns).text == "not numeric"


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

    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {"xl/sharedStrings.xml": "<sst>{{ missing }}</sst>"},
    )
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

