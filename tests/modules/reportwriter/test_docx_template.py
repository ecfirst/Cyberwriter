"""Tests for the extended DOCX templating behaviour."""

from __future__ import annotations

from importlib import util
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from docx.opc.packuri import PackURI
from docx.oxml import parse_xml
from lxml import etree
from xml.etree import ElementTree as ET

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

CHART_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart">'
    "<c:chart><c:plotArea><c:barChart>"
    "<c:ser><c:idx val=\"0\"/><c:order val=\"0\"/>"
    "<c:val><c:numRef><c:numCache><c:ptCount val=\"1\"/>"
    "<c:pt idx=\"0\"><c:v>{}</c:v></c:pt>"
    "</c:numCache></c:numRef></c:val></c:ser>"
    "</c:barChart></c:plotArea></c:chart></c:chartSpace>"
)


class FakeXmlPart:
    """Minimal XML part used to exercise templating helpers."""

    def __init__(self, partname: str, xml: str):
        self.partname = PackURI(partname)
        self._element = parse_xml(xml.encode("utf-8"))
        self._blob = etree.tostring(self._element)
        self.related_parts: dict[str, object] = {}

    @property
    def blob(self) -> bytes:
        return self._blob


class FakeXlsxPart:
    """Minimal XLSX part stored inside the DOCX package."""

    def __init__(
        self,
        partname: str,
        files: dict[str, str] | None = None,
        blob: bytes | None = None,
    ):
        self.partname = PackURI(partname)
        if blob is not None:
            self._blob = blob
        else:
            self._blob = self._build_blob(files or {})

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


class FakeChartPart(FakeXmlPart):
    """Chart part that can reference other parts via relationships."""

    def __init__(
        self,
        partname: str,
        xml: str,
        related_parts: dict[str, object] | None = None,
    ) -> None:
        super().__init__(partname, xml)
        if related_parts is not None:
            self.related_parts = related_parts


def test_iter_additional_parts_filters_to_configured_patterns(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    matching = FakeXmlPart("/word/diagrams/data1.xml", DIAGRAM_XML.format("value"))
    chart = FakeXmlPart("/word/charts/chart1.xml", CHART_XML.format("value"))
    other = FakeXmlPart("/word/styles.xml", DIAGRAM_XML.format("value"))

    monkeypatch.setattr(
        template.docx.part.package,
        "iter_parts",
        lambda: iter([matching, chart, other]),
    )

    assert list(template._iter_additional_parts()) == [matching, chart]


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


def test_render_additional_parts_updates_chart_xml(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    part = FakeXmlPart("/word/charts/chart1.xml", CHART_XML.format("{{ item }}"))
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"item": "123"}, None)

    text = etree.tostring(part._element, encoding="unicode")
    assert "123" in text


def test_render_chart_part_refreshes_cache_from_workbook(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel_part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {
            "xl/workbook.xml": (
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                "<sheets>"
                '<sheet name="Sheet1" sheetId="1" r:id="rId1"/>'
                "</sheets>"
                "</workbook>"
            ),
            "xl/_rels/workbook.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                'Target="worksheets/sheet1.xml"/>'
                "</Relationships>"
            ),
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                "<sheetData>"
                '<row r="1">'
                '<c r="A1" t="inlineStr"><is><t>{{ first }}</t></is></c>'
                "</row>"
                '<row r="2">'
                '<c r="A2" t="inlineStr"><is><t>{{ second }}</t></is></c>'
                "</row>"
                '<row r="3">'
                '<c r="A3" t="inlineStr"><is><t>{{ third }}</t></is></c>'
                "</row>"
                "</sheetData>"
                "</worksheet>"
            ),
        },
    )

    chart_xml = (
        '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<c:chart><c:plotArea><c:barChart>"
        "<c:ser><c:idx val=\"0\"/><c:order val=\"0\"/>"
        "<c:val><c:numRef><c:f>Sheet1!$A$1:$A$3</c:f>"
        "<c:numCache><c:ptCount val=\"3\"/>"
        "<c:pt idx=\"0\"><c:v>1</c:v></c:pt>"
        "<c:pt idx=\"1\"><c:v>2</c:v></c:pt>"
        "<c:pt idx=\"2\"><c:v>3</c:v></c:pt>"
        "</c:numCache></c:numRef></c:val></c:ser>"
        "</c:barChart></c:plotArea></c:chart>"
        "<c:externalData r:id=\"rId1\"/>"
        "</c:chartSpace>"
    )

    chart_part = FakeChartPart(
        "/word/charts/chart1.xml",
        chart_xml,
        related_parts={"rId1": excel_part},
    )

    monkeypatch.setattr(
        template,
        "_iter_additional_parts",
        lambda: iter([excel_part, chart_part]),
    )

    context = {"first": 5, "second": 10, "third": 15}
    template._render_additional_parts(context, None)

    ns = {"c": "http://schemas.openxmlformats.org/drawingml/2006/chart"}
    values = [
        node.text
        for node in chart_part._element.xpath(
            ".//c:numRef/c:numCache/c:pt/c:v", namespaces=ns
        )
    ]
    assert values == ["5", "10", "15"]


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


def test_render_excel_part_coerces_shared_string_cells(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    shared_strings = (
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<si><t>{{ number }}</t></si>"
        "<si><t>Unchanged</t></si>"
        "</sst>"
    )
    sheet_xml = (
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        '<row r="1">'
        '<c r="A1" t="s"><v>0</v></c>'
        '<c r="A2" t="s"><v>1</v></c>'
        "</row>"
        "</sheetData>"
        "</worksheet>"
    )

    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {
            "xl/sharedStrings.xml": shared_strings,
            "xl/worksheets/sheet1.xml": sheet_xml,
        },
    )
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"number": "42"}, None)

    sheet_xml = part.read_xml("xl/worksheets/sheet1.xml")
    root = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

    cells = root.findall(".//x:c", ns)
    assert len(cells) == 2

    assert cells[0].get("t") is None
    assert cells[0].find("x:v", ns).text == "42"

    assert cells[1].get("t") == "s"
    assert cells[1].find("x:v", ns).text == "1"


def test_render_excel_part_preserves_xml_declaration(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    declaration = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
    sheet_xml = (
        declaration
        + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + "<sheetData>"
        + '<row r="1">'
        + '<c r="A1" t="inlineStr"><is><t>{{ number }}</t></is></c>'
        + "</row>"
        + "</sheetData>"
        + "</worksheet>"
    )

    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {"xl/worksheets/sheet1.xml": sheet_xml},
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))

    template._render_additional_parts({"number": 7}, None)

    updated_xml = part.read_xml("xl/worksheets/sheet1.xml")
    assert updated_xml.startswith(declaration)


def test_render_excel_part_collects_workbook_values():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    part = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        {
            "xl/workbook.xml": (
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                "<sheets>"
                '<sheet name="Sheet1" sheetId="1" r:id="rId1"/>'
                "</sheets>"
                "</workbook>"
            ),
            "xl/_rels/workbook.xml.rels": (
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                'Target="worksheets/sheet1.xml"/>'
                "</Relationships>"
            ),
            "xl/sharedStrings.xml": (
                '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<si><t>{{ text }}</t></si>'
                "</sst>"
            ),
            "xl/worksheets/sheet1.xml": (
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                "<sheetData>"
                '<row r="1">'
                '<c r="A1" t="inlineStr"><is><t>{{ number }}</t></is></c>'
                '<c r="B1" t="s"><v>0</v></c>'
                "</row>"
                "</sheetData>"
                "</worksheet>"
            ),
        },
    )

    result = template._render_excel_part(part, {"number": "5.5", "text": "hello"}, None)
    assert result is not None

    final_bytes, workbook_data = result
    assert final_bytes
    assert workbook_data["Sheet1"]["A1"] == 5.5
    assert workbook_data["Sheet1"]["B1"] == "hello"

    sheet_xml = part.read_xml("xl/worksheets/sheet1.xml")
    root = ET.fromstring(sheet_xml)
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    cells = {cell.get("r"): cell for cell in root.findall(".//x:c", ns)}

    assert cells["A1"].get("t") is None
    assert cells["A1"].find("x:v", ns).text == "5.5"
    assert cells["B1"].get("t") == "s"
    assert cells["B1"].find("x:v", ns).text == "0"


def test_serialize_xml_with_declaration_restores_header():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    original = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<root xmlns=\"http://example.com\"><value>1</value></root>"
    )
    root = ET.fromstring(original)

    serialized = template._serialize_xml_with_declaration(original, root)

    assert serialized.startswith(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
    )
    parsed = ET.fromstring(serialized)
    assert parsed.tag.endswith("root")
    namespace = "{http://example.com}"
    value = parsed.find(f"{namespace}value")
    assert value is not None and value.text == "1"


def test_get_undeclared_variables_includes_diagram_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    part = FakeXmlPart("/word/diagrams/drawing1.xml", DIAGRAM_SPLIT_XML.format(" missing "))
    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([part]))
    monkeypatch.setattr(template, "get_xml", lambda: "")
    monkeypatch.setattr(template, "get_headers_footers", lambda _uri: [])

    variables = template.get_undeclared_template_variables()

    assert "missing" in variables


def test_get_undeclared_variables_includes_chart_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    part = FakeXmlPart("/word/charts/chart1.xml", CHART_XML.format("{{ missing }}"))
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

