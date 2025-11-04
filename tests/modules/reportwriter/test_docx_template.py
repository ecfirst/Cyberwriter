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

WORKSHEET_CHART_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    "<row r=\"1\">"
    "<c r=\"A1\"><v>{{ first_val }}</v></c>"
    "<c r=\"B1\" t=\"inlineStr\"><is><t>{{ first_label }}</t></is></c>"
    "</row>"
    "<row r=\"2\">"
    "<c r=\"A2\" t=\"s\"><v>0</v></c>"
    "<c r=\"B2\" t=\"s\"><v>1</v></c>"
    "</row>"
    "</sheetData>"
    "</worksheet>"
)

WORKSHEET_TR_TC_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    "<row>{%tr for row in rows %}</row>"
    "<row>{% endtr %}</row>"
    "<c>{{tc row.value }}</c>"
    "<c>{%tc%}</c>"
    "</sheetData>"
    "</worksheet>"
)

WORKSHEET_TR_TC_TRIMMED_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    "<row>{%-tr for row in rows -%}</row>"
    "<row>{%- endtr -%}</row>"
    "<c>{%-tc row.value -%}</c>"
    "</sheetData>"
    "</worksheet>"
)

SHARED_STRINGS_CHART_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    "count=\"2\" uniqueCount=\"2\">"
    "<si><t>{{ second_val }}</t></si>"
    "<si><t>{{ second_label }}</t></si>"
    "</sst>"
)

CHART_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    "<c:chart>"
    "<c:plotArea>"
    "<c:lineChart>"
    "<c:ser>"
    "<c:val><c:numRef><c:f>Sheet1!$A$1:$A$2</c:f>"
    "<c:numCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>1</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>2</c:v></c:pt>"
    "</c:numCache></c:numRef>"
    "<c:numLit><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>3</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>4</c:v></c:pt>"
    "</c:numLit></c:val>"
    "<c:cat><c:strRef><c:f>Sheet1!$B$1:$B$2</c:f>"
    "<c:strCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>First</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>Second</c:v></c:pt>"
    "</c:strCache></c:strRef>"
    "<c:strLit><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>Old</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>Values</c:v></c:pt>"
    "</c:strLit></c:cat>"
    "</c:ser>"
    "</c:lineChart>"
    "</c:plotArea>"
    "</c:chart>"
    "<c:externalData r:id=\"rId1\"><c:autoUpdate val=\"0\"/></c:externalData>"
    "</c:chartSpace>"
)

CHART_EXT_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:x14="http://schemas.microsoft.com/office/drawing/2010/chart">'
    "<c:chart>"
    "<c:plotArea>"
    "<c:barChart>"
    "<c:ser>"
    "<c:val><c:numRef><c:f>Sheet1!$A$1:$A$2</c:f>"
    "<c:numCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>1</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>2</c:v></c:pt>"
    "</c:numCache>"
    "<c:extLst><c:ext uri=\"{C5E0089C-D5B0-43F5-8A56-9C2E5A163620}\">"
    "<x14:numRef><x14:f>Sheet1!$A$1:$A$2</x14:f>"
    "<x14:numCache><x14:ptCount val=\"2\"/>"
    "<x14:pt idx=\"0\"><x14:v>1</x14:v></x14:pt>"
    "<x14:pt idx=\"1\"><x14:v>2</x14:v></x14:pt>"
    "</x14:numCache></x14:numRef>"
    "</c:ext></c:extLst>"
    "</c:numRef></c:val>"
    "<c:cat><c:strRef><c:f>Sheet1!$B$1:$B$2</c:f>"
    "<c:strCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>Old</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>Data</c:v></c:pt>"
    "</c:strCache>"
    "<c:extLst><c:ext uri=\"{C5E0089C-D5B0-43F5-8A56-9C2E5A163620}\">"
    "<x14:strRef><x14:f>Sheet1!$B$1:$B$2</x14:f>"
    "<x14:strCache><x14:ptCount val=\"2\"/>"
    "<x14:pt idx=\"0\"><x14:v>Old</x14:v></x14:pt>"
    "<x14:pt idx=\"1\"><x14:v>Data</x14:v></x14:pt>"
    "</x14:strCache></x14:strRef>"
    "</c:ext></c:extLst>"
    "</c:strRef></c:cat>"
    "</c:ser>"
    "</c:barChart>"
    "</c:plotArea>"
    "</c:chart>"
    "<c:externalData r:id=\"rId1\"><c:autoUpdate val=\"0\"/></c:externalData>"
    "</c:chartSpace>"
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

CONTENT_TYPES_WITH_TABLE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
    '<Override PartName="/xl/tables/table1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>'
    "</Types>"
)

WORKSHEET_TABLE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    "<sheetData>"
    "<row r=\"1\">"
    "<c r=\"A1\" t=\"inlineStr\"><is><t>Numbers</t></is></c>"
    "<c r=\"B1\" t=\"inlineStr\"><is><t>Labels</t></is></c>"
    "</row>"
    "<row r=\"2\">"
    "<c r=\"A2\"><v>{{ first_number }}</v></c>"
    "<c r=\"B2\" t=\"inlineStr\"><is><t>{{ first_label }}</t></is></c>"
    "</row>"
    "<row r=\"3\">"
    "<c r=\"A3\"><v>{{ second_number }}</v></c>"
    "<c r=\"B3\" t=\"inlineStr\"><is><t>{{ second_label }}</t></is></c>"
    "</row>"
    "</sheetData>"
    "<tableParts count=\"1\"><tablePart r:id=\"rId1\"/></tableParts>"
    "</worksheet>"
)

WORKSHEET_TABLE_LOOP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    "<sheetData>"
    "<row r=\"1\">"
    "<c r=\"A1\" t=\"inlineStr\"><is><t>Numbers</t></is></c>"
    "<c r=\"B1\" t=\"inlineStr\"><is><t>Labels</t></is></c>"
    "</row>"
    "{% for row in rows %}"
    "<row r=\"{{ loop.index + 1 }}\">"
    "<c r=\"A{{ loop.index + 1 }}\"><v>{{ row.number }}</v></c>"
    "<c r=\"B{{ loop.index + 1 }}\" t=\"inlineStr\"><is><t>{{ row.label }}</t></is></c>"
    "</row>"
    "{% endfor %}"
    "</sheetData>"
    "<tableParts count=\"1\"><tablePart r:id=\"rId1\"/></tableParts>"
    "</worksheet>"
)

TABLE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'id="1" name="Table1" displayName="Table1" ref="A1:B3" headerRowCount="1">'
    '<tableColumns count="2">'
    '<tableColumn id="1" name="Numbers"/>'
    '<tableColumn id="2" name="Labels"/>'
    '</tableColumns>'
    '<autoFilter ref="A1:B3"/>'
    '</table>'
)

TABLE_SMALL_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'id="1" name="Table1" displayName="Table1" ref="A1:B2" headerRowCount="1">'
    '<tableColumns count="2">'
    '<tableColumn id="1" name="Numbers"/>'
    '<tableColumn id="2" name="Labels"/>'
    '</tableColumns>'
    '<autoFilter ref="A1:B2"/>'
    '</table>'
)

SHEET_TABLE_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" '
    'Target="../tables/table1.xml"/>'
    "</Relationships>"
)

CHART_TABLE_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    "<c:chart>"
    "<c:plotArea>"
    "<c:lineChart>"
    "<c:ser>"
    "<c:val><c:numRef><c:f>Sheet1!Table1[Numbers]</c:f>"
    "<c:numCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>1</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>2</c:v></c:pt>"
    "</c:numCache></c:numRef></c:val>"
    "<c:cat><c:strRef><c:f>Sheet1!Table1[Labels]</c:f>"
    "<c:strCache><c:ptCount val=\"2\"/>"
    "<c:pt idx=\"0\"><c:v>First</c:v></c:pt>"
    "<c:pt idx=\"1\"><c:v>Second</c:v></c:pt>"
    "</c:strCache></c:strRef></c:cat>"
    "</c:ser>"
    "</c:lineChart>"
    "</c:plotArea>"
    "</c:chart>"
    "<c:externalData r:id=\"rId1\"><c:autoUpdate val=\"0\"/></c:externalData>"
    "</c:chartSpace>"
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

    def __init__(
        self,
        partname: str,
        worksheet_xml: str,
        shared_xml: str | None = None,
        *,
        content_types_xml: str | None = None,
        extra_files: dict[str, str | bytes] | None = None,
    ):
        self.partname = PackURI(partname)
        self._blob = self._build_blob(
            worksheet_xml,
            shared_xml,
            content_types_xml=content_types_xml,
            extra_files=extra_files,
        )

    @staticmethod
    def _build_blob(
        worksheet_xml: str,
        shared_xml: str | None,
        *,
        content_types_xml: str | None,
        extra_files: dict[str, str | bytes] | None,
    ) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", content_types_xml or CONTENT_TYPES_XML)
            archive.writestr("xl/workbook.xml", WORKBOOK_XML)
            archive.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
            archive.writestr("xl/worksheets/sheet1.xml", worksheet_xml)
            if shared_xml is not None:
                archive.writestr("xl/sharedStrings.xml", shared_xml)
            if extra_files:
                for name, data in extra_files.items():
                    archive.writestr(name, data if isinstance(data, bytes) else data.encode("utf-8"))
        return buffer.getvalue()

    @property
    def blob(self) -> bytes:
        return self._blob


class FakeRelationship:
    """Relationship pointing a chart to an embedded workbook."""

    def __init__(self, target_part):
        self.reltype = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/embeddedPackage"
        self.target_part = target_part


class FakeChartPart(FakeXmlPart):
    """Chart XML part with a relationship to a workbook."""

    def __init__(self, partname: str, xml: str, target_part):
        super().__init__(partname, xml)
        self.rels = {"rId1": FakeRelationship(target_part)}


def test_iter_additional_parts_filters_to_known_patterns(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    matching = FakeXmlPart("/word/diagrams/data1.xml", DIAGRAM_XML.format("value"))
    chart = FakeXmlPart("/word/charts/chart1.xml", DIAGRAM_XML.format("value"))
    other = FakeXmlPart("/word/document.xml", DIAGRAM_XML.format("value"))

    monkeypatch.setattr(
        template.docx.part.package,
        "iter_parts",
        lambda: iter([matching, chart, other]),
    )

    assert list(template._iter_additional_parts()) == [matching, chart]


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


def test_render_additional_parts_updates_chart_cache(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_CHART_XML,
        SHARED_STRINGS_CHART_XML,
    )
    chart = FakeChartPart(
        "/word/charts/chart1.xml",
        CHART_XML,
        excel,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel, chart]))

    template._render_additional_parts(
        {
            "first_val": 10,
            "second_val": 20,
            "first_label": "Alpha",
            "second_label": "Beta",
        },
        None,
    )

    chart_xml = etree.tostring(chart._element, encoding="unicode")
    assert "<c:pt idx=\"0\"><c:v>10</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>20</c:v></c:pt>" in chart_xml
    assert "<c:numLit><c:ptCount val=\"2\"/>" in chart_xml
    assert "<c:numLit><c:ptCount val=\"2\"/><c:pt idx=\"0\"><c:v>10</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>20</c:v></c:pt></c:numLit>" in chart_xml
    assert "<c:pt idx=\"0\"><c:v>Alpha</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>Beta</c:v></c:pt>" in chart_xml
    assert "<c:strLit><c:ptCount val=\"2\"/>" in chart_xml
    assert "<c:strLit><c:ptCount val=\"2\"/><c:pt idx=\"0\"><c:v>Alpha</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>Beta</c:v></c:pt></c:strLit>" in chart_xml
    assert "<c:autoUpdate val=\"1\"/>" in chart_xml
    assert "{{" not in chart_xml


def test_render_additional_parts_updates_chart_cache_structured_ref(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TABLE_XML,
        None,
        content_types_xml=CONTENT_TYPES_WITH_TABLE_XML,
        extra_files={
            "xl/worksheets/_rels/sheet1.xml.rels": SHEET_TABLE_RELS_XML,
            "xl/tables/table1.xml": TABLE_XML,
        },
    )
    chart = FakeChartPart(
        "/word/charts/chart1.xml",
        CHART_TABLE_XML,
        excel,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel, chart]))

    template._render_additional_parts(
        {
            "first_number": 5,
            "second_number": 7,
            "first_label": "One",
            "second_label": "Two",
        },
        None,
    )

    chart_xml = etree.tostring(chart._element, encoding="unicode")
    assert "<c:pt idx=\"0\"><c:v>5</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>7</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"0\"><c:v>One</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>Two</c:v></c:pt>" in chart_xml
    assert "<c:autoUpdate val=\"1\"/>" in chart_xml
    assert "{{" not in chart_xml

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        table_xml = archive.read("xl/tables/table1.xml").decode("utf-8")

    assert "ref=\"A1:B3\"" in table_xml
    assert "{{" not in table_xml


def test_render_additional_parts_updates_chart_cache_extensions(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_CHART_XML,
        SHARED_STRINGS_CHART_XML,
    )
    chart = FakeChartPart(
        "/word/charts/chart1.xml",
        CHART_EXT_XML,
        excel,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel, chart]))

    template._render_additional_parts(
        {
            "first_val": 10,
            "second_val": 20,
            "first_label": "Alpha",
            "second_label": "Beta",
        },
        None,
    )

    chart_xml = etree.tostring(chart._element, encoding="unicode")
    assert "<c:pt idx=\"0\"><c:v>10</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>20</c:v></c:pt>" in chart_xml
    assert "<x14:pt idx=\"0\"><x14:v>10</x14:v></x14:pt>" in chart_xml
    assert "<x14:pt idx=\"1\"><x14:v>20</x14:v></x14:pt>" in chart_xml
    assert "<c:pt idx=\"0\"><c:v>Alpha</c:v></c:pt>" in chart_xml
    assert "<c:pt idx=\"1\"><c:v>Beta</c:v></c:pt>" in chart_xml
    assert "<x14:pt idx=\"0\"><x14:v>Alpha</x14:v></x14:pt>" in chart_xml
    assert "<x14:pt idx=\"1\"><x14:v>Beta</x14:v></x14:pt>" in chart_xml
    assert "<c:autoUpdate val=\"1\"/>" in chart_xml
    assert "{{" not in chart_xml


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


def test_patch_xml_handles_excel_tc_tr_tags():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(WORKSHEET_TR_TC_XML)

    assert "{% for row in rows %}" in cleaned
    assert "{% endfor %}" in cleaned
    assert "{% for for" not in cleaned
    assert "{{ row.value }}" in cleaned
    assert "{{tc" not in cleaned
    assert "{%tc" not in cleaned


def test_patch_xml_handles_trimmed_excel_tr_tags():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(WORKSHEET_TR_TC_TRIMMED_XML)

    assert "{%- for row in rows -%}" in cleaned
    assert "{%- endfor -%}" in cleaned
    assert "tr for" not in cleaned
    assert "endtr" not in cleaned


def test_render_additional_parts_expands_table_range_for_loop(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TABLE_LOOP_XML,
        None,
        content_types_xml=CONTENT_TYPES_WITH_TABLE_XML,
        extra_files={
            "xl/worksheets/_rels/sheet1.xml.rels": SHEET_TABLE_RELS_XML,
            "xl/tables/table1.xml": TABLE_SMALL_XML,
        },
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    template._render_additional_parts(
        {
            "rows": [
                {"number": 1, "label": "One"},
                {"number": 2, "label": "Two"},
                {"number": 3, "label": "Three"},
            ]
        },
        None,
    )

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        table_xml = archive.read("xl/tables/table1.xml").decode("utf-8")

    assert "ref=\"A1:B4\"" in table_xml
    assert "{{" not in table_xml

