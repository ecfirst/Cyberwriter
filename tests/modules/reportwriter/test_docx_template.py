"""Tests for the extended DOCX templating behaviour."""

from __future__ import annotations

import io
import re
import zipfile
from importlib import util
from pathlib import Path
from xml.etree import ElementTree as ET

from docx.opc.packuri import PackURI
from docx.oxml import parse_xml
from jinja2 import Environment
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

WORKSHEET_TR_ENDFOR_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    "<row>{%tr for site in sites %}</row>"
    "<row>{%tr endfor %}</row>"
    "</sheetData>"
    "</worksheet>"
)

WORKSHEET_TR_SPLIT_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    '<row><c t="inlineStr"><is><r><t>{%</t></r><r><t>tr for site in project.workbook_data.web.sites %}</t></r></is></c></row>'
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><r><t>{{ site.url }}</t></r></is></c>'
    '<c r="B2" t="inlineStr"><is><r><t>{{ site.unique_high }}</t></r></is></c>'
    '<c r="C2" t="inlineStr"><is><r><t>{{ site.unique_med }}</t></r></is></c>'
    '<c r="D2" t="inlineStr"><is><r><t>{{ site.unique_low }}</t></r></is></c>'
    '</row>'
    '<row><c t="inlineStr"><is><r><t>{%</t></r><r><t>tr endfor %}</t></r></is></c></row>'
    "</sheetData>"
    "</worksheet>"
)

WORKSHEET_TC_SPLIT_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    "<sheetData>"
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><r><t>{{</t></r><r><t>tc site.url }}</t></r></is></c>'
    '<c r="B2" t="inlineStr"><is><r><t>{{</t></r><r><t>tc site.unique_high }}</t></r></is></c>'
    '</row>'
    "</sheetData>"
    "</worksheet>"
)

WORKSHEET_TR_LOOP_ROWS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<dimension ref="A1:D2"/>'
    '<sheetData>'
    '<row r="1">'
    '<c r="A1" t="inlineStr"><is><t>Site</t></is></c>'
    '<c r="B1" t="inlineStr"><is><t>High</t></is></c>'
    '<c r="C1" t="inlineStr"><is><t>Medium</t></is></c>'
    '<c r="D1" t="inlineStr"><is><t>Low</t></is></c>'
    '</row>'
    '<row>{%tr for site in sites %}</row>'
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><t>{{tc site.url }}</t></is></c>'
    '<c r="B2"><v>{{tc site.high }}</v></c>'
    '<c r="C2"><v>{{tc site.medium }}</v></c>'
    '<c r="D2"><v>{{tc site.low }}</v></c>'
    '</row>'
    '<row>{%tr endfor %}</row>'
    '</sheetData>'
    '</worksheet>'
)

SMARTART_DOCUMENT_XML = (
    '<w:document '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
    '<w:body>'
    '<w:p>'
    '<w:r>'
    '<w:drawing>'
    '<wp:inline>'
    '<a:graphic>'
    '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
    '<dgm:relIds r:dm="rIdData" r:lo="rIdLayout" r:qs="rIdQuick" r:cs="rIdColor"/>'
    '</a:graphicData>'
    '</a:graphic>'
    '</wp:inline>'
    '</w:drawing>'
    '</w:r>'
    '</w:p>'
    '<w:p><w:r><w:object r:id="rIdDrawing"/></w:r></w:p>'
    '</w:body>'
    '</w:document>'
)

SMARTART_DOCUMENT_DATA_ONLY_XML = (
    '<w:document '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
    '<w:body>'
    '<w:p>'
    '<w:r>'
    '<w:drawing>'
    '<a:graphic>'
    '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
    '<dgm:relIds r:dm="rIdData"/>'
    '</a:graphicData>'
    '</a:graphic>'
    '</w:drawing>'
    '</w:r>'
    '</w:p>'
    '</w:body>'
    '</w:document>'
)

WORKSHEET_TC_LOOP_TEMPLATE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<sheetData>'
    '<row r="1">'
    '<c r="A1" t="inlineStr"><is><t>Old Passwords</t></is></c>'
    '<c r="B1" t="inlineStr"><is><t>{%tc for domain in domains %}</t></is></c>'
    '<c r="C1" t="inlineStr"><is><t>{{ domain.name }}</t></is></c>'
    '<c r="D1" t="inlineStr"><is><t>{%tc endfor %}</t></is></c>'
    '</row>'
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><t>Compliant</t></is></c>'
    '<c r="B2" t="inlineStr"><is><t>{%tc for domain in domains %}</t></is></c>'
    '<c r="C2"><v>{{ domain.compliant }}</v></c>'
    '<c r="D2" t="inlineStr"><is><t>{%tc endfor %}</t></is></c>'
    '</row>'
    '<row r="3">'
    '<c r="A3" t="inlineStr"><is><t>Stale</t></is></c>'
    '<c r="B3" t="inlineStr"><is><t>{%tc for domain in domains %}</t></is></c>'
    '<c r="C3"><v>{{ domain.stale }}</v></c>'
    '<c r="D3" t="inlineStr"><is><t>{%tc endfor %}</t></is></c>'
    '</row>'
    '</sheetData>'
    '<tableParts count="1"><tablePart r:id="rId1"/></tableParts>'
    '</worksheet>'
)

WORKSHEET_TC_RENDERED_COLUMNS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<sheetData>'
    '<row r="1">'
    '<c r="A1" t="inlineStr"><is><t>Metric</t></is></c>'
    '<c r="B1" t="inlineStr"><is><t>Edge-FW01</t></is></c>'
    '<c r="C1" t="inlineStr"><is><t>Edge-FW02</t></is></c>'
    '</row>'
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><t>High Risk</t></is></c>'
    '<c r="B2"><v>2</v></c>'
    '<c r="C2"><v>1</v></c>'
    '</row>'
    '<row r="3">'
    '<c r="A3" t="inlineStr"><is><t>Medium Risk</t></is></c>'
    '<c r="B3"><v>5</v></c>'
    '<c r="C3"><v>4</v></c>'
    '</row>'
    '<row r="4">'
    '<c r="A4" t="inlineStr"><is><t>Low Risk</t></is></c>'
    '<c r="B4"><v>3</v></c>'
    '<c r="C4"><v>2</v></c>'
    '</row>'
    '</sheetData>'
    '<tableParts count="1"><tablePart r:id="rId1"/></tableParts>'
    '</worksheet>'
)

ORPHANED_DRAWING_PARAGRAPH = (
    '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<w:r>'
    '<w:drawing>'
    '<wp:inline>'
    '<wp:docPr id="42" name="Picture"/>'
    '<a:graphic>'
    '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<pic:pic>'
    '<pic:nvPicPr><pic:cNvPr id="1" name="Orphaned"/><pic:cNvPicPr/></pic:nvPicPr>'
    '<pic:blipFill><a:blip r:embed="rId999"/></pic:blipFill>'
    '<pic:spPr/>'
    '</pic:pic>'
    '</a:graphicData>'
    '</a:graphic>'
    '</wp:inline>'
    '</w:drawing>'
    '</w:r>'
    '</w:p>'
)

ORPHANED_HYPERLINK_PARAGRAPH = (
    '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<w:hyperlink r:id="rId901">'
    '<w:r><w:t>See appendix</w:t></w:r>'
    '</w:hyperlink>'
    '</w:p>'
    '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<w:hyperlink r:id="rId902">'
    '<w:r><w:t>Local appendix</w:t></w:r>'
    '</w:hyperlink>'
    '</w:p>'
    '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<w:hyperlink r:id="rId903">'
    '<w:r><w:t>Helpful link</w:t></w:r>'
    '</w:hyperlink>'
    '</w:p>'
)

DUPLICATE_BODY_BLOCK = (
    '<w:body>'
    '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:r><w:t>Extra Section</w:t></w:r>'
    '</w:p>'
    '<w:sectPr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>'
    '</w:body>'
)

WORKSHEET_TR_PROJECT_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<dimension ref="A1:D2"/>'
    '<sheetData>'
    '<row><c r="A1" t="inlineStr"><is><t>{%tr for site in project.workbook_data.web.sites %}</t></is></c></row>'
    '<row r="2">'
    '<c r="A2" t="inlineStr"><is><t>{{ site.url }}</t></is></c>'
    '<c r="B2" t="inlineStr"><is><t>{{ site.unique_high }}</t></is></c>'
    '<c r="C2" t="inlineStr"><is><t>{{ site.unique_med }}</t></is></c>'
    '<c r="D2" t="inlineStr"><is><t>{{ site.unique_low }}</t></is></c>'
    '</row>'
    '<row><c r="A3" t="inlineStr"><is><t>{%tr endfor %}</t></is></c></row>'
    '</sheetData>'
    '</worksheet>'
)

WORKSHEET_TR_RENDERED_GAPS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<dimension ref="A1:D5"/>'
    '<sheetData>'
    '<row r="1">'
    '<c r="A1" t="inlineStr"><is><t>Site</t></is></c>'
    '<c r="B1" t="inlineStr"><is><t>High Risk</t></is></c>'
    '<c r="C1" t="inlineStr"><is><t>Medium Risk</t></is></c>'
    '<c r="D1" t="inlineStr"><is><t>Low Risk</t></is></c>'
    '</row>'
    '<row r="2" spans="1:4"/>'
    '<row r="3">'
    '<c r="A3" t="inlineStr"><is><t>https://alpha</t></is></c>'
    '<c r="B3"><v>3</v></c>'
    '<c r="C3"><v>7</v></c>'
    '<c r="D3"><v>5</v></c>'
    '</row>'
    '<row r="4">'
    '<c r="A4" t="inlineStr"><is><t> </t></is></c>'
    '</row>'
    '<row r="5">'
    '<c r="A5" t="inlineStr"><is><t>https://beta</t></is></c>'
    '<c r="B5"><v>1</v></c>'
    '<c r="C5"><v>4</v></c>'
    '<c r="D5"><v>2</v></c>'
    '</row>'
    '</sheetData>'
    '</worksheet>'
)

WORKSHEET_TR_SHARED_STRINGS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<dimension ref="A1:D2"/>'
    '<sheetData>'
    '<row r="1">'
    '<c r="A1" t="inlineStr"><is><t>Site</t></is></c>'
    '<c r="B1" t="inlineStr"><is><t>High</t></is></c>'
    '<c r="C1" t="inlineStr"><is><t>Medium</t></is></c>'
    '<c r="D1" t="inlineStr"><is><t>Low</t></is></c>'
    '</row>'
    '<row>{%tr for site in sites %}</row>'
    '<row r="2">'
    '<c r="A2" t="s"><v>0</v></c>'
    '<c r="B2" t="s"><v>1</v></c>'
    '<c r="C2" t="s"><v>2</v></c>'
    '<c r="D2" t="s"><v>3</v></c>'
    '</row>'
    '<row>{%tr endfor %}</row>'
    '</sheetData>'
    '</worksheet>'
)

SHARED_STRINGS_TR_LOOP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'count="4" uniqueCount="4">'
    '<si><t>{{tc site.url }}</t></si>'
    '<si><t>{{tc site.high }}</t></si>'
    '<si><t>{{tc site.medium }}</t></si>'
    '<si><t>{{tc site.low }}</t></si>'
    '</sst>'
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

CHART_RICH_TEXT_SPLIT_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
    "<c:chart>"
    "<c:title><c:tx><c:rich>"
    "<a:p><a:pPr><a:defRPr/></a:pPr>"
    "<a:r><a:rPr lang=\"en-US\"/></a:r>"
    "<a:r><a:t>{{</a:t></a:r>"
    "<a:r><a:rPr lang=\"en-US\"/></a:r>"
    "<a:r><a:t> value }}</a:t></a:r>"
    "</a:p></c:rich></c:tx></c:title>"
    "</c:chart>"
    "</c:chartSpace>"
)

CHART_TC_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart">'
    "<c:chart><c:plotArea><c:ser>"
    "{%tc for device in devices %}"
    '<c:idx val="{{ loop.index0 }}"/>'
    "<c:tx><c:v>{{ device.name }}</c:v></c:tx>"
    "{%tc endfor %}"
    "</c:ser></c:plotArea></c:chart>"
    "</c:chartSpace>"
)

CHART_TR_XML = (
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart">'
    "<c:chart><c:plotArea><c:ser>"
    "{%tr for device in devices %}"
    '<c:idx val="{{ loop.index0 }}"/>'
    "<c:tx><c:v>{{ device.name }}</c:v></c:tx>"
    "{%tr endfor %}"
    "</c:ser></c:plotArea></c:chart>"
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

TABLE_TC_NARROW_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    'id="1" name="Table1" displayName="Table1" ref="A1:B4" headerRowCount="1">'
    '<tableColumns count="2">'
    '<tableColumn id="1" name="Metric"/>'
    '<tableColumn id="2" name="Placeholder"/>'
    '</tableColumns>'
    '<autoFilter ref="A1:B4"/>'
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


def test_render_renders_main_document_before_additional_parts(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    calls: list[str] = []

    monkeypatch.setattr(
        template,
        "build_xml",
        lambda context, env: (calls.append("build_xml") or "<document/>"),
    )
    monkeypatch.setattr(
        template,
        "fix_tables",
        lambda xml: (calls.append("fix_tables") or xml),
    )
    monkeypatch.setattr(template, "fix_docpr_ids", lambda tree: calls.append("fix_docpr_ids"))
    monkeypatch.setattr(template, "map_tree", lambda tree: calls.append("map_tree"))
    monkeypatch.setattr(
        template,
        "build_headers_footers_xml",
        lambda context, uri, env: [],
    )
    monkeypatch.setattr(
        template,
        "map_headers_footers_xml",
        lambda rel_key, xml: calls.append("map_headers_footers"),
    )
    monkeypatch.setattr(
        template,
        "render_properties",
        lambda context, env: calls.append("render_properties"),
    )
    monkeypatch.setattr(
        template,
        "_render_additional_parts",
        lambda context, env: calls.append("additional_parts"),
    )

    template.render({}, Environment())

    assert "build_xml" in calls
    assert "additional_parts" in calls
    assert calls.index("build_xml") < calls.index("additional_parts")
    assert calls.index("render_properties") < calls.index("additional_parts")


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
    assert "<c:autoUpdate val=\"0\"/>" in chart_xml
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
    assert "<c:autoUpdate val=\"0\"/>" in chart_xml
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
    assert "<c:autoUpdate val=\"0\"/>" in chart_xml
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


def test_patch_xml_handles_excel_tr_endfor_tags():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(WORKSHEET_TR_ENDFOR_XML)

    assert "{% for site in sites %}" in cleaned
    assert "{% endfor %}" in cleaned
    assert "tr for" not in cleaned
    assert "tr endfor" not in cleaned


def test_patch_xml_handles_split_excel_tr_tags():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(WORKSHEET_TR_SPLIT_XML)

    assert "{% for site in project.workbook_data.web.sites %}" in cleaned
    assert "{% endfor %}" in cleaned
    assert "tr for" not in cleaned
    assert "tr endfor" not in cleaned
    assert not re.search(r"<row[^>]*>\\s*{% for", cleaned)
    assert not re.search(r"{% endfor %}\\s*</row", cleaned)


def test_patch_xml_handles_split_excel_tc_tags():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(WORKSHEET_TC_SPLIT_XML)

    assert "tc site.url" not in cleaned
    assert "tc site.unique_high" not in cleaned
    assert "{{ site.url }}" in cleaned
    assert "{{ site.unique_high }}" in cleaned


def test_patch_xml_preserves_chart_paragraph_markup():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(CHART_RICH_TEXT_SPLIT_XML)

    assert "<a:pPr>" in cleaned
    assert "</a:pPr>" in cleaned
    etree.fromstring(cleaned.encode("utf-8"))


def test_patch_xml_strips_tc_in_chart_parts():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(CHART_TC_XML)

    assert "{%tc" not in cleaned
    assert "for device in devices" in cleaned


def test_patch_xml_strips_tr_in_chart_parts():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")

    cleaned = template.patch_xml(CHART_TR_XML)

    assert "{% for device in devices %}" in cleaned
    assert "{% endfor %}" in cleaned
    assert "tr for" not in cleaned
    assert "tr endfor" not in cleaned


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


def test_render_additional_parts_updates_table_columns_for_tc(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TC_RENDERED_COLUMNS_XML,
        content_types_xml=CONTENT_TYPES_WITH_TABLE_XML,
        extra_files={
            "xl/worksheets/_rels/sheet1.xml.rels": SHEET_TABLE_RELS_XML,
            "xl/tables/table1.xml": TABLE_TC_NARROW_XML,
        },
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    template._render_additional_parts({}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        table_xml = archive.read("xl/tables/table1.xml").decode("utf-8")

    tree = etree.fromstring(table_xml.encode("utf-8"))
    ns = tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    assert 'ref="A1:C4"' in table_xml
    assert tree.get("ref") == "A1:C4"
    columns = tree.findall(f"{prefix}tableColumns/{prefix}tableColumn")
    assert len(columns) == 3
    assert [column.get("name") for column in columns] == [
        "Metric",
        "Edge-FW01",
        "Edge-FW02",
    ]


def test_render_additional_parts_renders_tc_column_loops(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TC_LOOP_TEMPLATE_XML,
        content_types_xml=CONTENT_TYPES_WITH_TABLE_XML,
        extra_files={
            "xl/worksheets/_rels/sheet1.xml.rels": SHEET_TABLE_RELS_XML,
            "xl/tables/table1.xml": TABLE_TC_NARROW_XML,
        },
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    domains = [
        {"name": "corp.example.com", "compliant": 145, "stale": 30},
        {"name": "lab.example.com", "compliant": 120, "stale": 25},
    ]

    template._render_additional_parts({"domains": domains}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        table_xml = archive.read("xl/tables/table1.xml").decode("utf-8")

    sheet_tree = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = sheet_tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    rows = sheet_tree.findall(f"{prefix}sheetData/{prefix}row")
    assert len(rows) == 3

    def row_values(row):
        values = []
        for cell in row.findall(f"{prefix}c"):
            value = cell.find(f"{prefix}v")
            if value is not None and value.text is not None:
                values.append(value.text)
                continue
            inline = cell.find(f"{prefix}is")
            if inline is None:
                values.append("")
                continue
            text = "".join(
                node.text or ""
                for node in inline.findall(f".//{prefix}t")
            )
            values.append(text)
        return values

    assert [cell.get("r") for cell in rows[0].findall(f"{prefix}c")] == [
        "A1",
        "B1",
        "C1",
    ]
    assert row_values(rows[0]) == [
        "Old Passwords",
        "corp.example.com",
        "lab.example.com",
    ]

    assert [cell.get("r") for cell in rows[1].findall(f"{prefix}c")] == [
        "A2",
        "B2",
        "C2",
    ]
    assert row_values(rows[1]) == [
        "Compliant",
        "145",
        "120",
    ]

    assert [cell.get("r") for cell in rows[2].findall(f"{prefix}c")] == [
        "A3",
        "B3",
        "C3",
    ]
    assert row_values(rows[2]) == [
        "Stale",
        "30",
        "25",
    ]

    table_tree = etree.fromstring(table_xml.encode("utf-8"))
    table_ns = table_tree.nsmap.get(None)
    table_prefix = f"{{{table_ns}}}" if table_ns else ""

    assert table_tree.get("ref") == "A1:C3"
    columns = table_tree.findall(f"{table_prefix}tableColumns/{table_prefix}tableColumn")
    assert [column.get("name") for column in columns] == [
        "Old Passwords",
        "corp.example.com",
        "lab.example.com",
    ]


def test_render_additional_parts_inserts_rows_for_tr_loop(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TR_LOOP_ROWS_XML,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    sites = [
        {"url": "https://alpha", "high": 5, "medium": 3, "low": 1},
        {"url": "https://beta", "high": 4, "medium": 2, "low": 0},
        {"url": "https://gamma", "high": 6, "medium": 1, "low": 2},
    ]

    template._render_additional_parts({"sites": sites}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")

    tree = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    rows = tree.findall(f"{prefix}sheetData/{prefix}row")
    assert [row.get("r") for row in rows] == ["1", "2", "3", "4"]

    data_rows = rows[1:]
    for idx, row in enumerate(data_rows, start=2):
        cells = row.findall(f"{prefix}c")
        assert [cell.get("r") for cell in cells] == [
            f"A{idx}",
            f"B{idx}",
            f"C{idx}",
            f"D{idx}",
        ]

    dimension = tree.find(f"{prefix}dimension")
    assert dimension is not None
    assert dimension.get("ref") == "A1:D4"

    for site in sites:
        assert site["url"] in sheet_xml
        assert f">{site['high']}<" in sheet_xml
        assert f">{site['medium']}<" in sheet_xml
        assert f">{site['low']}<" in sheet_xml


def test_render_additional_parts_reindexes_project_loop_rows(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TR_PROJECT_XML,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    sites = [
        {"url": "https://alpha", "unique_high": 7, "unique_med": 5, "unique_low": 3},
        {"url": "https://beta", "unique_high": 4, "unique_med": 2, "unique_low": 1},
    ]

    template._render_additional_parts({"project": {"workbook_data": {"web": {"sites": sites}}}}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")

    tree = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    rows = tree.findall(f"{prefix}sheetData/{prefix}row")
    assert [row.get("r") for row in rows] == ["1", "2"]

    dimension = tree.find(f"{prefix}dimension")
    assert dimension is not None
    assert dimension.get("ref") == "A1:D2"

    first_cells = rows[0].findall(f"{prefix}c")
    assert [cell.get("r") for cell in first_cells] == ["A1", "B1", "C1", "D1"]

    first_values = {cell.get("r"): cell for cell in first_cells}
    url = first_values["A1"].find(f"{prefix}is/{prefix}t")
    assert url is not None and url.text == sites[0]["url"]

    for column, key in zip(("B", "C", "D"), ("unique_high", "unique_med", "unique_low")):
        value = first_values[f"{column}1"].find(f"{prefix}v")
        assert value is not None
        assert value.text == str(sites[0][key])

    second_cells = rows[1].findall(f"{prefix}c")
    assert [cell.get("r") for cell in second_cells] == ["A2", "B2", "C2", "D2"]

    second_values = {cell.get("r"): cell for cell in second_cells}
    url = second_values["A2"].find(f"{prefix}is/{prefix}t")
    assert url is not None and url.text == sites[1]["url"]

    for column, key in zip(("B", "C", "D"), ("unique_high", "unique_med", "unique_low")):
        value = second_values[f"{column}2"].find(f"{prefix}v")
        assert value is not None
        assert value.text == str(sites[1][key])


def test_normalise_sheet_rows_removes_empty_rows():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    normalised = template._normalise_sheet_rows(WORKSHEET_TR_RENDERED_GAPS_XML)

    tree = etree.fromstring(normalised.encode("utf-8"))
    ns = tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    rows = tree.findall(f"{prefix}sheetData/{prefix}row")
    assert [row.get("r") for row in rows] == ["1", "2", "3"]

    header_cells = rows[0].findall(f"{prefix}c")
    assert [cell.get("r") for cell in header_cells] == ["A1", "B1", "C1", "D1"]

    first_data = rows[1].findall(f"{prefix}c")
    assert [cell.get("r") for cell in first_data] == ["A2", "B2", "C2", "D2"]

    second_data = rows[2].findall(f"{prefix}c")
    assert [cell.get("r") for cell in second_data] == ["A3", "B3", "C3", "D3"]

    dimension = tree.find(f"{prefix}dimension")
    assert dimension is not None
    assert dimension.get("ref") == "A1:D3"


def test_render_additional_parts_handles_tr_loop_shared_strings(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TR_SHARED_STRINGS_XML,
        SHARED_STRINGS_TR_LOOP_XML,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    sites = [
        {"url": "alpha", "high": 3, "medium": 2, "low": 1},
        {"url": "beta", "high": 4, "medium": 3, "low": 2},
    ]

    template._render_additional_parts({"sites": sites}, None)

    with zipfile.ZipFile(io.BytesIO(excel._blob)) as archive:
        sheet_xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        shared_xml = archive.read("xl/sharedStrings.xml").decode("utf-8")

    assert "{{" not in shared_xml

    tree = etree.fromstring(sheet_xml.encode("utf-8"))
    ns = tree.nsmap.get(None)
    prefix = f"{{{ns}}}" if ns else ""

    rows = tree.findall(f"{prefix}sheetData/{prefix}row")
    assert len(rows) == len(sites) + 1

    data_rows = rows[1:]
    for row, site in zip(data_rows, sites):
        row_index = int(row.get("r"))
        cells = {cell.get("r"): cell for cell in row.findall(f"{prefix}c")}

        url_cell = cells[f"A{row_index}"]
        assert url_cell.get("t") == "inlineStr"
        url_text = url_cell.find(f"{prefix}is/{prefix}t")
        assert url_text is not None
        assert url_text.text == site["url"]

        for column, key in zip(("B", "C", "D"), ("high", "medium", "low")):
            ref = f"{column}{row_index}"
            cell = cells[ref]
            assert cell.get("t") is None
            value = cell.find(f"{prefix}v")
            assert value is not None
            assert value.text == str(site[key])

    dimension = tree.find(f"{prefix}dimension")
    assert dimension is not None
    assert dimension.get("ref") == f"A1:D{len(sites) + 1}"


def test_get_undeclared_variables_ignores_tr_loop_variables(monkeypatch):
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    excel = FakeXlsxPart(
        "/word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
        WORKSHEET_TR_PROJECT_XML,
    )

    monkeypatch.setattr(template, "_iter_additional_parts", lambda: iter([excel]))

    env = Environment()

    class _AnyFilter(dict):
        def __contains__(self, key):  # pragma: no cover - behaviour exercised via meta
            return True

        def __missing__(self, key):  # pragma: no cover - behaviour exercised via meta
            stub = lambda value, *args, **kwargs: value
            self[key] = stub
            return stub

        def get(self, key, default=None):  # pragma: no cover - behaviour exercised via meta
            try:
                return super().__getitem__(key)
            except KeyError:
                return self.__missing__(key)

    env.filters = _AnyFilter(env.filters)

    undeclared = template.get_undeclared_template_variables(env)
    assert "project" in undeclared
    assert "site" not in undeclared


def test_render_prunes_orphan_relationships(tmp_path):
    base_template = Path("DOCS/sample_reports/template.docx")
    original = base_template.read_bytes()

    buffer = io.BytesIO()
    rels_path = "word/_rels/header2.xml.rels"
    relationships_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    doc_relationships_path = "word/_rels/document.xml.rels"

    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == rels_path:
                tree = ET.fromstring(data)
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId999",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                        "Target": "media/missing.png",
                    },
                )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
            elif info.filename == "word/header2.xml":
                data = data.replace(b"</w:hdr>", ORPHANED_DRAWING_PARAGRAPH.encode("utf-8") + b"</w:hdr>")
            elif info.filename == doc_relationships_path:
                tree = ET.fromstring(data)
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId901",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "Cybersecurity Assessment Report Appendices 2025.docx",
                        "TargetMode": "External",
                    },
                )
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId902",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "file:///C:/Temp/Missing.xlsx",
                        "TargetMode": "External",
                    },
                )
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId903",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "https://example.com/report",
                        "TargetMode": "External",
                    },
                )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
            elif info.filename == "word/document.xml":
                data = data.replace(b"</w:body>", ORPHANED_HYPERLINK_PARAGRAPH.encode("utf-8") + b"</w:body>")

            dst.writestr(info, data)

    modified_template = tmp_path / "broken_template.docx"
    modified_template.write_bytes(buffer.getvalue())

    template = GhostwriterDocxTemplate(str(modified_template))
    template.render({}, Environment())

    output_doc = tmp_path / "rendered.docx"
    template.save(output_doc)

    with zipfile.ZipFile(output_doc) as archive:
        rels_xml = archive.read(rels_path).decode("utf-8")
        header_xml = archive.read("word/header2.xml").decode("utf-8")
        document_xml = archive.read("word/document.xml").decode("utf-8")
        doc_rels_xml = archive.read(doc_relationships_path).decode("utf-8")

    assert "media/image1.png" in rels_xml
    assert "media/missing.png" not in rels_xml
    assert "rId999" not in header_xml
    assert "See appendix" in document_xml
    assert "rId901" not in document_xml
    assert "rId902" not in document_xml
    assert "rId903" in document_xml
    assert "Cybersecurity Assessment Report Appendices 2025.docx" not in doc_rels_xml
    assert "file:///c:/temp/missing.xlsx" not in doc_rels_xml.lower()
    assert "https://example.com/report" in doc_rels_xml


def test_render_removes_unreferenced_chart_parts(tmp_path):
    base_template = Path("DOCS/sample_reports/template.docx")
    original = base_template.read_bytes()

    buffer = io.BytesIO()
    doc_relationships_path = "word/_rels/document.xml.rels"
    chart_part = "word/charts/chart999.xml"
    relationships_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    content_types_ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    chart_reltype = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart"
    chart_content_type = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml"
    chart_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart">'
        "<c:lang val=\"en-US\"/>"
        "</c:chartSpace>"
    )

    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == doc_relationships_path:
                tree = ET.fromstring(data)
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId999",
                        "Type": chart_reltype,
                        "Target": "charts/chart999.xml",
                    },
                )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
            elif info.filename == "[Content_Types].xml":
                tree = ET.fromstring(data)
                override_tag = f"{{{content_types_ns}}}Override"
                has_override = any(
                    element.get("PartName") == f"/{chart_part}"
                    for element in tree.findall(override_tag)
                )
                if not has_override:
                    ET.SubElement(
                        tree,
                        override_tag,
                        {
                            "PartName": f"/{chart_part}",
                            "ContentType": chart_content_type,
                        },
                    )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)

            dst.writestr(info, data)

        dst.writestr(chart_part, chart_xml)

    modified_template = tmp_path / "chart_template.docx"
    modified_template.write_bytes(buffer.getvalue())

    template = GhostwriterDocxTemplate(str(modified_template))
    template.render({}, Environment())

    output_doc = tmp_path / "rendered.docx"
    template.save(output_doc)

    with zipfile.ZipFile(output_doc) as archive:
        names = archive.namelist()
        assert chart_part not in names
        doc_rels_xml = archive.read(doc_relationships_path).decode("utf-8")
        assert "rId999" not in doc_rels_xml


def test_prepare_additional_parts_detects_smartart_relationship_attributes():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    class DummyRelationship:
        def __init__(self, target_part):
            self.target_part = target_part
            self.is_external = False

    class DummyPart:
        def __init__(self, name: str):
            self.partname = PackURI(f"/{name}")
            self.rels: dict[str, DummyRelationship] = {}

        def drop_rel(self, rel_id: str) -> None:
            self.rels.pop(rel_id, None)

    class DummyPackage:
        def __init__(self, parts: list[DummyPart]):
            self._parts = parts

        def iter_parts(self):
            return iter(self._parts)

    class DummyDocx:
        def __init__(self, part: DummyPart):
            self.part = part

    document_element = parse_xml(SMARTART_DOCUMENT_XML.encode("utf-8"))

    doc_part = DummyPart("word/document.xml")
    doc_part.element = document_element

    data_part = DummyPart("word/diagrams/data5.xml")
    drawing_part = DummyPart("word/diagrams/drawing5.xml")
    layout_part = DummyPart("word/diagrams/layout5.xml")
    quick_part = DummyPart("word/diagrams/quickStyle5.xml")
    color_part = DummyPart("word/diagrams/colors5.xml")

    doc_part.rels = {
        "rIdDrawing": DummyRelationship(drawing_part),
        "rIdData": DummyRelationship(data_part),
        "rIdLayout": DummyRelationship(layout_part),
        "rIdQuick": DummyRelationship(quick_part),
        "rIdColor": DummyRelationship(color_part),
    }

    package = DummyPackage(
        [doc_part, data_part, drawing_part, layout_part, quick_part, color_part]
    )
    doc_part.package = package

    template.docx = DummyDocx(doc_part)

    template._prepare_additional_parts()

    assert template._active_additional_partnames == {
        "word/diagrams/data5.xml",
        "word/diagrams/drawing5.xml",
    }
    assert set(doc_part.rels.keys()) == {
        "rIdDrawing",
        "rIdData",
        "rIdLayout",
        "rIdQuick",
        "rIdColor",
    }


def test_prepare_additional_parts_keeps_diagram_dependencies_without_relids():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    class DummyRelationship:
        def __init__(self, target_part):
            self.target_part = target_part
            self.is_external = False

    class DummyPart:
        def __init__(self, name: str, element=None):
            self.partname = PackURI(f"/{name}")
            self._partname = name
            self._element = element
            self._blob = None
            self.rels: dict[str, DummyRelationship] = {}

        @property
        def element(self):
            return self._element

        @element.setter
        def element(self, value):
            self._element = value

        def drop_rel(self, rel_id: str) -> None:
            self.rels.pop(rel_id, None)

    class DummyPackage:
        def __init__(self, parts: list[DummyPart]):
            self._parts = parts

        def iter_parts(self):
            return iter(self._parts)

    class DummyDocx:
        def __init__(self, part: DummyPart):
            self.part = part

    document_element = parse_xml(
        SMARTART_DOCUMENT_DATA_ONLY_XML.encode("utf-8")
    )
    data_element = parse_xml(
        '<dgm:data xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram"/>'
        .encode("utf-8")
    )

    doc_part = DummyPart("word/document.xml", document_element)
    data_part = DummyPart("word/diagrams/data5.xml", data_element)
    drawing_part = DummyPart("word/diagrams/drawing5.xml")

    doc_part.rels = {
        "rIdData": DummyRelationship(data_part),
    }

    data_part.rels = {
        "rIdDrawing": DummyRelationship(drawing_part),
    }

    package = DummyPackage([doc_part, data_part, drawing_part])
    doc_part.package = package

    template.docx = DummyDocx(doc_part)

    template._prepare_additional_parts()

    assert template._active_additional_partnames == {
        "word/diagrams/data5.xml",
        "word/diagrams/drawing5.xml",
    }
    assert set(data_part.rels.keys()) == {"rIdDrawing"}


def test_prepare_additional_parts_detects_relid_attributes_on_non_extra_parts():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    class DummyRelationship:
        def __init__(self, target_part):
            self.target_part = target_part
            self.is_external = False

    class DummyPart:
        def __init__(self, name: str, element=None):
            self.partname = PackURI(f"/{name}")
            self._element = element
            self._blob = None
            self.rels: dict[str, DummyRelationship] = {}

        def drop_rel(self, rel_id: str) -> None:
            self.rels.pop(rel_id, None)

    class DummyPackage:
        def __init__(self, parts: list[DummyPart]):
            self._parts = parts

        def iter_parts(self):
            return iter(self._parts)

    class DummyDocx:
        def __init__(self, part: DummyPart):
            self.part = part

    document_element = parse_xml(
        (
            '<w:document '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            "<w:body/>"
            "</w:document>"
        ).encode("utf-8")
    )

    header_element = parse_xml(
        (
            '<w:hdr '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
            'xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
            '<w:p><w:r><dgm:relIds relId="rIdDrawing"/></w:r></w:p>'
            "</w:hdr>"
        ).encode("utf-8")
    )

    doc_part = DummyPart("word/document.xml", document_element)
    header_part = DummyPart("word/header1.xml", header_element)
    drawing_part = DummyPart("word/diagrams/drawing5.xml")

    doc_part.rels = {"rIdHeader": DummyRelationship(header_part)}
    header_part.rels = {"rIdDrawing": DummyRelationship(drawing_part)}

    package = DummyPackage([doc_part, header_part, drawing_part])
    doc_part.package = package

    template.docx = DummyDocx(doc_part)

    template._prepare_additional_parts()

    assert template._active_additional_partnames == {"word/diagrams/drawing5.xml"}
    assert set(header_part.rels.keys()) == {"rIdDrawing"}


def test_renumber_chart_assets_assigns_sequential_names():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    class DummyRelationship:
        def __init__(self, target_part):
            self.target_part = target_part
            self.is_external = False

    class DummyPart:
        def __init__(self, name: str):
            self.partname = PackURI(f"/{name}")
            self.rels: dict[str, DummyRelationship] = {}

    class DummyPackage:
        def __init__(self, parts: list[DummyPart]):
            self._parts = parts

        def iter_parts(self):
            return iter(self._parts)

    class DummyDocPart:
        def __init__(self, package: DummyPackage):
            self.package = package

    class DummyDocx:
        def __init__(self, package: DummyPackage):
            self.part = DummyDocPart(package)

    chart_a = DummyPart("word/charts/chart3.xml")
    color_a = DummyPart("word/charts/colors9.xml")
    style_a = DummyPart("word/charts/style4.xml")
    workbook_a = DummyPart("word/embeddings/Microsoft_Excel_Worksheet7.xlsx")
    chart_a.rels = {
        "rIdColor": DummyRelationship(color_a),
        "rIdStyle": DummyRelationship(style_a),
        "rIdWorkbook": DummyRelationship(workbook_a),
    }

    chart_b = DummyPart("word/charts/chart10.xml")
    color_b = DummyPart("word/charts/colors3.xml")
    style_b = DummyPart("word/charts/style12.xml")
    workbook_b = DummyPart("word/embeddings/Microsoft_Excel_Worksheet12.xlsx")
    chart_b.rels = {
        "rIdColor": DummyRelationship(color_b),
        "rIdStyle": DummyRelationship(style_b),
        "rIdWorkbook": DummyRelationship(workbook_b),
    }

    parts = [
        chart_a,
        color_a,
        style_a,
        workbook_a,
        chart_b,
        color_b,
        style_b,
        workbook_b,
    ]
    package = DummyPackage(parts)
    template.docx = DummyDocx(package)

    template._active_additional_partnames = {
        "word/charts/chart3.xml",
        "word/charts/colors9.xml",
        "word/charts/style4.xml",
        "word/embeddings/Microsoft_Excel_Worksheet7.xlsx",
        "word/charts/chart10.xml",
        "word/charts/colors3.xml",
        "word/charts/style12.xml",
        "word/embeddings/Microsoft_Excel_Worksheet12.xlsx",
    }

    template._renumber_chart_assets()

    assert template._normalise_partname(chart_a) == "word/charts/chart1.xml"
    assert template._normalise_partname(chart_b) == "word/charts/chart2.xml"
    assert template._normalise_partname(color_a) == "word/charts/colors1.xml"
    assert template._normalise_partname(color_b) == "word/charts/colors2.xml"
    assert template._normalise_partname(style_a) == "word/charts/style1.xml"
    assert template._normalise_partname(style_b) == "word/charts/style2.xml"
    assert (
        template._normalise_partname(workbook_a)
        == "word/embeddings/Microsoft_Excel_Worksheet.xlsx"
    )
    assert (
        template._normalise_partname(workbook_b)
        == "word/embeddings/Microsoft_Excel_Worksheet1.xlsx"
    )

    assert template._active_additional_partnames == {
        "word/charts/chart1.xml",
        "word/charts/chart2.xml",
        "word/charts/colors1.xml",
        "word/charts/colors2.xml",
        "word/charts/style1.xml",
        "word/charts/style2.xml",
        "word/embeddings/Microsoft_Excel_Worksheet.xlsx",
        "word/embeddings/Microsoft_Excel_Worksheet1.xlsx",
    }


def test_renumber_chart_assets_handles_shared_color_parts():
    template = GhostwriterDocxTemplate("DOCS/sample_reports/template.docx")
    template.init_docx()

    class DummyRelationship:
        def __init__(self, target_part):
            self.target_part = target_part
            self.is_external = False

    class DummyPart:
        def __init__(self, name: str):
            self.partname = PackURI(f"/{name}")
            self.rels: dict[str, DummyRelationship] = {}

    class DummyPackage:
        def __init__(self, parts: list[DummyPart]):
            self._parts = parts

        def iter_parts(self):
            return iter(self._parts)

    class DummyDocPart:
        def __init__(self, package: DummyPackage):
            self.package = package

    class DummyDocx:
        def __init__(self, package: DummyPackage):
            self.part = DummyDocPart(package)

    shared_color = DummyPart("word/charts/colors9.xml")
    shared_style = DummyPart("word/charts/style9.xml")

    chart_one = DummyPart("word/charts/chart4.xml")
    chart_one.rels = {
        "rIdColor": DummyRelationship(shared_color),
        "rIdStyle": DummyRelationship(shared_style),
    }

    chart_two = DummyPart("word/charts/chart7.xml")
    chart_two.rels = {
        "rIdColor": DummyRelationship(shared_color),
        "rIdStyle": DummyRelationship(shared_style),
    }

    chart_three = DummyPart("word/charts/chart9.xml")
    color_three = DummyPart("word/charts/colors15.xml")
    style_three = DummyPart("word/charts/style17.xml")
    chart_three.rels = {
        "rIdColor": DummyRelationship(color_three),
        "rIdStyle": DummyRelationship(style_three),
    }

    parts = [
        chart_one,
        shared_color,
        shared_style,
        chart_two,
        chart_three,
        color_three,
        style_three,
    ]

    package = DummyPackage(parts)
    template.docx = DummyDocx(package)

    template._active_additional_partnames = {
        "word/charts/chart4.xml",
        "word/charts/chart7.xml",
        "word/charts/chart9.xml",
        "word/charts/colors9.xml",
        "word/charts/colors15.xml",
        "word/charts/style9.xml",
        "word/charts/style17.xml",
    }

    template._renumber_chart_assets()

    assert template._normalise_partname(shared_color) == "word/charts/colors1.xml"
    assert template._normalise_partname(color_three) == "word/charts/colors2.xml"
    assert template._normalise_partname(shared_style) == "word/charts/style1.xml"
    assert template._normalise_partname(style_three) == "word/charts/style2.xml"

    assert template._active_additional_partnames == {
        "word/charts/chart1.xml",
        "word/charts/chart2.xml",
        "word/charts/chart3.xml",
        "word/charts/colors1.xml",
        "word/charts/colors2.xml",
        "word/charts/style1.xml",
        "word/charts/style2.xml",
    }

def test_render_merges_duplicate_body_elements(tmp_path):
    base_template = Path("DOCS/sample_reports/template.docx")
    original = base_template.read_bytes()

    buffer = io.BytesIO()

    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "word/document.xml":
                data = data.replace(
                    b"</w:body>",
                    b"</w:body>" + DUPLICATE_BODY_BLOCK.encode("utf-8"),
                    1,
                )

            dst.writestr(info, data)

    modified_template = tmp_path / "duplicate_body_template.docx"
    modified_template.write_bytes(buffer.getvalue())

    template = GhostwriterDocxTemplate(str(modified_template))
    template.render({}, Environment())

    output_doc = tmp_path / "rendered.docx"
    template.save(output_doc)

    with zipfile.ZipFile(output_doc) as archive:
        document_xml = archive.read("word/document.xml")

    tree = etree.fromstring(document_xml)
    namespaces = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    bodies = tree.xpath("./w:body", namespaces=namespaces)

    assert len(bodies) == 1
    assert b"Extra Section" in document_xml


def test_render_preserves_primary_section_properties(tmp_path):
    base_template = Path("DOCS/sample_reports/template.docx")
    original = base_template.read_bytes()

    with zipfile.ZipFile(io.BytesIO(original)) as src:
        document_xml = src.read("word/document.xml")

    namespaces = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    }

    original_tree = etree.fromstring(document_xml)
    original_sectpr = original_tree.xpath("./w:body/w:sectPr", namespaces=namespaces)[0]
    original_refs = {
        child.tag: child.get(f"{{{namespaces['r']}}}id")
        for child in original_sectpr
        if child.get(f"{{{namespaces['r']}}}id") is not None
    }

    duplicate_body = (
        '<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:p><w:r><w:t>Legacy Section</w:t></w:r></w:p>'
        '<w:sectPr>'
        '<w:headerReference w:type="default" r:id="rId999"/>'
        '<w:footerReference w:type="default" r:id="rId998"/>'
        '</w:sectPr>'
        '</w:body>'
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "word/document.xml":
                data = data.replace(b"</w:body>", b"</w:body>" + duplicate_body.encode("utf-8"), 1)
            dst.writestr(info, data)

    modified_template = tmp_path / "section_template.docx"
    modified_template.write_bytes(buffer.getvalue())

    template = GhostwriterDocxTemplate(str(modified_template))
    template.render({}, Environment())

    output_doc = tmp_path / "rendered.docx"
    template.save(output_doc)

    with zipfile.ZipFile(output_doc) as archive:
        rendered_xml = archive.read("word/document.xml")

    rendered_tree = etree.fromstring(rendered_xml)
    rendered_sectpr = rendered_tree.xpath("./w:body/w:sectPr", namespaces=namespaces)[0]
    rendered_refs = {
        child.tag: child.get(f"{{{namespaces['r']}}}id")
        for child in rendered_sectpr
        if child.get(f"{{{namespaces['r']}}}id") is not None
    }

    rendered_text = rendered_xml.decode("utf-8")
    assert "rId999" not in rendered_text
    assert "rId998" not in rendered_text
    assert rendered_refs == original_refs


def test_render_removes_attached_template_reference(tmp_path):
    base_template = Path("DOCS/sample_reports/template.docx")
    original = base_template.read_bytes()

    relationships_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    word_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    rel_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"

    buffer = io.BytesIO()

    with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(buffer, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "word/settings.xml":
                tree = ET.fromstring(data)
                attached = ET.SubElement(tree, f"{{{word_ns}}}attachedTemplate")
                attached.set(
                    f"{{http://schemas.openxmlformats.org/officeDocument/2006/relationships}}id",
                    "rId555",
                )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)
            elif info.filename == "word/_rels/settings.xml.rels":
                tree = ET.fromstring(data)
                ET.SubElement(
                    tree,
                    f"{{{relationships_ns}}}Relationship",
                    {
                        "Id": "rId555",
                        "Type": rel_type,
                        "Target": "file:///C:/Templates/Legacy.dotx",
                        "TargetMode": "External",
                    },
                )
                data = ET.tostring(tree, encoding="utf-8", xml_declaration=True)

            dst.writestr(info, data)

    modified_template = tmp_path / "attached_template.docx"
    modified_template.write_bytes(buffer.getvalue())

    template = GhostwriterDocxTemplate(str(modified_template))
    template.render({}, Environment())

    output_doc = tmp_path / "rendered.docx"
    template.save(output_doc)

    with zipfile.ZipFile(output_doc) as archive:
        settings_xml = archive.read("word/settings.xml").decode("utf-8")
        rels_xml = archive.read("word/_rels/settings.xml.rels").decode("utf-8")

    assert "attachedTemplate" not in settings_xml
    assert "rId555" not in rels_xml

