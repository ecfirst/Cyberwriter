"""Extended DocxTemplate with support for additional templated parts."""

from __future__ import annotations

import fnmatch
import posixpath
from io import BytesIO
import re
from typing import Iterator
from zipfile import ZipFile, ZipInfo

from docx.oxml import parse_xml
from docxtpl.template import DocxTemplate
from jinja2 import Environment, meta
from xml.etree import ElementTree as ET


_EXCEL_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ET.register_namespace("", _EXCEL_MAIN_NS)


_CHART_MAIN_NS = "http://schemas.openxmlformats.org/drawingml/2006/chart"
_CHART_NS = {"c": _CHART_MAIN_NS}


_JINJA_STATEMENT_RE = re.compile(r"({[{%#].*?[}%]})", re.DOTALL)

_CHART_FORMULA_RE = re.compile(
    r"^(?:\[(?P<workbook>[^\]]+)\])?(?P<sheet>'[^']+'|[^'!]+)!(?P<range>.+)$"
)


class GhostwriterDocxTemplate(DocxTemplate):
    """Docx template that also renders SmartArt and embedded workbook parts.

    Microsoft Word stores SmartArt data in the ``word/diagrams`` folder of the
    DOCX package and embedded worksheets in ``word/embeddings`` as XLSX files.
    The python-docx-template library does not process those parts when
    rendering a document or when collecting undeclared variables for linting.
    This subclass extends the renderer so those parts participate in templating
    just like the document body.
    """

    _EXTRA_TEMPLATED_PATTERNS: tuple[str, ...] = (
        "word/diagrams/data*.xml",
        "word/diagrams/drawing*.xml",
        "word/charts/*.xml",
        "word/embeddings/*.xlsx",
    )

    def render(self, context, jinja_env=None, autoescape: bool = False) -> None:  # type: ignore[override]
        """Render the template, including SmartArt diagram XML parts."""

        # Initialisation mirrors :meth:`docxtpl.template.DocxTemplate.render` so we
        # can hook additional parts into the rendering pipeline while reusing the
        # base implementation for the main document.
        self.render_init()

        if autoescape:
            if not jinja_env:
                jinja_env = Environment(autoescape=autoescape)
            else:
                jinja_env.autoescape = autoescape

        xml_src = self.build_xml(context, jinja_env)
        tree = self.fix_tables(xml_src)
        self.fix_docpr_ids(tree)
        self.map_tree(tree)

        headers = self.build_headers_footers_xml(context, self.HEADER_URI, jinja_env)
        for rel_key, xml in headers:
            self.map_headers_footers_xml(rel_key, xml)

        footers = self.build_headers_footers_xml(context, self.FOOTER_URI, jinja_env)
        for rel_key, xml in footers:
            self.map_headers_footers_xml(rel_key, xml)

        self._render_additional_parts(context, jinja_env)

        self.render_properties(context, jinja_env)

        self.is_rendered = True

    def get_undeclared_template_variables(self, jinja_env=None):  # type: ignore[override]
        """Return undeclared variables, including those in SmartArt parts."""

        self.init_docx(reload=False)

        xml_sources = [self.patch_xml(self.get_xml())]
        for uri in (self.HEADER_URI, self.FOOTER_URI):
            for _rel_key, part in self.get_headers_footers(uri):
                xml_sources.append(self.patch_xml(self.get_part_xml(part)))

        for part in self._iter_additional_parts():
            if self._is_excel_part(part):
                xml_sources.extend(self._iter_excel_xml_strings(part))
            else:
                xml_sources.append(self.patch_xml(self.get_part_xml(part)))

        env = jinja_env or Environment()
        parse_content = env.parse("".join(xml_sources))
        return meta.find_undeclared_variables(parse_content)

    def patch_xml(self, src_xml):  # type: ignore[override]
        """Normalize XML for templating across Word body and SmartArt parts."""

        patched = super().patch_xml(src_xml)

        def strip_namespaced_tags(match: re.Match[str]) -> str:
            statement = match.group(0)
            cleaned: list[str] = []
            in_single = False
            in_double = False
            idx = 0

            while idx < len(statement):
                char = statement[idx]
                if char == "'" and not in_double:
                    in_single = not in_single
                    cleaned.append(char)
                    idx += 1
                    continue
                if char == '"' and not in_single:
                    in_double = not in_double
                    cleaned.append(char)
                    idx += 1
                    continue
                if char == "<" and not in_single and not in_double:
                    end = statement.find(">", idx)
                    if end == -1:
                        cleaned.append(char)
                        idx += 1
                        continue
                    idx = end + 1
                    continue

                cleaned.append(char)
                idx += 1

            return "".join(cleaned)

        return _JINJA_STATEMENT_RE.sub(strip_namespaced_tags, patched)

    # ------------------------------------------------------------------
    # Helpers

    def _iter_additional_parts(self) -> Iterator:
        """Yield DOCX parts that should be templated in addition to the body."""

        if not self.docx:
            return

        package = self.docx.part.package
        seen: set[str] = set()
        for part in package.iter_parts():
            partname = str(part.partname).lstrip("/")
            if partname in seen:
                continue
            if self._matches_extra_template(partname):
                seen.add(partname)
                yield part

    def _matches_extra_template(self, partname: str) -> bool:
        return any(fnmatch.fnmatch(partname, pattern) for pattern in self._EXTRA_TEMPLATED_PATTERNS)

    def _render_additional_parts(self, context, jinja_env) -> None:
        excel_results: dict[str, dict[str, object]] = {}
        chart_parts: list = []
        other_parts: list = []

        for part in self._iter_additional_parts():
            if self._is_excel_part(part):
                partname = self._get_partname(part)
                result = self._render_excel_part(part, context, jinja_env)
                if result is not None:
                    final_bytes, workbook_data = result
                    excel_results[partname] = {
                        "bytes": final_bytes,
                        "data": workbook_data or {},
                        "basename": partname.split("/")[-1],
                    }
                continue

            if self._is_chart_part(part):
                chart_parts.append(part)
                continue

            other_parts.append(part)

        for part in other_parts:
            self._render_generic_xml_part(part, context, jinja_env)

        if not chart_parts:
            return

        for part in chart_parts:
            self._render_chart_part(part, context, jinja_env, excel_results)

    def _is_excel_part(self, part) -> bool:
        partname = str(part.partname).lstrip("/")
        return partname.endswith(".xlsx")

    def _is_chart_part(self, part) -> bool:
        partname = self._get_partname(part)
        return partname.startswith("word/charts/") and partname.endswith(".xml")

    def _get_partname(self, part) -> str:
        return str(part.partname).lstrip("/")

    def _iter_excel_xml_strings(self, part) -> Iterator[str]:
        blob = getattr(part, "blob", None)
        if blob is None:
            blob = getattr(part, "_blob", b"")
        if not blob:
            return

        with ZipFile(BytesIO(blob)) as archive:
            for info in archive.infolist():
                if not info.filename.lower().endswith(".xml"):
                    continue
                xml = archive.read(info.filename).decode("utf-8")
                yield self.patch_xml(xml)

    def _render_generic_xml_part(self, part, context, jinja_env) -> None:
        xml = self.get_part_xml(part)
        patched = self.patch_xml(xml)
        rendered = self.render_xml_part(patched, part, context, jinja_env)
        rendered_bytes = rendered.encode("utf-8")
        if hasattr(part, "_element"):
            part._element = parse_xml(rendered_bytes)
        if hasattr(part, "_blob"):
            part._blob = rendered_bytes

    def _render_excel_part(self, part, context, jinja_env):
        blob = getattr(part, "blob", None)
        if blob is None:
            blob = getattr(part, "_blob", b"")
        if not blob:
            return None

        source = BytesIO(blob)

        rendered_files: dict[str, bytes] = {}
        file_infos: dict[str, ZipInfo] = {}
        with ZipFile(source, "r") as archive:
            for info in archive.infolist():
                data = archive.read(info.filename)
                if info.filename.lower().endswith(".xml"):
                    xml = data.decode("utf-8")
                    patched = self.patch_xml(xml)
                    rendered = self.render_xml_part(patched, part, context, jinja_env)
                    data = rendered.encode("utf-8")
                rendered_files[info.filename] = data
                file_infos[info.filename] = info

        shared_strings: dict[int, str] | None = None
        shared_strings_key = next(
            (name for name in rendered_files if name.lower() == "xl/sharedstrings.xml"),
            None,
        )
        if shared_strings_key is not None:
            shared_strings = self._parse_excel_shared_strings(
                rendered_files[shared_strings_key].decode("utf-8")
            )

        worksheet_values: dict[str, dict[str, object]] = {}

        for filename, data in list(rendered_files.items()):
            if not filename.startswith("xl/worksheets/") or not filename.lower().endswith(".xml"):
                continue
            xml = data.decode("utf-8")
            processed_xml, sheet_data = self._process_excel_worksheet_xml(
                xml, shared_strings
            )
            if processed_xml != xml:
                rendered_files[filename] = processed_xml.encode("utf-8")
            worksheet_values[filename] = sheet_data

        sheet_map = self._parse_workbook_sheets(rendered_files)
        workbook_data: dict[str, dict[str, object]] = {}
        for path, name in sheet_map.items():
            values = worksheet_values.get(path)
            if values is not None:
                workbook_data[name] = values

        final_bytes = self._build_excel_archive(rendered_files, file_infos)

        if hasattr(part, "_blob"):
            part._blob = final_bytes

        return final_bytes, workbook_data

    def _render_chart_part(
        self,
        part,
        context,
        jinja_env,
        excel_results: dict[str, dict[str, object]],
    ) -> None:
        xml = self.get_part_xml(part)
        patched = self.patch_xml(xml)
        rendered = self.render_xml_part(patched, part, context, jinja_env)
        rendered = self._refresh_chart_cache_from_workbooks(part, rendered, excel_results)
        rendered_bytes = rendered.encode("utf-8")
        if hasattr(part, "_element"):
            part._element = parse_xml(rendered_bytes)
        if hasattr(part, "_blob"):
            part._blob = rendered_bytes

    # ------------------------------------------------------------------
    # Excel helpers

    def _build_excel_archive(
        self, rendered_files: dict[str, bytes], file_infos: dict[str, ZipInfo]
    ) -> bytes:
        buffer = BytesIO()
        with ZipFile(buffer, "w") as patched_archive:
            for filename, data in rendered_files.items():
                info = file_infos.get(filename)
                if info is not None:
                    patched_archive.writestr(self._clone_zipinfo(info), data)
                else:
                    patched_archive.writestr(filename, data)
        return buffer.getvalue()

    def _process_excel_worksheet_xml(
        self, xml: str, shared_strings: dict[int, str] | None
    ) -> tuple[str, dict[str, object]]:
        """Coerce numeric cells and return extracted worksheet values."""

        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return xml, {}

        namespace = {"x": _EXCEL_MAIN_NS}
        changed = False
        sheet_data: dict[str, object] = {}

        for cell in root.findall(".//x:c", namespace):
            coordinate = cell.get("r")
            if not coordinate:
                continue

            cell_type = cell.get("t")
            text_value = self._extract_excel_cell_text(
                cell, cell_type, namespace, shared_strings
            )

            if cell_type in {"inlineStr", "str", "s"}:
                numeric_text = self._normalize_numeric_string(text_value)
                if numeric_text is not None:
                    self._apply_numeric_cell(cell, cell_type, namespace, numeric_text)
                    converted = self._cast_numeric_value(numeric_text)
                    sheet_data[coordinate] = converted if converted is not None else numeric_text
                    changed = True
                    continue
                sheet_data[coordinate] = text_value
                continue

            if cell_type == "b":
                sheet_data[coordinate] = self._interpret_excel_bool(text_value)
                continue

            numeric_text = self._normalize_numeric_string(text_value)
            if numeric_text is not None:
                converted = self._cast_numeric_value(numeric_text)
                sheet_data[coordinate] = converted if converted is not None else numeric_text
            else:
                sheet_data[coordinate] = text_value

        if changed:
            return ET.tostring(root, encoding="unicode"), sheet_data

        return xml, sheet_data

    def _apply_numeric_cell(
        self,
        cell,
        cell_type: str | None,
        namespace: dict[str, str],
        numeric_text: str,
    ) -> None:
        if cell_type == "inlineStr":
            for child in list(cell):
                cell.remove(child)
            value_element = ET.SubElement(cell, f"{{{_EXCEL_MAIN_NS}}}v")
        else:
            value_element = cell.find("x:v", namespace)
            if value_element is None:
                value_element = ET.SubElement(cell, f"{{{_EXCEL_MAIN_NS}}}v")
        value_element.text = numeric_text
        cell.attrib.pop("t", None)

    # ------------------------------------------------------------------
    # Chart helpers

    def _refresh_chart_cache_from_workbooks(
        self,
        part,
        xml: str,
        excel_results: dict[str, dict[str, object]],
    ) -> str:
        if not excel_results:
            return xml

        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return xml

        self._ensure_chart_auto_update(root)

        workbook_map = self._resolve_chart_workbooks(part, excel_results)
        if not workbook_map:
            return ET.tostring(root, encoding="unicode")

        updated = False

        for num_ref in root.findall(".//c:numRef", _CHART_NS):
            if self._update_chart_reference(num_ref, workbook_map, numeric=True):
                updated = True

        for str_ref in root.findall(".//c:strRef", _CHART_NS):
            if self._update_chart_reference(str_ref, workbook_map, numeric=False):
                updated = True

        if not updated:
            return ET.tostring(root, encoding="unicode")

        return ET.tostring(root, encoding="unicode")

    def _ensure_chart_auto_update(self, root: ET.Element) -> None:
        external = root.find(".//c:externalData", _CHART_NS)
        if external is None:
            return

        auto = external.find("c:autoUpdate", _CHART_NS)
        if auto is None:
            auto = ET.SubElement(external, f"{{{_CHART_MAIN_NS}}}autoUpdate")
        auto.set("val", "1")

    def _resolve_chart_workbooks(
        self,
        part,
        excel_results: dict[str, dict[str, object]],
    ) -> dict[str, dict[str, object]]:
        partnames = []
        related_parts = getattr(part, "related_parts", None)
        if isinstance(related_parts, dict):
            partnames.extend(
                self._get_partname(related)
                for related in related_parts.values()
                if self._is_excel_part(related)
            )
        else:
            rels = getattr(part, "rels", None)
            if rels is not None:
                for rel in getattr(rels, "values", lambda: [])():
                    target = getattr(rel, "target_part", None)
                    if target is not None and self._is_excel_part(target):
                        partnames.append(self._get_partname(target))

        if not partnames and len(excel_results) == 1:
            partnames = [next(iter(excel_results))]

        workbook_map: dict[str, dict[str, object]] = {}
        for partname in partnames:
            info = excel_results.get(partname)
            if not info:
                continue
            data = info.get("data")
            if isinstance(data, dict):
                workbook_map[partname] = data

        if workbook_map:
            return workbook_map

        # Fall back to matching on the basename if direct lookup fails.
        basename_map = {info["basename"]: key for key, info in excel_results.items() if "basename" in info}
        resolved: dict[str, dict[str, object]] = {}
        for partname in partnames:
            basename = partname.split("/")[-1]
            target_partname = basename_map.get(basename)
            if not target_partname:
                continue
            data = excel_results[target_partname].get("data")
            if isinstance(data, dict):
                resolved[target_partname] = data
        if resolved:
            return resolved

        return {}

    def _update_chart_reference(
        self,
        ref_element: ET.Element,
        workbook_map: dict[str, dict[str, object]],
        *,
        numeric: bool,
    ) -> bool:
        formula = ref_element.find("c:f", _CHART_NS)
        if formula is None or not formula.text:
            return False

        workbook_key, sheet_name, coords = self._parse_chart_formula(formula.text)
        if sheet_name is None or not coords:
            return False

        workbook_data = None
        if workbook_key is not None:
            for partname, data in workbook_map.items():
                basename = partname.split("/")[-1]
                if basename == workbook_key:
                    workbook_data = data
                    break
        if workbook_data is None:
            workbook_data = next(iter(workbook_map.values()), None)
        if workbook_data is None:
            return False

        values = self._collect_range_values(workbook_data, sheet_name, coords)
        if values is None:
            return False

        cache_tag = "numCache" if numeric else "strCache"
        cache = ref_element.find(f"c:{cache_tag}", _CHART_NS)
        if cache is None:
            cache = ET.SubElement(ref_element, f"{{{_CHART_MAIN_NS}}}{cache_tag}")

        for existing in list(cache.findall("c:pt", _CHART_NS)):
            cache.remove(existing)

        pt_count = cache.find("c:ptCount", _CHART_NS)
        if pt_count is None:
            pt_count = ET.SubElement(cache, f"{{{_CHART_MAIN_NS}}}ptCount")
        pt_count.set("val", str(len(values)))

        for idx, value in enumerate(values):
            pt = ET.SubElement(cache, f"{{{_CHART_MAIN_NS}}}pt", {"idx": str(idx)})
            val = ET.SubElement(pt, f"{{{_CHART_MAIN_NS}}}v")
            if value is None:
                val.text = ""
            elif numeric and isinstance(value, (int, float)):
                val.text = self._format_numeric_value(value)
            else:
                val.text = str(value)

        return True

    def _parse_chart_formula(
        self, formula: str
    ) -> tuple[str | None, str | None, tuple[tuple[int, int], tuple[int, int]] | None]:
        match = _CHART_FORMULA_RE.match(formula.strip())
        if not match:
            return None, None, None

        workbook = match.group("workbook")
        sheet = match.group("sheet")
        ref_range = match.group("range")

        if sheet:
            sheet = sheet.strip("'")

        coords = self._parse_range(ref_range)
        return workbook, sheet, coords

    def _parse_range(
        self, ref_range: str
    ) -> tuple[tuple[int, int], tuple[int, int]] | None:
        if ":" in ref_range:
            start, end = ref_range.split(":", 1)
        else:
            start = end = ref_range

        start_coord = self._parse_coordinate(start)
        end_coord = self._parse_coordinate(end)
        if start_coord is None or end_coord is None:
            return None

        return start_coord, end_coord

    def _parse_coordinate(self, coord: str) -> tuple[int, int] | None:
        match = re.match(r"\$?([A-Za-z]+)\$?(\d+)", coord.strip())
        if not match:
            return None

        column = match.group(1)
        row = int(match.group(2))
        return self._column_index_from_string(column), row

    def _collect_range_values(
        self,
        workbook_data: dict[str, dict[str, object]],
        sheet_name: str,
        coords: tuple[tuple[int, int], tuple[int, int]],
    ) -> list[object | None] | None:
        sheet_data = workbook_data.get(sheet_name)
        if sheet_data is None:
            return None

        (start_col, start_row), (end_col, end_row) = coords
        if end_col < start_col:
            start_col, end_col = end_col, start_col
        if end_row < start_row:
            start_row, end_row = end_row, start_row

        values: list[object | None] = []

        for row in range(start_row, end_row + 1):
            for col in range(start_col, end_col + 1):
                coordinate = f"{self._column_string_from_index(col)}{row}"
                values.append(sheet_data.get(coordinate))

        return values

    def _column_index_from_string(self, column: str) -> int:
        index = 0
        for char in column.upper():
            if not char.isalpha():
                return 0
            index = index * 26 + (ord(char) - ord("A") + 1)
        return index

    def _column_string_from_index(self, index: int) -> str:
        if index <= 0:
            return "A"

        chars: list[str] = []
        while index:
            index, remainder = divmod(index - 1, 26)
            chars.append(chr(ord("A") + remainder))
        return "".join(reversed(chars))

    def _format_numeric_value(self, value: int | float) -> str:
        if isinstance(value, int) or (isinstance(value, float) and value.is_integer()):
            return str(int(value))
        return repr(float(value))

    def _parse_workbook_sheets(self, rendered_files: dict[str, bytes]) -> dict[str, str]:
        workbook_bytes = rendered_files.get("xl/workbook.xml")
        if workbook_bytes is None:
            return {}

        try:
            root = ET.fromstring(workbook_bytes.decode("utf-8"))
        except ET.ParseError:
            return {}

        namespace = {
            "x": _EXCEL_MAIN_NS,
            "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        }

        sheets: list[tuple[str, str]] = []
        for sheet in root.findall(".//x:sheet", namespace):
            name = sheet.get("name")
            rel_id = sheet.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
            if name and rel_id:
                sheets.append((rel_id, name))

        if not sheets:
            return {}

        rels_bytes = rendered_files.get("xl/_rels/workbook.xml.rels")
        targets: dict[str, str] = {}
        if rels_bytes is not None:
            try:
                rel_root = ET.fromstring(rels_bytes.decode("utf-8"))
            except ET.ParseError:
                rel_root = None
            if rel_root is not None:
                rel_ns = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
                for rel in rel_root.findall("rel:Relationship", rel_ns):
                    rel_id = rel.get("Id")
                    target = rel.get("Target")
                    if rel_id and target:
                        targets[rel_id] = target

        sheet_map: dict[str, str] = {}
        for rel_id, name in sheets:
            target = targets.get(rel_id)
            if not target:
                continue
            normalized = self._normalize_excel_path(target)
            sheet_map[normalized] = name

        return sheet_map

    def _normalize_excel_path(self, target: str) -> str:
        cleaned = target.replace("\\", "/")
        if cleaned.startswith("/"):
            cleaned = cleaned.lstrip("/")
        if cleaned.startswith("xl/"):
            return posixpath.normpath(cleaned)
        if cleaned.startswith("../"):
            combined = posixpath.normpath(posixpath.join("xl", cleaned))
        else:
            combined = posixpath.normpath(posixpath.join("xl", cleaned))
        if not combined.startswith("xl/"):
            combined = f"xl/{combined.lstrip('/')}"
        return combined

    def _extract_excel_cell_text(
        self,
        cell,
        cell_type: str | None,
        namespace: dict[str, str],
        shared_strings: dict[int, str] | None,
    ) -> str | None:
        if cell_type == "inlineStr":
            text_element = cell.find(".//x:t", namespace)
            if text_element is not None and text_element.text is not None:
                return text_element.text
            return None

        value_element = cell.find("x:v", namespace)
        if value_element is not None and value_element.text is not None:
            if cell_type == "s" and shared_strings is not None:
                try:
                    index = int(value_element.text)
                except (TypeError, ValueError):
                    return value_element.text
                return shared_strings.get(index)
            return value_element.text
        return None

    def _interpret_excel_bool(self, value: str | None) -> bool | None:
        if value is None:
            return None
        return value in {"1", "true", "TRUE"}

    def _parse_excel_shared_strings(self, xml: str) -> dict[int, str]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return {}

        namespace = {"x": _EXCEL_MAIN_NS}
        parsed: dict[int, str] = {}

        for index, entry in enumerate(root.findall(".//x:si", namespace)):
            text = "".join(entry.itertext())
            parsed[index] = text

        return parsed

    def _clone_zipinfo(self, info: ZipInfo) -> ZipInfo:
        clone = ZipInfo(info.filename, date_time=info.date_time)
        clone.compress_type = info.compress_type
        clone.comment = info.comment
        clone.extra = info.extra
        clone.create_system = info.create_system
        clone.create_version = info.create_version
        clone.extract_version = info.extract_version
        clone.flag_bits = info.flag_bits
        clone.internal_attr = info.internal_attr
        clone.external_attr = info.external_attr
        clone.volume = getattr(info, "volume", 0)
        return clone

    @staticmethod
    def _cast_numeric_value(numeric_text: str):
        if "." in numeric_text:
            try:
                return float(numeric_text)
            except ValueError:
                return None
        try:
            return int(numeric_text)
        except ValueError:
            return None

    @staticmethod
    def _normalize_numeric_string(value: str | None) -> str | None:
        if value is None:
            return None

        stripped = value.strip()
        if not stripped:
            return None

        if not re.fullmatch(r"-?\d+(\.\d+)?", stripped):
            return None

        signless = stripped.lstrip("-")
        if "." not in signless and len(signless) > 1 and signless.startswith("0"):
            return None

        return stripped

