"""Extended DocxTemplate with support for additional templated parts."""

from __future__ import annotations

import fnmatch
import io
import re
import zipfile
from typing import Iterator

from docx.oxml import parse_xml
from docxtpl.template import DocxTemplate
from jinja2 import Environment, meta
from lxml import etree


_JINJA_STATEMENT_RE = re.compile(r"({[{%#].*?[}%]})", re.DOTALL)
_INLINE_STRING_TYPES = {"inlineStr"}


class GhostwriterDocxTemplate(DocxTemplate):
    """Docx template that also renders SmartArt diagram parts.

    Microsoft Word stores SmartArt data in the ``word/diagrams`` folder of the
    DOCX package. The python-docx-template library does not process those XML
    parts when rendering a document or when collecting undeclared variables for
    linting.  This subclass extends the renderer so those parts participate in
    templating just like the document body.
    """

    _EXTRA_TEMPLATED_PATTERNS: tuple[str, ...] = (
        "word/diagrams/data*.xml",
        "word/diagrams/drawing*.xml",
        "word/embeddings/Microsoft_Excel_Worksheet*.xlsx",
        "word/charts/chart*.xml",
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

        self._render_additional_parts(context, jinja_env)

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
            partname = self._normalise_partname(part)
            if self._is_excel_part(partname):
                xml_sources.extend(
                    self.patch_xml(xml) for xml in self._iter_excel_xml(part)
                )
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
            partname = self._normalise_partname(part)
            if partname in seen:
                continue
            if self._matches_extra_template(partname):
                seen.add(partname)
                yield part

    def _matches_extra_template(self, partname: str) -> bool:
        return any(fnmatch.fnmatch(partname, pattern) for pattern in self._EXTRA_TEMPLATED_PATTERNS)

    def _normalise_partname(self, part) -> str:
        return str(part.partname).lstrip("/")

    def _is_excel_part(self, partname: str) -> bool:
        return partname.endswith(".xlsx")

    def _render_additional_parts(self, context, jinja_env) -> None:
        parts = list(self._iter_additional_parts())
        excel_values: dict[str, dict[str, dict[str, str]]] = {}

        for part in parts:
            partname = self._normalise_partname(part)
            if not self._is_excel_part(partname):
                continue

            rendered = self._render_excel_part(part, context, jinja_env)
            if rendered is None:
                continue

            rendered_blob, workbook_values = rendered
            if rendered_blob is not None and hasattr(part, "_blob"):
                part._blob = rendered_blob
            if workbook_values:
                excel_values[partname] = workbook_values

        for part in parts:
            partname = self._normalise_partname(part)
            if self._is_excel_part(partname):
                continue

            xml = self.get_part_xml(part)
            patched = self.patch_xml(xml)
            rendered = self.render_xml_part(patched, part, context, jinja_env)
            if self._is_chart_part(partname):
                rendered = self._sync_chart_cache(rendered, part, excel_values)

            rendered_bytes = rendered.encode("utf-8")
            if hasattr(part, "_element"):
                part._element = parse_xml(rendered_bytes)
            if hasattr(part, "_blob"):
                part._blob = rendered_bytes

    def _iter_excel_xml(self, part) -> Iterator[str]:
        blob = getattr(part, "_blob", None)
        if blob is None and hasattr(part, "blob"):
            blob = part.blob
        if not blob:
            return

        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for name in archive.namelist():
                if name.endswith(".xml"):
                    yield archive.read(name).decode("utf-8")

    def _render_excel_part(self, part, context, jinja_env):
        blob = getattr(part, "_blob", None)
        if blob is None and hasattr(part, "blob"):
            blob = part.blob
        if not blob:
            return None

        source = io.BytesIO(blob)
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            files: dict[str, bytes] = {info.filename: archive.read(info.filename) for info in infos}

        rendered_xml: dict[str, str] = {}
        for name, data in files.items():
            if not name.endswith(".xml"):
                continue
            xml = data.decode("utf-8")
            patched = self.patch_xml(xml)
            rendered_xml[name] = self.render_xml_part(patched, part, context, jinja_env)

        sheet_map = self._build_sheet_map(rendered_xml, files)
        rendered_xml, workbook_values = self._coerce_excel_types(rendered_xml, sheet_map)

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for info in infos:
                filename = info.filename
                data = rendered_xml.get(filename)
                if data is not None:
                    content: bytes = data.encode("utf-8")
                else:
                    content = files[filename]

                new_info = zipfile.ZipInfo(filename)
                new_info.date_time = info.date_time
                new_info.external_attr = info.external_attr
                new_info.internal_attr = info.internal_attr
                new_info.compress_type = info.compress_type
                new_info.flag_bits = info.flag_bits
                archive.writestr(new_info, content)

        return output.getvalue(), workbook_values

    def _is_chart_part(self, partname: str) -> bool:
        return partname.startswith("word/charts/") and partname.endswith(".xml")

    def _build_sheet_map(
        self,
        rendered_xml: dict[str, str],
        files: dict[str, bytes],
    ) -> dict[str, str]:
        workbook_xml = rendered_xml.get("xl/workbook.xml")
        if workbook_xml is None and "xl/workbook.xml" in files:
            workbook_xml = files["xl/workbook.xml"].decode("utf-8")

        rels_xml = rendered_xml.get("xl/_rels/workbook.xml.rels")
        if rels_xml is None and "xl/_rels/workbook.xml.rels" in files:
            rels_xml = files["xl/_rels/workbook.xml.rels"].decode("utf-8")

        if not workbook_xml or not rels_xml:
            return {}

        return self._parse_sheet_map(workbook_xml, rels_xml)

    def _parse_sheet_map(self, workbook_xml: str, rels_xml: str) -> dict[str, str]:
        try:
            workbook_tree = etree.fromstring(workbook_xml.encode("utf-8"))
            rels_tree = etree.fromstring(rels_xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return {}

        ns = workbook_tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        rels_ns = rels_tree.nsmap.get(None)
        rels_prefix = f"{{{rels_ns}}}" if rels_ns else ""
        r_ns = workbook_tree.nsmap.get("r")
        default_r_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        r_prefix = f"{{{r_ns}}}" if r_ns else f"{{{default_r_ns}}}"

        rel_targets: dict[str, str] = {}
        for rel in rels_tree.findall(f"{rels_prefix}Relationship"):
            rel_id = rel.get("Id")
            target = rel.get("Target")
            if not rel_id or not target:
                continue
            rel_targets[rel_id] = target

        sheet_map: dict[str, str] = {}
        for sheet in workbook_tree.findall(f".//{prefix}sheet"):
            name = sheet.get("name")
            rel_id = sheet.get(f"{r_prefix}id")
            if not name or not rel_id:
                continue
            target = rel_targets.get(rel_id)
            if not target:
                continue
            target_path = target.lstrip("/")
            if not target_path.startswith("xl/"):
                target_path = f"xl/{target_path}"
            sheet_map[target_path] = name

        return sheet_map

    # Excel helpers -------------------------------------------------

    def _coerce_excel_types(
        self,
        xml_files: dict[str, str],
        sheet_map: dict[str, str],
    ) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        if not xml_files:
            return xml_files, {}

        shared_strings = None
        shared_strings_key = "xl/sharedStrings.xml"
        if shared_strings_key in xml_files:
            shared_strings = self._parse_shared_strings(xml_files[shared_strings_key])

        workbook_values: dict[str, dict[str, str]] = {}
        for name, xml in list(xml_files.items()):
            if not name.startswith("xl/worksheets/"):
                continue
            sheet_name = sheet_map.get(name)
            coerced, cell_values = self._coerce_sheet_types(
                xml,
                shared_strings,
            )
            xml_files[name] = coerced
            if cell_values:
                if sheet_name:
                    workbook_values[sheet_name] = cell_values
                workbook_values.setdefault(name, cell_values)

        if shared_strings is not None and shared_strings_key in xml_files:
            xml_files[shared_strings_key] = self._serialise_shared_strings(shared_strings)

        return xml_files, workbook_values

    def _parse_shared_strings(self, xml: str) -> tuple[list[str], etree._Element]:
        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return [], etree.Element("sharedStrings")

        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        values: list[str] = []
        for si in tree.findall(f"{prefix}si"):
            text = "".join(t.text or "" for t in si.findall(f".//{prefix}t"))
            values.append(text)
        return values, tree

    def _serialise_shared_strings(self, parsed: tuple[list[str], etree._Element]) -> str:
        values, tree = parsed
        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        for idx, si in enumerate(tree.findall(f"{prefix}si")):
            text = values[idx] if idx < len(values) else ""
            t_elements = si.findall(f".//{prefix}t")
            if not t_elements:
                etree.SubElement(si, f"{prefix}t").text = text
                continue

            t_elements[0].text = text
            for extra in t_elements[1:]:
                parent = extra.getparent()
                if parent is not None:
                    parent.remove(extra)
        return etree.tostring(tree, encoding="unicode")

    def _coerce_sheet_types(
        self,
        xml: str,
        shared_strings: tuple[list[str], etree._Element] | None,
    ) -> tuple[str, dict[str, str]]:
        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return xml, {}

        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""

        shared_values = shared_strings[0] if shared_strings else []
        cell_values: dict[str, str] = {}
        for cell in tree.findall(f".//{prefix}c"):
            cell_type = cell.get("t")
            cell_ref = cell.get("r")
            value_text: str | None = None
            if cell_type == "s":
                value_node = cell.find(f"{prefix}v")
                if value_node is None or value_node.text is None:
                    if cell_ref and cell_ref not in cell_values:
                        cell_values[cell_ref] = ""
                    continue
                try:
                    index = int(value_node.text)
                except (TypeError, ValueError):
                    if cell_ref and cell_ref not in cell_values:
                        cell_values[cell_ref] = value_node.text or ""
                    continue
                if 0 <= index < len(shared_values):
                    original_value = shared_values[index]
                    coerced = self._maybe_numeric(original_value)
                    if coerced is not None:
                        cell.attrib.pop("t", None)
                        value_node.text = coerced
                        shared_values[index] = coerced
                        value_text = coerced
                    else:
                        value_text = original_value
                if cell_ref and value_text is not None:
                    cell_values[cell_ref] = value_text
                elif cell_ref and cell_ref not in cell_values:
                    cell_values[cell_ref] = ""
                continue

            if cell_type in _INLINE_STRING_TYPES:
                inline = cell.find(f"{prefix}is")
                if inline is None:
                    if cell_ref and cell_ref not in cell_values:
                        cell_values[cell_ref] = ""
                    continue
                text_nodes = inline.findall(f".//{prefix}t")
                text = "".join(node.text or "" for node in text_nodes)
                coerced = self._maybe_numeric(text)
                if coerced is None:
                    value_text = text
                    if cell_ref:
                        cell_values[cell_ref] = value_text
                    continue
                cell.attrib.pop("t", None)
                for node in text_nodes:
                    parent = node.getparent()
                    if parent is not None:
                        parent.remove(node)
                inline_parent = inline.getparent()
                if inline_parent is not None:
                    inline_parent.remove(inline)
                value_node = etree.SubElement(cell, f"{prefix}v")
                value_node.text = coerced
                value_text = coerced
                if cell_ref:
                    cell_values[cell_ref] = value_text
                continue

            if cell_type == "str" or cell_type == "b":
                value_node = cell.find(f"{prefix}v")
                if value_node is None or value_node.text is None:
                    if cell_ref and cell_ref not in cell_values:
                        cell_values[cell_ref] = ""
                    continue
                coerced = self._maybe_numeric(value_node.text)
                if coerced is not None:
                    cell.attrib.pop("t", None)
                    value_node.text = coerced
                    value_text = coerced
                else:
                    value_text = value_node.text
                if cell_ref:
                    cell_values[cell_ref] = value_text
                continue

            value_node = cell.find(f"{prefix}v")
            if value_node is not None and value_node.text is not None:
                value_text = value_node.text
            if cell_ref and value_text is not None:
                cell_values[cell_ref] = value_text

        return etree.tostring(tree, encoding="unicode"), cell_values

    def _maybe_numeric(self, value: str) -> str | None:
        stripped = value.strip()
        if not stripped:
            return None
        if re.fullmatch(r"-?\d+", stripped):
            return str(int(stripped))
        if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)(?:[eE][+-]?\d+)?", stripped):
            number = float(stripped)
            if number.is_integer():
                return str(int(number))
            return (
                ("%f" % number).rstrip("0").rstrip(".")
                if "e" not in stripped.lower()
                else stripped
            )
        return None

    # Chart helpers -------------------------------------------------

    def _sync_chart_cache(
        self,
        xml: str,
        part,
        excel_values: dict[str, dict[str, dict[str, str]]],
    ) -> str:
        workbook_data = self._resolve_chart_workbook(part, excel_values)
        if not workbook_data:
            return xml

        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return xml

        ns = tree.nsmap.get("c") or tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        updated = False

        for num_ref in tree.findall(f".//{prefix}numRef"):
            formula = self._find_chart_formula(num_ref, prefix)
            if not formula:
                continue
            values = self._extract_range_values(formula, workbook_data)
            if values is None:
                continue
            cache = num_ref.find(f"{prefix}numCache")
            if cache is None:
                cache = etree.SubElement(num_ref, f"{prefix}numCache")
            self._write_cache(cache, values, prefix)
            updated = True

        for str_ref in tree.findall(f".//{prefix}strRef"):
            formula = self._find_chart_formula(str_ref, prefix)
            if not formula:
                continue
            values = self._extract_range_values(formula, workbook_data)
            if values is None:
                continue
            cache = str_ref.find(f"{prefix}strCache")
            if cache is None:
                cache = etree.SubElement(str_ref, f"{prefix}strCache")
            self._write_cache(cache, values, prefix)
            updated = True

        if not updated:
            return xml

        return etree.tostring(tree, encoding="unicode")

    def _resolve_chart_workbook(
        self,
        part,
        excel_values: dict[str, dict[str, dict[str, str]]],
    ) -> dict[str, dict[str, str]] | None:
        rels = getattr(part, "rels", None)
        if not rels:
            return None

        for rel in rels.values():
            reltype = getattr(rel, "reltype", "")
            if not reltype or "embeddedPackage" not in reltype:
                continue
            target = getattr(rel, "target_part", None)
            if target is None:
                continue
            partname = self._normalise_partname(target)
            workbook_data = excel_values.get(partname)
            if workbook_data:
                return workbook_data
        return None

    def _find_chart_formula(self, ref_node, prefix: str) -> str | None:
        formula_node = ref_node.find(f"{prefix}f")
        if formula_node is None or formula_node.text is None:
            return None
        return formula_node.text.strip()

    def _extract_range_values(
        self,
        formula: str,
        workbook_data: dict[str, dict[str, str]],
    ) -> list[str] | None:
        if not formula:
            return None

        if "(" in formula and ")" in formula:
            inner = formula[formula.find("(") + 1 : formula.rfind(")")]
            parts = self._split_formula_arguments(inner)
            values: list[str] = []
            for part in parts:
                extracted = self._extract_range_values(part, workbook_data)
                if extracted:
                    values.extend(extracted)
            return values or None

        if "!" not in formula:
            return None

        sheet_part, cell_part = formula.rsplit("!", 1)
        sheet_name = self._normalise_sheet_name(sheet_part)
        if not sheet_name:
            return None

        sheet_values = workbook_data.get(sheet_name)
        if sheet_values is None:
            return None

        cells = self._expand_cell_range(cell_part)
        if not cells:
            return None

        values = [sheet_values.get(cell, "") for cell in cells]
        return values

    def _split_formula_arguments(self, formula: str) -> list[str]:
        depth = 0
        current: list[str] = []
        parts: list[str] = []
        for char in formula:
            if char == "," and depth == 0:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                continue
            if char == "(":
                depth += 1
            elif char == ")" and depth > 0:
                depth -= 1
            current.append(char)
        tail = "".join(current).strip()
        if tail:
            parts.append(tail)
        return parts

    def _normalise_sheet_name(self, sheet_part: str) -> str | None:
        stripped = sheet_part.strip()
        if stripped.startswith("="):
            stripped = stripped[1:]
        if stripped.startswith("'") and stripped.endswith("'"):
            stripped = stripped[1:-1]
        if stripped.startswith("[") and "]" in stripped:
            stripped = stripped.split("]", 1)[1]
        if stripped.startswith("'") and stripped.endswith("'"):
            stripped = stripped[1:-1]
        return stripped or None

    def _expand_cell_range(self, cell_part: str) -> list[str]:
        reference = cell_part.strip()
        if reference.startswith("="):
            reference = reference[1:]
        if not reference:
            return []

        ranges = [r.strip() for r in reference.split(",") if r.strip()]
        cells: list[str] = []
        for cell_range in ranges:
            start_end = cell_range.split(":")
            if len(start_end) == 1:
                coord = self._normalise_cell_reference(start_end[0])
                if coord:
                    cells.append(coord)
                continue
            if len(start_end) != 2:
                continue
            start = self._split_cell(start_end[0])
            end = self._split_cell(start_end[1])
            if start is None or end is None:
                continue
            start_col, start_row = start
            end_col, end_row = end
            for col in range(start_col, end_col + 1):
                for row in range(start_row, end_row + 1):
                    cells.append(f"{self._column_letters(col)}{row}")
        return cells

    def _normalise_cell_reference(self, cell: str) -> str | None:
        parsed = self._split_cell(cell)
        if parsed is None:
            return None
        col, row = parsed
        return f"{self._column_letters(col)}{row}"

    def _split_cell(self, cell: str) -> tuple[int, int] | None:
        cleaned = cell.strip().replace("$", "")
        match = re.fullmatch(r"([A-Za-z]+)(\d+)", cleaned)
        if not match:
            return None
        col_letters, row_str = match.groups()
        col_index = 0
        for char in col_letters.upper():
            col_index = col_index * 26 + (ord(char) - ord("A") + 1)
        return col_index, int(row_str)

    def _column_letters(self, index: int) -> str:
        letters: list[str] = []
        while index > 0:
            index, remainder = divmod(index - 1, 26)
            letters.append(chr(ord("A") + remainder))
        return "".join(reversed(letters))

    def _write_cache(self, cache, values: list[str], prefix: str) -> None:
        pt_count = cache.find(f"{prefix}ptCount")
        if pt_count is None:
            pt_count = etree.SubElement(cache, f"{prefix}ptCount")
        pt_count.set("val", str(len(values)))

        for pt in list(cache.findall(f"{prefix}pt")):
            cache.remove(pt)

        for idx, value in enumerate(values):
            pt = etree.SubElement(cache, f"{prefix}pt", idx=str(idx))
            v = etree.SubElement(pt, f"{prefix}v")
            v.text = "" if value is None else str(value)

