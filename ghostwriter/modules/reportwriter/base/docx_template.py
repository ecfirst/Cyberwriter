"""Extended DocxTemplate with support for additional templated parts."""

from __future__ import annotations

import fnmatch
import io
import re
import zipfile
import posixpath
from copy import deepcopy
from typing import Iterator

from docx.oxml import parse_xml
from docxtpl.template import DocxTemplate
from jinja2 import Environment, meta
from lxml import etree


_JINJA_STATEMENT_RE = re.compile(r"({[{%#].*?[}%]})", re.DOTALL)
_INLINE_STRING_TYPES = {"inlineStr"}
_XML_TAG_GAP = r"(?:\s|</?(?:[A-Za-z_][\w.-]*:)?[A-Za-z_][\w.-]*[^>]*>)*"
_RELATIONSHIP_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


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

        active_parts = self._cleanup_unused_additional_relationships()
        self._render_additional_parts(context, jinja_env, active_parts)

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
                infos_files = self._read_excel_part(part)
                if infos_files is None:
                    continue
                _infos, files = infos_files
                files = self._inline_templated_shared_strings(files)
                for name, data in files.items():
                    if not name.endswith(".xml"):
                        continue
                    xml_sources.append(self.patch_xml(data.decode("utf-8")))
            else:
                xml_sources.append(self.patch_xml(self.get_part_xml(part)))

        env = jinja_env or getattr(self, "jinja_env", None) or Environment()
        parse_content = env.parse("".join(xml_sources))
        return meta.find_undeclared_variables(parse_content)

    def patch_xml(self, src_xml):  # type: ignore[override]
        """Normalize XML for templating across Word body and SmartArt parts."""

        patched = super().patch_xml(src_xml)
        patched = self._strip_excel_table_tags(patched)

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

    def _strip_excel_table_tags(self, xml: str) -> str:
        """Remove Excel row/cell wrappers around Ghostwriter ``tr``/``tc`` tags."""

        has_spreadsheet_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main" in xml

        if has_spreadsheet_ns:

            def _strip_container(value: str, container: str, tag: str) -> str:
                open_regex = "<(?:[A-Za-z_][\\w.-]*:)?%s[^>]*>\\s*%s\\s*%s"
                close_regex = "%s.*?%s\\s*</(?:[A-Za-z_][\\w.-]*:)?%s>"
                for start, end, start_regex in (
                    ("{{", "}}", "\\{\\{"),
                    ("{%", "%}", "\\{%"),
                    ("{#", "#}", "\\{#"),
                ):
                    open_pattern = re.compile(
                        open_regex % (container, start_regex, tag),
                        re.DOTALL,
                    )
                    value = open_pattern.sub(start, value)
                    close_pattern = re.compile(
                        close_regex % (start_regex, end, container),
                        re.DOTALL,
                    )

                    def close_replacement(match: re.Match[str]) -> str:
                        matched = match.group(0)
                        end_index = matched.rfind(end)
                        return matched[: end_index + len(end)] if end_index != -1 else matched

                    value = close_pattern.sub(close_replacement, value)

                return re.sub(r"(\{\{|\{%|\{#)\s+", lambda m: m.group(1) + " ", value)

            xml = _strip_container(xml, "row", "tr")
            xml = _strip_container(xml, "c", "tc")

        def _replace_open_tr(match: re.Match[str]) -> str:
            trim = match.group("trim") or ""
            return "{%" + trim + " for"

        def _replace_close_tr(match: re.Match[str]) -> str:
            trim = match.group("trim") or ""
            return "{%" + trim + " endfor"

        open_tr_pattern = re.compile(
            r"\{%(?P<trim>-?)" + _XML_TAG_GAP + r"tr" + _XML_TAG_GAP + r"for\b",
        )
        close_tr_pattern = re.compile(
            r"\{%(?P<trim>-?)"
            + _XML_TAG_GAP
            + r"(?:endtr|tr"
            + _XML_TAG_GAP
            + r"endfor)\b",
        )
        xml = open_tr_pattern.sub(_replace_open_tr, xml)
        xml = close_tr_pattern.sub(_replace_close_tr, xml)

        if has_spreadsheet_ns:
            row_wrapper_pattern = re.compile(
                r"<row[^>]*>"
                r"(?:\s|<[^>]+>)*"
                r"(?P<stmt>\{%-?\s*(?:for\b[^%]*|endfor)\s*-?%})"
                r"(?:\s|</[^>]+>)*"
                r"</row>",
                re.DOTALL,
            )

            def _unwrap_row(match: re.Match[str]) -> str:
                return match.group("stmt")

            xml = row_wrapper_pattern.sub(_unwrap_row, xml)

        tc_pattern = re.compile(
            r"(\{[\{%#]-?)(" + _XML_TAG_GAP + r")tc\b",
        )

        def _strip_tc(match: re.Match[str]) -> str:
            gap = match.group(2)
            next_char = match.string[match.end() : match.end() + 1]
            if gap and gap[-1].isspace() and next_char and next_char.isspace():
                gap = gap[:-1]
            return match.group(1) + gap

        xml = tc_pattern.sub(_strip_tc, xml)
        return xml

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

    def _render_additional_parts(
        self,
        context,
        jinja_env,
        active_partnames: set[str] | None = None,
    ) -> None:
        parts = list(self._iter_additional_parts())

        if active_partnames is not None:
            parts = [
                part
                for part in parts
                if self._normalise_partname(part) in active_partnames
            ]
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

    def _cleanup_unused_additional_relationships(self) -> set[str] | None:
        if not self.docx:
            return None

        referencing_parts: list = [self.docx.part]

        for uri in (self.HEADER_URI, self.FOOTER_URI):
            for _rel_key, part in self.get_headers_footers(uri):
                referencing_parts.append(part)

        active_partnames: set[str] = set()

        for part in referencing_parts:
            element = self._get_part_element(part)
            if element is None:
                continue

            used_rel_ids = self._collect_used_relationship_ids(element)

            rels = getattr(part, "rels", None)
            if not rels:
                continue

            removed = False

            for rel_id, rel in list(rels.items()):
                if getattr(rel, "is_external", False):
                    continue

                try:
                    target_part = rel.target_part
                except (AttributeError, KeyError, ValueError):
                    target_part = None

                if target_part is None:
                    continue

                target_name = self._normalise_partname(target_part)
                if not self._matches_extra_template(target_name):
                    continue

                if rel_id in used_rel_ids:
                    active_partnames.add(target_name)
                    continue

                if self._remove_relationship_nodes(element, rel_id):
                    removed = True

                drop_rel = getattr(part, "drop_rel", None)
                if callable(drop_rel):
                    drop_rel(rel_id)
                else:
                    backing = getattr(rels, "_rels", None)
                    if isinstance(backing, dict):
                        backing.pop(rel_id, None)

            if removed:
                self._update_part_xml(part, element)

        # Ensure only additional parts that remain referenced are templated.
        return active_partnames

    def _get_part_element(self, part):
        element = getattr(part, "_element", None)
        if element is not None:
            return element

        blob = getattr(part, "_blob", None)
        if blob is None and hasattr(part, "blob"):
            try:
                blob = part.blob  # type: ignore[attr-defined]
            except Exception:
                blob = None

        if not isinstance(blob, (bytes, bytearray)):
            xml = self.get_part_xml(part)
            if not xml:
                return None
            blob = xml.encode("utf-8")

        try:
            element = parse_xml(blob)
        except Exception:
            return None

        if hasattr(part, "_element"):
            part._element = element

        return element

    def _collect_used_relationship_ids(self, element) -> set[str]:
        prefix = f"{{{_RELATIONSHIP_NS}}}"
        used: set[str] = set()

        for node in element.iter():
            for attr, value in node.attrib.items():
                if not value:
                    continue
                if attr.startswith(prefix) or attr in {"r:id", "relId"}:
                    used.add(value)

        return used

    def _remove_relationship_nodes(self, element, rel_id: str) -> bool:
        if not rel_id:
            return False

        removed = False
        candidates = []

        prefix = f"{{{_RELATIONSHIP_NS}}}"
        tracked_attrs = {f"{prefix}embed", f"{prefix}link", f"{prefix}id", "relId"}

        for node in element.iter():
            if any(node.get(attr) == rel_id for attr in tracked_attrs):
                candidates.append(node)

        if not candidates:
            return False

        for node in candidates:
            removal = self._find_relationship_removal_node(node)
            if removal is None:
                continue
            parent = removal.getparent()
            if parent is None:
                continue
            parent.remove(removal)
            removed = True

        return removed

    def _find_relationship_removal_node(self, node):
        current = node
        removal = None

        while current is not None:
            qname = etree.QName(current)
            local = qname.localname
            if local in {"drawing", "object", "pict"}:
                removal = current
            if local == "r":
                return current
            current = current.getparent()

        return removal

    def _update_part_xml(self, part, element) -> None:
        if hasattr(part, "_element"):
            part._element = element

        xml_bytes = etree.tostring(element, encoding="utf-8")

        if hasattr(part, "_blob"):
            part._blob = xml_bytes

    def _read_excel_part(self, part) -> tuple[list[zipfile.ZipInfo], dict[str, bytes]] | None:
        blob = getattr(part, "_blob", None)
        if blob is None and hasattr(part, "blob"):
            blob = part.blob
        if not blob:
            return None

        source = io.BytesIO(blob)
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            files = {info.filename: archive.read(info.filename) for info in infos}
        return infos, files

    def _render_excel_part(self, part, context, jinja_env):
        infos_files = self._read_excel_part(part)
        if infos_files is None:
            return None
        infos, files = infos_files

        files = self._inline_templated_shared_strings(files)

        rendered_xml: dict[str, str] = {}
        for name, data in files.items():
            if not name.endswith(".xml"):
                continue
            xml = data.decode("utf-8")
            patched = self.patch_xml(xml)
            rendered_xml[name] = self.render_xml_part(patched, part, context, jinja_env)

        sheet_map = self._build_sheet_map(rendered_xml, files)
        rendered_xml, workbook_values = self._coerce_excel_types(rendered_xml, sheet_map)
        rendered_xml, table_map = self._sync_excel_tables(
            rendered_xml,
            files,
            sheet_map,
            workbook_values,
        )
        if table_map:
            workbook_values.setdefault("__tables__", table_map)

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

    def _inline_templated_shared_strings(self, files: dict[str, bytes]) -> dict[str, bytes]:
        """Embed templated shared strings directly in worksheet cells.

        Ghostwriter templates often place ``{{ ... }}`` and ``{% ... %}`` markers in
        shared string entries that are referenced from worksheet cells. When those
        entries participate in ``{%tr%}`` loops, the shared string is rendered
        outside of the loop context and raises ``UndefinedError`` exceptions. To
        avoid this, shared-string backed cells containing template statements are
        converted to inline strings and the shared string entries are cleared so
        the templating engine no longer sees the Ghostwriter markers.
        """

        shared_key = "xl/sharedStrings.xml"
        shared_blob = files.get(shared_key)
        if not shared_blob:
            return files

        try:
            shared_tree = etree.fromstring(shared_blob)
        except etree.XMLSyntaxError:
            return files

        shared_ns = shared_tree.nsmap.get(None)
        shared_prefix = f"{{{shared_ns}}}" if shared_ns else ""

        templated_entries: dict[int, etree._Element] = {}
        changed_shared = False
        for idx, si in enumerate(shared_tree.findall(f"{shared_prefix}si")):
            text = "".join(si.itertext())
            if not any(marker in text for marker in ("{{", "{%", "{#")):
                continue

            templated_entries[idx] = deepcopy(si)
            for child in list(si):
                si.remove(child)
            empty = etree.SubElement(si, f"{shared_prefix}t")
            empty.text = ""
            empty.attrib.pop("{http://www.w3.org/XML/1998/namespace}space", None)
            changed_shared = True

        if not templated_entries:
            return files

        if changed_shared:
            files[shared_key] = etree.tostring(shared_tree, encoding="utf-8")

        for name, blob in list(files.items()):
            if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
                continue

            try:
                sheet_tree = etree.fromstring(blob)
            except etree.XMLSyntaxError:
                continue

            sheet_ns = sheet_tree.nsmap.get(None)
            sheet_prefix = f"{{{sheet_ns}}}" if sheet_ns else ""
            updated = False

            for cell in sheet_tree.findall(f".//{sheet_prefix}c[@t='s']"):
                value_node = cell.find(f"{sheet_prefix}v")
                if value_node is None or value_node.text is None:
                    continue

                try:
                    shared_index = int(value_node.text)
                except ValueError:
                    continue

                shared_value = templated_entries.get(shared_index)
                if shared_value is None:
                    continue

                for child in list(cell):
                    if etree.QName(child).localname in {"v", "is"}:
                        cell.remove(child)

                cell.set("t", "inlineStr")
                inline = etree.SubElement(cell, f"{sheet_prefix}is")
                for child in shared_value:
                    inline.append(deepcopy(child))
                updated = True

            if updated:
                files[name] = etree.tostring(sheet_tree, encoding="utf-8")

        return files

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
            normalised = self._normalise_sheet_rows(xml)
            if normalised != xml:
                xml_files[name] = normalised
                xml = normalised

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

    def _sync_excel_tables(
        self,
        xml_files: dict[str, str],
        files: dict[str, bytes],
        sheet_map: dict[str, str],
        workbook_values: dict[str, dict[str, str]],
    ) -> tuple[dict[str, str], dict[str, dict[str, object]]]:
        if not sheet_map:
            return xml_files, {}

        tables: dict[str, dict[str, object]] = {}
        lower_lookup: dict[str, str] = {}

        for sheet_path, sheet_name in sheet_map.items():
            sheet_xml = xml_files.get(sheet_path)
            if sheet_xml is None and sheet_path in files:
                sheet_xml = files[sheet_path].decode("utf-8")
            if not sheet_xml:
                continue

            table_data = self._extract_sheet_tables(
                sheet_path,
                sheet_name,
                sheet_xml,
                xml_files,
                files,
                workbook_values,
            )
            if not table_data:
                continue

            for table_name, info in table_data.items():
                tables[table_name] = info
                lower_lookup[table_name.lower()] = table_name

        if tables:
            tables["__lower__"] = lower_lookup

        return xml_files, tables

    def _extract_sheet_tables(
        self,
        sheet_path: str,
        sheet_name: str,
        sheet_xml: str,
        xml_files: dict[str, str],
        files: dict[str, bytes],
        workbook_values: dict[str, dict[str, str]],
    ) -> dict[str, dict[str, object]]:
        try:
            sheet_tree = etree.fromstring(sheet_xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return {}

        ns = sheet_tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        r_ns = sheet_tree.nsmap.get("r")
        default_r_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        r_prefix = f"{{{r_ns}}}" if r_ns else f"{{{default_r_ns}}}"

        rels_path = sheet_path.replace("worksheets/", "worksheets/_rels/") + ".rels"
        rels_xml = xml_files.get(rels_path)
        if rels_xml is None and rels_path in files:
            rels_xml = files[rels_path].decode("utf-8")
        rel_targets = self._parse_relationship_targets(rels_xml)

        row_columns = self._map_sheet_columns(sheet_tree)

        tables: dict[str, dict[str, object]] = {}
        for table_part in sheet_tree.findall(f".//{prefix}tablePart"):
            rel_id = table_part.get(f"{r_prefix}id")
            if not rel_id:
                continue
            target = rel_targets.get(rel_id)
            if not target:
                continue
            table_path = self._normalise_excel_path(target, sheet_path)
            table_xml = xml_files.get(table_path)
            if table_xml is None and table_path in files:
                table_xml = files[table_path].decode("utf-8")
            if not table_xml:
                continue

            updated_xml, table_info = self._update_table_definition(
                table_xml,
                sheet_name,
                row_columns,
                workbook_values,
                sheet_path,
            )
            if updated_xml is not None:
                xml_files[table_path] = updated_xml
            if table_info is not None:
                tables[table_info["name"]] = table_info

        return tables

    def _normalise_excel_path(self, target: str, base_path: str) -> str:
        cleaned = target.strip()
        if not cleaned:
            return base_path
        if cleaned.startswith("/"):
            cleaned = cleaned[1:]
            return cleaned if cleaned.startswith("xl/") else f"xl/{cleaned}"

        base_dir = posixpath.dirname(base_path)
        combined = posixpath.normpath(posixpath.join(base_dir, cleaned))
        if not combined.startswith("xl/"):
            combined = posixpath.normpath(posixpath.join("xl", cleaned))
        if not combined.startswith("xl/"):
            combined = f"xl/{combined.lstrip('/')}"
        return combined

    def _parse_relationship_targets(self, xml: str | None) -> dict[str, str]:
        if not xml:
            return {}
        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return {}

        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""
        targets: dict[str, str] = {}
        for rel in tree.findall(f"{prefix}Relationship"):
            rel_id = rel.get("Id")
            target = rel.get("Target")
            if not rel_id or not target:
                continue
            targets[rel_id] = target
        return targets

    def _normalise_sheet_rows(self, xml: str) -> str:
        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return xml

        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""

        sheet_data = tree.find(f"{prefix}sheetData")
        if sheet_data is None:
            return xml

        rows = list(sheet_data.findall(f"{prefix}row"))
        if not rows:
            return xml

        filtered_rows: list[etree._Element] = []
        for row in rows:
            cells = row.findall(f"{prefix}c")
            if not cells:
                sheet_data.remove(row)
                continue
            if not any(self._cell_has_value(cell, prefix) for cell in cells):
                sheet_data.remove(row)
                continue
            filtered_rows.append(row)

        if not filtered_rows:
            return etree.tostring(tree, encoding="unicode")

        rows = filtered_rows

        # Determine the smallest referenced row index so we can normalise
        # templated worksheets that introduced leading control rows (for
        # example ``{%tr%}`` markers placed before the first data row).  Word
        # expects contiguous row numbers starting at 1 for the chart ranges to
        # remain valid. When Ghostwriter removes the control rows, the
        # remaining worksheet content can start at ``r="2"`` which leaves the
        # original chart formulas pointing at empty cells.  By tracking the
        # minimum row value used anywhere in the sheet we can shift everything
        # back into place after rendering.
        min_defined_row: int | None = None
        for row in rows:
            attr = row.get("r")
            if attr:
                try:
                    row_index = int(attr)
                except ValueError:
                    row_index = None
                if row_index is not None and (
                    min_defined_row is None or row_index < min_defined_row
                ):
                    min_defined_row = row_index
            for cell in row.findall(f"{prefix}c"):
                ref = cell.get("r")
                if not ref:
                    continue
                parsed = self._split_cell(ref)
                if parsed is None:
                    continue
                _col, row_index = parsed
                if min_defined_row is None or row_index < min_defined_row:
                    min_defined_row = row_index

        row_offset = max((min_defined_row or 1) - 1, 0)
        last_index = 0
        min_col: int | None = None
        max_col: int | None = None
        min_row: int | None = None
        max_row: int | None = None

        for row in rows:
            attr = row.get("r")
            try:
                candidate = int(attr) if attr else None
            except ValueError:
                candidate = None

            if candidate is not None:
                candidate = max(1, candidate - row_offset)

            target_index = last_index + 1
            if candidate is None or candidate <= last_index:
                row_index = target_index
            else:
                row_index = min(candidate, target_index)

            cells = []
            parsed_rows: list[int] = []
            removed_cells = False
            for cell in row.findall(f"{prefix}c"):
                if not self._cell_has_value(cell, prefix):
                    row.remove(cell)
                    removed_cells = True
                    continue
                ref = cell.get("r")
                parsed = self._split_cell(ref) if ref else None
                if parsed is not None:
                    col_index, parsed_row = parsed
                    parsed_row = max(1, parsed_row - row_offset)
                    parsed = (col_index, parsed_row)
                cells.append((cell, parsed))
                if parsed is not None:
                    parsed_rows.append(parsed[1])

            if not cells:
                parent = row.getparent()
                if parent is not None:
                    parent.remove(row)
                continue

            unique_rows = {value for value in parsed_rows}
            if candidate is None and parsed_rows:
                candidate = min(parsed_rows)
                if row_index > candidate:
                    row_index = candidate

            row.set("r", str(row_index))

            cols: list[int] = []
            row_rows: list[int] = []
            next_col = 0
            for cell, parsed in cells:
                if parsed is None or removed_cells:
                    col_index = next_col + 1
                    cell_row = row_index
                    if parsed is not None:
                        _, original_row = parsed
                        if len(unique_rows) > 1:
                            cell_row = original_row
                            row_index = max(row_index, cell_row)
                else:
                    col_index, original_row = parsed
                    if len(unique_rows) <= 1:
                        cell_row = row_index
                    else:
                        cell_row = original_row
                    row_index = max(row_index, cell_row)
                next_col = col_index
                cell.set("r", f"{self._column_letters(col_index)}{cell_row}")
                cols.append(col_index)
                row_rows.append(cell_row)

                if min_col is None or col_index < min_col:
                    min_col = col_index
                if max_col is None or col_index > max_col:
                    max_col = col_index

            if cols:
                row.set("spans", f"{min(cols)}:{max(cols)}")
            else:
                row.attrib.pop("spans", None)

            if row_rows:
                row.set("r", str(min(row_rows)))
                min_row_val = min(row_rows)
                max_row_val = max(row_rows)
                if min_row is None or min_row_val < min_row:
                    min_row = min_row_val
                if max_row is None or max_row_val > max_row:
                    max_row = max_row_val
                last_index = max(last_index, max_row_val)
            else:
                if min_row is None or row_index < min_row:
                    min_row = row_index
                if max_row is None or row_index > max_row:
                    max_row = row_index
                last_index = max(last_index, row_index)

        dimension = tree.find(f"{prefix}dimension")
        if min_row is not None and min_col is not None and max_col is not None and max_row is not None:
            ref = (
                f"{self._column_letters(min_col)}{min_row}:"
                f"{self._column_letters(max_col)}{max_row}"
            )
        else:
            ref = "A1"

        if dimension is None:
            tag = f"{prefix}dimension" if prefix else "dimension"
            dimension = etree.Element(tag)
            tree.insert(0, dimension)

        dimension.set("ref", ref)

        return etree.tostring(tree, encoding="unicode")

    def _cell_has_value(self, cell: etree._Element, prefix: str) -> bool:
        if cell.find(f"{prefix}f") is not None:
            return True

        value = cell.find(f"{prefix}v")
        if value is not None and value.text is not None and value.text.strip():
            return True

        inline = cell.find(f"{prefix}is")
        if inline is not None:
            text = "".join(
                node.text or ""
                for node in inline.findall(f".//{prefix}t")
            )
            if text.strip():
                return True

        return False

    def _map_sheet_columns(self, sheet_tree: etree._Element) -> dict[int, set[int]]:
        ns = sheet_tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""

        rows: dict[int, set[int]] = {}
        for row in sheet_tree.findall(f".//{prefix}row"):
            row_index = row.get("r")
            if row_index:
                try:
                    idx = int(row_index)
                except ValueError:
                    continue
            else:
                # Fallback: count rows sequentially if "r" missing
                idx = len(rows) + 1
            cols: set[int] = set()
            for cell in row.findall(f"{prefix}c"):
                cell_ref = cell.get("r")
                if not cell_ref:
                    continue
                parsed = self._split_cell(cell_ref)
                if parsed is None:
                    continue
                col_index, _ = parsed
                cols.add(col_index)
            rows[idx] = cols
        return rows

    def _update_table_definition(
        self,
        table_xml: str,
        sheet_name: str,
        row_columns: dict[int, set[int]],
        workbook_values: dict[str, dict[str, str]],
        sheet_path: str,
    ) -> tuple[str | None, dict[str, object] | None]:
        try:
            table_tree = etree.fromstring(table_xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return None, None

        ns = table_tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""

        table_name = table_tree.get("name") or table_tree.get("displayName")
        if not table_name:
            return None, None

        ref = table_tree.get("ref")
        if not ref:
            return None, None

        start_cell, end_cell = ref.split(":") if ":" in ref else (ref, ref)
        start = self._split_cell(start_cell)
        end = self._split_cell(end_cell)
        if start is None or end is None:
            return None, None

        start_col, start_row = start
        end_col, end_row = end

        header_rows = int(table_tree.get("headerRowCount", "1") or 0)
        totals_rows = int(table_tree.get("totalsRowCount", "0") or 0)
        data_start_row = start_row + header_rows
        data_end_row = end_row - totals_rows if totals_rows else end_row

        # Determine actual last data row based on rendered worksheet
        actual_end_row = data_start_row - 1
        for row_index in sorted(row_columns):
            if row_index < data_start_row:
                continue
            if totals_rows and row_index > data_end_row:
                continue
            columns = row_columns[row_index]
            if any(start_col <= col <= end_col for col in columns):
                actual_end_row = max(actual_end_row, row_index)

        if totals_rows:
            new_end_row = max(actual_end_row, data_start_row - 1) + totals_rows
        else:
            new_end_row = max(actual_end_row, data_start_row - 1)

        if new_end_row < data_start_row and not totals_rows:
            new_end_row = data_start_row - 1

        if new_end_row != end_row:
            end_row = new_end_row

        columns_in_use: set[int] = set()
        for row_index in range(start_row, end_row + 1):
            columns = row_columns.get(row_index)
            if not columns:
                continue
            for column_index in columns:
                if column_index >= start_col:
                    columns_in_use.add(column_index)

        sheet_values = (
            workbook_values.get(sheet_name)
            or workbook_values.get(sheet_path)
            or {}
        )

        header_values: dict[int, str] = {}
        if header_rows:
            for offset in range(header_rows):
                header_row = start_row + offset
                row_cols = row_columns.get(header_row, set())
                for column_index in row_cols:
                    if column_index < start_col:
                        continue
                    cell_ref = f"{self._column_letters(column_index)}{header_row}"
                    value = sheet_values.get(cell_ref)
                    if value is None:
                        continue
                    stripped = value.strip()
                    if not stripped:
                        continue
                    header_values.setdefault(column_index, stripped)

        if columns_in_use:
            actual_end_col = max(columns_in_use)
        else:
            actual_end_col = end_col

        if actual_end_col < start_col:
            actual_end_col = start_col

        if actual_end_col != end_col:
            end_col = actual_end_col

        new_ref = (
            f"{self._column_letters(start_col)}{start_row}:"
            f"{self._column_letters(end_col)}{end_row}"
        )
        table_tree.set("ref", new_ref)
        for auto_filter in table_tree.findall(f"{prefix}autoFilter"):
            auto_filter.set("ref", new_ref)

        table_columns = table_tree.find(f"{prefix}tableColumns")
        if table_columns is None:
            tag = f"{prefix}tableColumns" if prefix else "tableColumns"
            table_columns = etree.SubElement(table_tree, tag)

        existing_columns = list(table_columns.findall(f"{prefix}tableColumn"))
        desired_count = end_col - start_col + 1
        max_id = 0
        for column in existing_columns:
            try:
                max_id = max(max_id, int(column.get("id", "0")))
            except ValueError:
                continue

        while len(existing_columns) > desired_count:
            column = existing_columns.pop()
            table_columns.remove(column)

        while len(existing_columns) < desired_count:
            max_id += 1
            column = etree.SubElement(table_columns, f"{prefix}tableColumn")
            column.set("id", str(max_id))
            column.set("name", f"Column{max_id}")
            existing_columns.append(column)

        column_names: list[str] = []
        for offset, column in enumerate(existing_columns):
            column_index = start_col + offset
            header_value = header_values.get(column_index)
            if header_value is None or not header_value.strip():
                header_value = column.get("name") or column.get("id") or f"Column{offset + 1}"
            column.set("name", header_value)
            column_names.append(header_value)

        table_columns.set("count", str(len(existing_columns)))

        if not column_names:
            width = end_col - start_col + 1
            column_names = [f"Column{idx}" for idx in range(1, width + 1)]

        table_info: dict[str, object] = {
            "name": table_name,
            "sheet": sheet_name,
            "columns": {},
            "order": column_names,
        }

        data_end_row = end_row - totals_rows if totals_rows else end_row

        columns_info: dict[str, dict[str, list[str]]] = {}
        for offset, column_name in enumerate(column_names):
            column_index = start_col + offset
            column_letter = self._column_letters(column_index)

            headers = [
                f"{column_letter}{row_index}"
                for row_index in range(start_row, start_row + header_rows)
            ] if header_rows else []

            data_cells = [
                f"{column_letter}{row_index}"
                for row_index in range(data_start_row, data_end_row + 1)
            ] if data_start_row <= data_end_row else []

            totals_cells = [
                f"{column_letter}{row_index}"
                for row_index in range(data_end_row + 1, end_row + 1)
            ] if totals_rows else []

            columns_info[column_name] = {
                "headers": headers,
                "data": data_cells,
                "totals": totals_cells,
            }

        table_info["columns"] = columns_info

        return etree.tostring(table_tree, encoding="unicode"), table_info

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

        updated = False

        for num_ref in tree.findall(".//{*}numRef"):
            formula = self._find_chart_formula(num_ref)
            if not formula:
                continue
            values = self._extract_range_values(formula, workbook_data)
            if values is None:
                continue
            cache = self._find_or_create_cache(num_ref, "numCache")
            self._write_cache(cache, values)
            self._write_literal_cache(num_ref, "numLit", values)
            updated = True

        for str_ref in tree.findall(".//{*}strRef"):
            formula = self._find_chart_formula(str_ref)
            if not formula:
                continue
            values = self._extract_range_values(formula, workbook_data)
            if values is None:
                continue
            cache = self._find_or_create_cache(str_ref, "strCache")
            self._write_cache(cache, values)
            self._write_literal_cache(str_ref, "strLit", values)
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

    def _find_chart_formula(self, ref_node) -> str | None:
        for child in ref_node:
            qname = etree.QName(child)
            if qname.localname != "f":
                continue
            if child.text is None:
                return None
            return child.text.strip()
        return None

    def _find_or_create_cache(self, ref_node, local_name: str):
        for child in ref_node:
            if etree.QName(child).localname == local_name:
                return child

        namespace = etree.QName(ref_node).namespace
        tag = f"{{{namespace}}}{local_name}" if namespace else local_name
        return etree.SubElement(ref_node, tag)

    def _write_literal_cache(self, ref_node, local_name: str, values: list[str]) -> None:
        parent = ref_node.getparent()
        if parent is None:
            return

        literal = None
        for child in parent:
            if etree.QName(child).localname == local_name:
                literal = child
                break

        if literal is None:
            namespace = etree.QName(ref_node).namespace
            tag = f"{{{namespace}}}{local_name}" if namespace else local_name
            literal = etree.SubElement(parent, tag)

        self._write_cache(literal, values)

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

        sheet_name = None
        cell_part = formula
        if "!" in formula:
            sheet_part, cell_part = formula.rsplit("!", 1)
            sheet_name = self._normalise_sheet_name(sheet_part)

        if "[" in cell_part and "]" in cell_part:
            structured = self._extract_structured_reference(
                sheet_name,
                cell_part,
                workbook_data,
            )
            if structured is not None:
                return structured

        if sheet_name is None:
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

    def _extract_structured_reference(
        self,
        sheet_name: str | None,
        reference: str,
        workbook_data: dict[str, dict[str, str]],
    ) -> list[str] | None:
        tables = workbook_data.get("__tables__")
        if not isinstance(tables, dict):
            return None

        table_name, tokens = self._parse_structured_reference(reference)
        if not table_name:
            return None

        table_info = tables.get(table_name)
        if table_info is None:
            lower_lookup = tables.get("__lower__")
            if isinstance(lower_lookup, dict):
                resolved = lower_lookup.get(table_name.lower())
                if resolved:
                    table_info = tables.get(resolved)
        if not isinstance(table_info, dict):
            return None

        resolved_sheet = sheet_name or table_info.get("sheet")
        if not isinstance(resolved_sheet, str) or not resolved_sheet:
            return None

        sheet_values = workbook_data.get(resolved_sheet)
        if sheet_values is None:
            return None

        qualifiers, columns = self._interpret_structured_tokens(tokens, table_info)
        if columns is None or not columns:
            return None

        values: list[str] = []
        columns_info = table_info.get("columns")
        if not isinstance(columns_info, dict):
            return None

        include_headers = qualifiers.get("headers", False)
        include_data = qualifiers.get("data", False)
        include_totals = qualifiers.get("totals", False)

        for column_name in columns:
            column_info = columns_info.get(column_name)
            if not isinstance(column_info, dict):
                continue
            if include_headers:
                for cell in column_info.get("headers", []):
                    values.append(sheet_values.get(cell, ""))
            if include_data:
                for cell in column_info.get("data", []):
                    values.append(sheet_values.get(cell, ""))
            if include_totals:
                for cell in column_info.get("totals", []):
                    values.append(sheet_values.get(cell, ""))

        return values or None

    def _parse_structured_reference(
        self,
        reference: str,
    ) -> tuple[str | None, list[object]]:
        cleaned = reference.strip()
        if cleaned.startswith("="):
            cleaned = cleaned[1:]
        if not cleaned:
            return None, []

        if "[" not in cleaned:
            return self._strip_structured_quotes(cleaned), []

        name_part, rest = cleaned.split("[", 1)
        table_name = self._strip_structured_quotes(name_part)
        tokens = self._split_structured_tokens("[" + rest)
        return table_name, tokens

    def _split_structured_tokens(self, token_str: str) -> list[object]:
        tokens: list[str] = []
        current: list[str] = []
        depth = 0
        for char in token_str:
            if char == "[":
                depth += 1
                if depth == 1:
                    current = []
                    continue
            elif char == "]":
                depth -= 1
                if depth == 0:
                    token = "".join(current).strip()
                    if token:
                        tokens.append(token)
                    current = []
                    continue
            elif char == "," and depth == 1:
                token = "".join(current).strip()
                if token:
                    tokens.append(token)
                current = []
                continue

            if depth >= 1:
                current.append(char)

        normalised: list[object] = []
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            if ":" in token:
                start, end = token.split(":", 1)
                start = self._strip_structured_component(start)
                end = self._strip_structured_component(end)
                if start and end:
                    normalised.append((start, end))
                continue
            normalised.append(self._strip_structured_component(token))
        return normalised

    def _strip_structured_component(self, component: str) -> str:
        result = component.strip()
        while result.startswith("[") and result.endswith("]") and len(result) >= 2:
            result = result[1:-1].strip()
        return self._strip_structured_quotes(result)

    def _strip_structured_quotes(self, value: str) -> str | None:
        stripped = value.strip()
        if stripped.startswith("'") and stripped.endswith("'") and len(stripped) >= 2:
            stripped = stripped[1:-1]
        return stripped or None

    def _interpret_structured_tokens(
        self,
        tokens: list[object],
        table_info: dict[str, object],
    ) -> tuple[dict[str, bool], list[str] | None]:
        order = table_info.get("order")
        if not isinstance(order, list):
            order = []
        order_lookup = {name: idx for idx, name in enumerate(order) if isinstance(name, str)}

        qualifier_flags: set[str] = set()
        selected_indices: list[int] = []

        def add_column(name: str | None) -> None:
            if not name:
                return
            idx = order_lookup.get(name)
            if idx is None:
                return
            if idx not in selected_indices:
                selected_indices.append(idx)

        for token in tokens:
            if isinstance(token, tuple):
                start, end = token
                if not isinstance(start, str) or not isinstance(end, str):
                    continue
                start_idx = order_lookup.get(start)
                end_idx = order_lookup.get(end)
                if start_idx is None or end_idx is None:
                    continue
                if start_idx <= end_idx:
                    indices = range(start_idx, end_idx + 1)
                else:
                    indices = range(end_idx, start_idx + 1)
                for idx in indices:
                    if idx not in selected_indices:
                        selected_indices.append(idx)
                continue

            if isinstance(token, str):
                lowered = token.lower()
                if lowered.startswith("#"):
                    qualifier_flags.add(lowered)
                    continue
                add_column(token)

        if not selected_indices:
            selected_indices = list(range(len(order)))

        qualifiers = {
            "headers": "#headers" in qualifier_flags or "#all" in qualifier_flags,
            "data": bool(
                {"#data", "#all"}.intersection(qualifier_flags)
                or not qualifier_flags
            ),
            "totals": "#totals" in qualifier_flags or "#all" in qualifier_flags,
        }

        if "#this row" in qualifier_flags:
            return qualifiers, None

        columns = [order[idx] for idx in sorted(selected_indices) if idx < len(order)]
        return qualifiers, columns

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

    def _write_cache(self, cache, values: list[str]) -> None:
        namespace = etree.QName(cache).namespace
        prefix = f"{{{namespace}}}" if namespace else ""
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

