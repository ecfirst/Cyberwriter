"""Extended DocxTemplate with support for additional templated parts."""

from __future__ import annotations

import fnmatch
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


_JINJA_STATEMENT_RE = re.compile(r"({[{%#].*?[}%]})", re.DOTALL)


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
        for part in self._iter_additional_parts():
            if self._is_excel_part(part):
                self._render_excel_part(part, context, jinja_env)
                continue

            xml = self.get_part_xml(part)
            patched = self.patch_xml(xml)
            rendered = self.render_xml_part(patched, part, context, jinja_env)
            rendered_bytes = rendered.encode("utf-8")
            if hasattr(part, "_element"):
                part._element = parse_xml(rendered_bytes)
            if hasattr(part, "_blob"):
                part._blob = rendered_bytes

    def _is_excel_part(self, part) -> bool:
        partname = str(part.partname).lstrip("/")
        return partname.endswith(".xlsx")

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

    def _render_excel_part(self, part, context, jinja_env) -> None:
        blob = getattr(part, "blob", None)
        if blob is None:
            blob = getattr(part, "_blob", b"")
        if not blob:
            return

        source = BytesIO(blob)
        destination = BytesIO()

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

        for filename, data in list(rendered_files.items()):
            if not filename.startswith("xl/worksheets/"):
                continue
            xml = data.decode("utf-8")
            coerced = self._coerce_excel_numeric_cells(xml, shared_strings)
            rendered_files[filename] = coerced.encode("utf-8")

        with ZipFile(destination, "w") as patched_archive:
            for filename, data in rendered_files.items():
                info = file_infos.get(filename)
                if info is not None:
                    patched_archive.writestr(info, data)
                else:
                    patched_archive.writestr(filename, data)

        rendered_bytes = destination.getvalue()
        if hasattr(part, "_blob"):
            part._blob = rendered_bytes

    # ------------------------------------------------------------------
    # Excel helpers

    def _coerce_excel_numeric_cells(
        self, xml: str, shared_strings: dict[int, str] | None
    ) -> str:
        """Convert templated inline strings that contain numbers into numeric cells."""

        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return xml

        namespace = {"x": _EXCEL_MAIN_NS}
        changed = False

        for cell in root.findall(".//x:c", namespace):
            cell_type = cell.get("t")
            if cell_type not in {"inlineStr", "str", "s"}:
                continue

            text_value = self._extract_excel_cell_text(
                cell, cell_type, namespace, shared_strings
            )
            numeric_text = self._normalize_numeric_string(text_value)
            if numeric_text is None:
                continue

            if cell_type == "inlineStr":
                for child in list(cell):
                    cell.remove(child)
                value_element = ET.SubElement(cell, f"{{{_EXCEL_MAIN_NS}}}v")
                value_element.text = numeric_text
            else:
                value_element = cell.find("x:v", namespace)
                if value_element is None:
                    value_element = ET.SubElement(cell, f"{{{_EXCEL_MAIN_NS}}}v")
                value_element.text = numeric_text

            cell.attrib.pop("t", None)
            changed = True

        if not changed:
            return xml

        return ET.tostring(root, encoding="unicode")

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

    @staticmethod
    def _normalize_numeric_string(value: str | None) -> str | None:
        if value is None:
            return None

        stripped = value.strip()
        if not stripped:
            return None

        if not re.fullmatch(r"-?\d+(\.\d+)?", stripped):
            return None

        return stripped

