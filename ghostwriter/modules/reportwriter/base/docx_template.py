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
        for part in self._iter_additional_parts():
            partname = self._normalise_partname(part)
            if self._is_excel_part(partname):
                rendered_blob = self._render_excel_part(part, context, jinja_env)
                if rendered_blob is not None and hasattr(part, "_blob"):
                    part._blob = rendered_blob
                continue

            xml = self.get_part_xml(part)
            patched = self.patch_xml(xml)
            rendered = self.render_xml_part(patched, part, context, jinja_env)
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

        rendered_xml = self._coerce_excel_types(rendered_xml)

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

        return output.getvalue()

    # Excel helpers -------------------------------------------------

    def _coerce_excel_types(self, xml_files: dict[str, str]) -> dict[str, str]:
        if not xml_files:
            return xml_files

        shared_strings = None
        shared_strings_key = "xl/sharedStrings.xml"
        if shared_strings_key in xml_files:
            shared_strings = self._parse_shared_strings(xml_files[shared_strings_key])

        for name, xml in list(xml_files.items()):
            if not name.startswith("xl/worksheets/"):
                continue
            xml_files[name] = self._coerce_sheet_types(xml, shared_strings)

        if shared_strings is not None and shared_strings_key in xml_files:
            xml_files[shared_strings_key] = self._serialise_shared_strings(shared_strings)

        return xml_files

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
    ) -> str:
        try:
            tree = etree.fromstring(xml.encode("utf-8"))
        except etree.XMLSyntaxError:
            return xml

        ns = tree.nsmap.get(None)
        prefix = f"{{{ns}}}" if ns else ""

        shared_values = shared_strings[0] if shared_strings else []
        for cell in tree.findall(f".//{prefix}c"):
            cell_type = cell.get("t")
            if cell_type == "s":
                value_node = cell.find(f"{prefix}v")
                if value_node is None or value_node.text is None:
                    continue
                try:
                    index = int(value_node.text)
                except (TypeError, ValueError):
                    continue
                if 0 <= index < len(shared_values):
                    coerced = self._maybe_numeric(shared_values[index])
                    if coerced is not None:
                        cell.attrib.pop("t", None)
                        value_node.text = coerced
                continue

            if cell_type in _INLINE_STRING_TYPES:
                inline = cell.find(f"{prefix}is")
                if inline is None:
                    continue
                text_nodes = inline.findall(f".//{prefix}t")
                text = "".join(node.text or "" for node in text_nodes)
                coerced = self._maybe_numeric(text)
                if coerced is None:
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
                continue

            if cell_type == "str" or cell_type == "b":
                value_node = cell.find(f"{prefix}v")
                if value_node is None or value_node.text is None:
                    continue
                coerced = self._maybe_numeric(value_node.text)
                if coerced is not None:
                    cell.attrib.pop("t", None)
                    value_node.text = coerced

        return etree.tostring(tree, encoding="unicode")

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

