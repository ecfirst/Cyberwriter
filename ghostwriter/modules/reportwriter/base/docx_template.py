"""Extended DocxTemplate with support for additional templated parts."""

from __future__ import annotations

import fnmatch
from io import BytesIO
import re
from typing import Iterator
from zipfile import ZipFile

from docx.oxml import parse_xml
from docxtpl.template import DocxTemplate
from jinja2 import Environment, meta


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

        with ZipFile(source, "r") as archive, ZipFile(destination, "w") as patched_archive:
            for info in archive.infolist():
                data = archive.read(info.filename)
                if info.filename.lower().endswith(".xml"):
                    xml = data.decode("utf-8")
                    patched = self.patch_xml(xml)
                    rendered = self.render_xml_part(patched, part, context, jinja_env)
                    data = rendered.encode("utf-8")
                patched_archive.writestr(info, data)

        rendered_bytes = destination.getvalue()
        if hasattr(part, "_blob"):
            part._blob = rendered_bytes

