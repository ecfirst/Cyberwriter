"""
Post-render checks and repairs for Word documents produced by `python-docx-template`.

Templates can produce structurally invalid (but well-formed) XML that Word refuses to open without a repair.
These helpers either fail with a user-facing error or quietly fix the structure before the file is saved.
"""

from docx.oxml.shared import OxmlElement

from ghostwriter.modules.reportwriter.base import ReportExportTemplateError

INLINE_SUBDOC_MESSAGE = (
    "A rich text value (an `_rt` field or an evidence object) was inserted with `{{ ... }}`, which places whole "
    "paragraphs inside a text run and corrupts the document. Use `{{p ... }}` instead so the content gets its own "
    "paragraph."
)


def check_and_fix_docx_element(element, location: str | None = "the DOCX template"):
    """
    Validates and repairs the rendered XML under `element` (a python-docx `w:document`, header, or footer element).

    * Raises `ReportExportTemplateError` if a subdocument (paragraphs or tables) ended up inside a text run,
      which happens when a template inserts an `_rt` value or evidence object with `{{ }}` instead of `{{p }}`.
    * Appends an empty paragraph to any table cell that has no block content, which happens when `{{p }}`
      replaces a cell's only paragraph with an empty value. Word requires at least one paragraph per cell.
    """
    nested = element.xpath(".//w:t//w:p | .//w:t//w:tbl")
    if nested:
        snippet = " ".join("".join(nested[0].itertext()).split())[:80]
        message = INLINE_SUBDOC_MESSAGE
        if snippet:
            message += f" The misplaced content starts with: {snippet!r}"
        raise ReportExportTemplateError(message, location)

    fixed_cells = 0
    for tc in element.xpath(".//w:tc"):
        if not tc.xpath("./w:p | ./w:tbl | ./w:sdt"):
            tc.append(OxmlElement("w:p"))
            fixed_cells += 1
    return fixed_cells
