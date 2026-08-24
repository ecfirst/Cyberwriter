"""Utilities for normalizing manually edited matrix text back to plain text.

The matrix entry forms render plain ``<textarea>`` widgets, but Ghostwriter's
global TinyMCE bundle auto-attaches to every textarea on the page unless it
opts out (see ``static/js/tinymce/config.js``). Historically the matrix forms
did not opt out, so manually edited entries were saved with ``<p>`` wrapping
and other WYSIWYG markup even though these fields are always consumed as
plain strings (never rendered through the rich-text pipeline). This module
converts any such HTML back into plain text so the field behaves the same
whether it was populated via CSV import or the manual editor.
"""

import re

import bs4

# Fields aren't touched unless they look like they contain HTML at all. This
# keeps clean, CSV-imported text (including a bare "<EC>" placeholder used in
# vulnerability_threat) completely untouched.
_HTML_HINT_RE = re.compile(
    r"</?(p|br|div|span|ul|ol|li|strong|em|b|i|u|table|tr|td|th|blockquote|h[1-6])\b"
    r"|&nbsp;|&lt;|&gt;|&amp;",
    re.IGNORECASE,
)

# The literal "<EC>" placeholder (see data_parsers._adjust_matrix_impact) is
# valid content for vulnerability_threat, but an HTML parser will treat it as
# an (invalid) tag and silently drop it. Shield it with a sentinel that can't
# appear in ordinary matrix text before parsing, then restore it afterward.
_EC_SENTINEL = "_GW_EC_PLACEHOLDER_"
_EC_RE = re.compile(r"(?:<EC>|&lt;EC&gt;)", re.IGNORECASE)

_BLOCK_TAGS = ("p", "div", "li", "tr")


def _build_plain_text(node, out: list) -> None:
    if isinstance(node, bs4.NavigableString):
        out.append(str(node))
        return

    if node.name == "br":
        out.append("\n")

    for child in node.children:
        _build_plain_text(child, out)

    if node.name in _BLOCK_TAGS:
        out.append("\n")


def normalize_matrix_text(value):
    """Return ``value`` with any editor-generated HTML converted to plain text.

    Non-string values are returned unchanged. Strings with no HTML hint are
    only whitespace-trimmed (this is also the fast path that leaves a bare
    ``<EC>`` placeholder untouched).
    """

    if not isinstance(value, str):
        return value

    if not _HTML_HINT_RE.search(value):
        return value.strip()

    shielded = _EC_RE.sub(_EC_SENTINEL, value)

    soup = bs4.BeautifulSoup(shielded, "html.parser")
    out = []
    _build_plain_text(soup, out)
    text = "".join(out)

    text = text.replace(_EC_SENTINEL, "<EC>")
    text = text.replace("\xa0", " ")

    # Collapse runs of 3+ newlines (e.g. from consecutive empty <p> tags) down
    # to a single blank line, and trim trailing whitespace on each line.
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()
