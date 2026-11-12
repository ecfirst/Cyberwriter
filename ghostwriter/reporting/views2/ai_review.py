"""
AI review generation for reports: one OpenAI-written summary per OWASP Top 10:2025 category,
built from the report's findings and the issues parsed from its supplemental workbooks.
"""

# Standard Libraries
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Mapping, Optional

# Django Imports
from django.contrib import messages
from django.db.utils import OperationalError, ProgrammingError
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.html import escape
from django.views.generic import View
from django.views.generic.detail import SingleObjectMixin

# Ghostwriter Libraries
from ghostwriter.api.utils import ForbiddenJsonResponse, RoleBasedAccessControlMixin
from ghostwriter.commandcenter.models import AIReviewPromptTemplate, OpenAIConfiguration
from ghostwriter.modules.openai_client import submit_prompt_to_assistant
from ghostwriter.modules.reportwriter.jinja_funcs import strip_html
from ghostwriter.reporting.ai_review_prompts import (
    AI_REVIEW_SECTION_LABELS,
    AI_REVIEW_SECTIONS,
    normalize_section_key,
    render_prompt_footer,
    render_prompt_text,
)
from ghostwriter.reporting.models import Report, ReportSupplementalFile
from ghostwriter.reporting.supplemental_parsers import iter_supplemental_entries

logger = logging.getLogger(__name__)

# Longest text sent for any single finding or issue field
MAX_TEXT_CHARS = 4000
# Upper bound on concurrent OpenAI requests for one "Generate All" click
MAX_WORKERS = 8

SUPPLEMENTAL_SOURCE_LABELS = dict(ReportSupplementalFile.Kind.choices)


def plain_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    """Strip HTML from ``value`` and cap it at ``limit`` characters."""
    if value is None:
        return ""
    text = str(value)
    if "<" in text:
        text = strip_html(text)
    text = text.strip()
    if len(text) > limit:
        text = text[: max(0, limit - 1)] + "…"
    return text


def build_ai_review_sections(ai_review_payload: Any) -> List[Dict[str, str]]:
    """Return every OWASP category with its stored content (``""`` when none)."""
    payload = ai_review_payload if isinstance(ai_review_payload, Mapping) else {}
    return [
        {"key": key, "label": label, "content": payload.get(key) or ""}
        for key, label, _description in AI_REVIEW_SECTIONS
    ]


def normalize_ai_review_payload(ai_review_payload: Any) -> Dict[str, Any]:
    """Return a plain dict copy of the stored review text, dropping anything that is not a mapping."""
    if not isinstance(ai_review_payload, Mapping):
        return {}
    return {str(key): value for key, value in ai_review_payload.items()}


def build_ai_review_payload(report: Report) -> Dict[str, Any]:
    """
    Collect the data sent to OpenAI for every category: the report's findings (title, tags, type,
    severity, CVSS, description, impact) and the issue, risk, impact, and evidence of each unique
    issue parsed from the uploaded supplemental workbooks.
    """
    findings: List[Dict[str, Any]] = []
    finding_links = (
        report.reportfindinglink_set.select_related("severity", "finding_type")
        .prefetch_related("tags")
        .order_by("severity__weight", "-cvss_score", "position")
    )
    for finding in finding_links:
        cvss_score = finding.cvss_score if finding.cvss_score not in ("", None) else None
        findings.append(
            {
                "title": plain_text(finding.title, 500),
                "tags": sorted(tag.name for tag in finding.tags.all()),
                "finding_type": str(finding.finding_type) if finding.finding_type else "",
                "severity": str(finding.severity) if finding.severity else "",
                "cvss_score": cvss_score,
                "cvss_vector": finding.cvss_vector or "",
                "description": plain_text(finding.description),
                "impact": plain_text(finding.impact),
            }
        )

    supplemental_issues: List[Dict[str, Any]] = []
    supplemental_files = list(report.supplemental_files.all())
    for supplemental in supplemental_files:
        # Entries cached by an older parser lack impact/evidence; re-read the workbook once
        if supplemental.needs_reparse:
            supplemental.refresh_cap_entries()
    for supplemental, entry in iter_supplemental_entries(supplemental_files):
        issue = plain_text(entry.get("issue"), 500)
        if not issue:
            continue
        source = entry.get("source") or supplemental.kind
        evidence = entry.get("evidence")
        if not isinstance(evidence, list):
            evidence = []
        supplemental_issues.append(
            {
                "source": SUPPLEMENTAL_SOURCE_LABELS.get(source, source),
                "issue": issue,
                "risk": entry.get("risk") or "",
                "impact": plain_text(entry.get("impact")),
                "evidence": [plain_text(sample) for sample in evidence if sample],
            }
        )

    project = report.project
    return {
        "report": {
            "title": report.title,
            "client": str(project.client) if project and project.client_id else "",
            "project": str(project) if project else "",
        },
        "findings": findings,
        "supplemental_issues": supplemental_issues,
    }


def build_ai_review_prompt(
    section_key: str,
    payload_json: str,
    prompt_texts: Optional[Mapping[str, Mapping[str, str]]] = None,
) -> str:
    """Compose instruction + report data JSON (+ footer) for one category."""
    key = normalize_section_key(section_key)
    label = AI_REVIEW_SECTION_LABELS.get(key, key)
    texts = (prompt_texts or {}).get(key) or AIReviewPromptTemplate.get_prompt_text(key)
    instruction = render_prompt_text(texts.get("instruction"), label)
    footer = render_prompt_footer(texts.get("footer"), label)
    prompt = f"{instruction}\n\n{payload_json}" if instruction else payload_json
    if footer:
        prompt += f"\n\n{footer}"
    return prompt


_MD_BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.S)
_MD_BOLD_US = re.compile(r"(?<!\w)__(?=\S)(.+?)(?<=\S)__(?!\w)", re.S)
_MD_ITALIC = re.compile(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])")
_MD_ITALIC_US = re.compile(r"(?<!\w)_(?=[^\s_])(.+?)(?<=[^\s_])_(?!\w)")
_MD_CODE = re.compile(r"`([^`\n]*)`")
_MD_HEADING = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]+", re.M)
_MD_LIST = re.compile(r"^[ \t]*(?:[-*+•]|\d{1,3}[.)])[ \t]+", re.M)


def strip_markdown(text: Optional[str]) -> str:
    """
    Remove the Markdown markers a model may still emit (bold, italic, inline code, headings, list
    bullets) while keeping the words. Underscores inside identifiers such as ``cvss_score`` survive
    because emphasis markers must wrap text at a word boundary.
    """
    if not text:
        return ""
    cleaned = str(text)
    for pattern in (_MD_BOLD, _MD_BOLD_US, _MD_CODE):
        cleaned = pattern.sub(r"\1", cleaned)
    cleaned = _MD_ITALIC.sub(r"\1", cleaned)
    cleaned = _MD_ITALIC_US.sub(r"\1", cleaned)
    cleaned = _MD_HEADING.sub("", cleaned)
    cleaned = _MD_LIST.sub("", cleaned)
    return cleaned


def normalize_ai_response(response_text: Optional[str]) -> str:
    """Convert AI response text into HTML suitable for rich text editors."""
    if not response_text:
        return ""
    cleaned = strip_markdown(response_text).strip()
    safe_text = escape(cleaned).replace("\n\n", "</p><p>").replace("\n", "<br />")
    if not safe_text.strip():
        return ""
    return f"<p>{safe_text}</p>"


def ai_review_enabled() -> bool:
    """Whether the OpenAI integration is switched on and has a model and API key."""
    try:
        config = OpenAIConfiguration.get_solo()
    except (OperationalError, ProgrammingError):  # pragma: no cover - table not ready
        return False
    return bool(config.enable and (config.api_key or "").strip() and (config.model or "").strip())


class ReportAiReviewGenerate(RoleBasedAccessControlMixin, SingleObjectMixin, View):
    """
    Generate AI review text for one or all OWASP Top 10 categories of a :model:`reporting.Report`
    and store it in ``Report.ai_review``. Returns JSON for the report page.
    """

    model = Report
    http_method_names = ["post"]

    def test_func(self):
        return self.get_object().user_can_edit(self.request.user)

    def handle_no_permission(self):
        return ForbiddenJsonResponse()

    def post(self, *args, **kwargs):
        report = self.get_object()
        try:
            requested_section = normalize_section_key(self.request.POST.get("section", ""))
            sections = build_ai_review_sections(report.ai_review)
            if requested_section:
                sections = [section for section in sections if section["key"] == requested_section]
                if not sections:
                    return JsonResponse(
                        {
                            "result": "warning",
                            "message": "The requested AI review category is not available.",
                            "data": {},
                        },
                        status=404,
                    )

            if not ai_review_enabled():
                return JsonResponse(
                    {
                        "result": "warning",
                        "message": (
                            "AI review is not enabled. An administrator must enable and configure the "
                            "OpenAI Configuration in the admin panel."
                        ),
                        "data": {},
                    }
                )

            payload_json = json.dumps(build_ai_review_payload(report), indent=2, default=str)
            prompt_texts = AIReviewPromptTemplate.get_prompt_texts()

            ai_outputs: Dict[str, str] = {}
            failed_sections: List[str] = []
            prompts: List[tuple] = []
            for section in sections:
                try:
                    prompt = build_ai_review_prompt(section["key"], payload_json, prompt_texts=prompt_texts)
                except Exception as exc:  # pragma: no cover - defensive logging
                    logger.warning(
                        "Failed to build AI review prompt for %s on report %s: %s", section["key"], report.pk, exc
                    )
                    failed_sections.append(section["key"])
                    continue
                if not prompt:
                    failed_sections.append(section["key"])
                    continue
                prompts.append((section["key"], prompt))

            if prompts:
                with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(prompts))) as executor:
                    future_map = {
                        executor.submit(
                            submit_prompt_to_assistant,
                            prompt,
                            metadata={"feature": "report_ai_review", "report_id": str(report.pk), "section": key},
                        ): key
                        for key, prompt in prompts
                    }
                    for future in as_completed(future_map):
                        section_key = future_map[future]
                        try:
                            ai_response = future.result()
                        except Exception as exc:  # pragma: no cover - defensive logging
                            logger.warning(
                                "AI review generation failed for %s on report %s: %s", section_key, report.pk, exc
                            )
                            ai_response = None
                        if ai_response:
                            ai_outputs[section_key] = normalize_ai_response(ai_response)
                        else:
                            failed_sections.append(section_key)

            if ai_outputs:
                current_payload = normalize_ai_review_payload(report.ai_review)
                current_payload.update(ai_outputs)
                report.ai_review = current_payload
                report.save(update_fields=["ai_review"])

            if not ai_outputs:
                logger.warning(
                    "AI review generation returned no content for report %s; failed categories: %s",
                    report.pk,
                    failed_sections,
                )
                return JsonResponse(
                    {
                        "result": "warning",
                        "message": (
                            "AI review generation did not return any content. "
                            "The OpenAI request may have failed or timed out; please try again."
                        ),
                        "data": {},
                    },
                    status=502,
                )

            if requested_section:
                response_message = (
                    "AI review generation complete."
                    if not failed_sections
                    else "Unable to generate the requested AI review."
                )
            else:
                response_message = (
                    "AI review generation complete."
                    if not failed_sections
                    else "Some categories could not be generated."
                )
            if failed_sections:
                logger.warning(
                    "AI review generation partially completed for report %s; failed categories: %s",
                    report.pk,
                    failed_sections,
                )
            return JsonResponse(
                {
                    "result": "success",
                    "message": response_message,
                    "data": ai_outputs,
                    "failed": sorted(set(failed_sections)),
                }
            )
        except Exception:  # pragma: no cover - defensive logging
            logger.exception("AI review generation encountered an unexpected error for report %s", report.pk)
            return JsonResponse(
                {"result": "error", "message": "AI review generation failed due to an internal error."},
                status=500,
            )


class ReportAiReviewSave(RoleBasedAccessControlMixin, SingleObjectMixin, View):
    """Persist manual AI review edits submitted from the report page."""

    model = Report
    http_method_names = ["post"]

    def test_func(self):
        return self.get_object().user_can_edit(self.request.user)

    def handle_no_permission(self):
        messages.error(self.request, "You do not have permission to update this report.")
        return redirect("home:dashboard")

    def post(self, *args, **kwargs):
        report = self.get_object()
        payload = normalize_ai_review_payload(report.ai_review)
        for section in build_ai_review_sections(report.ai_review):
            payload[section["key"]] = self.request.POST.get(f"ai_review_{section['key']}", "") or ""
        report.ai_review = payload
        report.save(update_fields=["ai_review"])
        messages.success(self.request, "AI review updates saved.", extra_tags="alert-success")
        return redirect(reverse("reporting:report_detail", kwargs={"pk": report.pk}) + "#ai-review")
