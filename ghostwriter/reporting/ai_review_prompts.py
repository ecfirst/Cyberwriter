"""Default AI review prompt text and section metadata for the OWASP Top 10:2025 report review.

This module is intentionally free of Django imports so that both
``ghostwriter.reporting.views2.ai_review`` and ``ghostwriter.commandcenter.models`` can
import it without creating an import cycle. The admin-editable
``AIReviewPromptTemplate`` rows are seeded from ``AI_REVIEW_PROMPT_DEFAULTS``
and fall back to it when a row is missing.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Optional

LABEL_PLACEHOLDER = "{label}"

# Defaults for the OpenAI Responses API request. The admin-editable
# ``OpenAIConfiguration`` singleton falls back to them when its fields are blank.
DEFAULT_OPENAI_MODEL = "gpt-6-sol"
DEFAULT_OPENAI_REASONING_EFFORT = "medium"
DEFAULT_OPENAI_VERBOSITY = "medium"
OPENAI_EFFORT_CHOICES = (("low", "Low"), ("medium", "Medium"), ("high", "High"))
DEFAULT_OPENAI_INSTRUCTIONS = (
    'You are a cybersecurity professional AI assistant. '
    'You are an expert in identifying, explaining, and summarizing technical vulnerabilities, exploitation methods, and security impacts in language that is easy for non-technical audiences to understand.\n\n'
    'Your tone must be professional, factual, and clear, avoiding jargon unless it is immediately explained. '
    'When summarizing or describing data, focus strictly on the information provided — do not speculate beyond the evidence.\n\n'
    'You must:\n\n'
    'Write only the language that directly satisfies the user’s request.\n\n'
    'Exclude all additional commentary, explanations, reasoning, or meta-text.\n\n'
    'Use concise, well-structured paragraphs.\n\n'
    'Clearly explain technical issues in plain English without oversimplifying.\n\n'
    'Accurately describe how a vulnerability works, how it can be exploited, and the realistic impact.\n\n'
    'Avoid emotional, promotional, or sensational wording.\n\n'
    'Provide context only when it clarifies risk or relevance.\n\n'
    'Your responses must only contain the requested output — nothing more.'
)

# (section key, label, short description of what the category covers)
AI_REVIEW_SECTIONS = (
    (
        "a01_rt",
        "A01:2025 Broken Access Control",
        "failures to enforce authorization, such as insecure direct object references, privilege "
        "escalation, missing function-level access control, forced browsing, path traversal, and "
        "permissive CORS configuration.",
    ),
    (
        "a02_rt",
        "A02:2025 Security Misconfiguration",
        "insecure default settings, unnecessary services or features left enabled, missing security "
        "headers, verbose error messages, directory listings, and unhardened servers, frameworks, or "
        "cloud resources.",
    ),
    (
        "a03_rt",
        "A03:2025 Software Supply Chain Failures",
        "vulnerable or compromised third-party components, libraries, frameworks, build pipelines, "
        "package sources, and update mechanisms, including software running known-vulnerable versions.",
    ),
    (
        "a04_rt",
        "A04:2025 Cryptographic Failures",
        "weak or missing encryption, outdated TLS/SSL protocols or cipher suites, weak hashing, "
        "cleartext transmission or storage of sensitive data, and poor key or certificate management.",
    ),
    (
        "a05_rt",
        "A05:2025 Injection",
        "untrusted data reaching an interpreter, such as SQL, NoSQL, OS command, LDAP, and XPath "
        "injection as well as cross-site scripting.",
    ),
    (
        "a06_rt",
        "A06:2025 Insecure Design",
        "missing or ineffective security controls in the application's design, business logic abuse, "
        "absent threat modeling, and missing rate limiting or anti-automation protections.",
    ),
    (
        "a07_rt",
        "A07:2025 Authentication Failures",
        "weak or default passwords, credential stuffing and brute-force exposure, missing "
        "multi-factor authentication, session management weaknesses, and insecure password recovery.",
    ),
    (
        "a08_rt",
        "A08:2025 Software or Data Integrity Failures",
        "unsigned or unverified updates and artifacts, insecure deserialization, CI/CD and code "
        "integrity weaknesses, and untrusted data accepted over trusted channels.",
    ),
    (
        "a09_rt",
        "A09:2025 Security Logging and Alerting Failures",
        "insufficient logging, monitoring, alerting, and incident response visibility that lets "
        "attacks go undetected.",
    ),
    (
        "a10_rt",
        "A10:2025 Mishandling of Exceptional Conditions",
        "improper error handling, fail-open behavior, unhandled exceptions, information leakage "
        "through error output, and resource exhaustion triggered by unexpected input.",
    ),
)

AI_REVIEW_SECTION_CHOICES = [(key, label) for key, label, _description in AI_REVIEW_SECTIONS]

AI_REVIEW_SECTION_LABELS = {key: label for key, label, _description in AI_REVIEW_SECTIONS}

AI_REVIEW_SECTION_KEYS = [key for key, _label, _description in AI_REVIEW_SECTIONS]

DEFAULT_INSTRUCTION_TEMPLATE = (
    "Provide a summary in one or two paragraphs for OWASP Top 10:2025 category {label}. This category "
    "covers {description} Use the report findings and scanner issues in the following JSON as context. "
    "Identify which findings or issues, if any, fall under this category, explain in plain language how "
    "they could be exploited and the realistic impact, and keep the response concise. If nothing in the "
    "data relates to this category, state that no issues in this category were identified during the "
    "assessment."
)

# Fully expanded instruction/footer text per section. ``{label}`` is replaced with the
# category label when the prompt is built, so admin edits can reuse it.
AI_REVIEW_PROMPT_DEFAULTS: "OrderedDict[str, Dict[str, str]]" = OrderedDict(
    (
        key,
        {
            "label": label,
            "instruction": DEFAULT_INSTRUCTION_TEMPLATE.format(
                label=LABEL_PLACEHOLDER, description=description
            ),
            "footer": "",
        },
    )
    for key, label, description in AI_REVIEW_SECTIONS
)

GENERIC_INSTRUCTION = (
    "Provide a summary in one or two paragraphs for the OWASP Top 10:2025 category {label}. Use the "
    "report findings and scanner issues in the following JSON as context and keep the response concise."
)


def normalize_section_key(section_key: str) -> str:
    """Return the ``*_rt`` section key for ``section_key`` (accepts bare keys such as ``a01``)."""

    key = (section_key or "").strip()
    if key.endswith("_rt"):
        return key
    return f"{key}_rt" if key else key


def get_default_prompt_text(section_key: str) -> Dict[str, str]:
    """Return the default ``{"instruction", "footer"}`` for ``section_key``."""

    entry = AI_REVIEW_PROMPT_DEFAULTS.get(normalize_section_key(section_key))
    if entry is None:
        return {"instruction": GENERIC_INSTRUCTION, "footer": ""}
    return {"instruction": entry["instruction"], "footer": entry["footer"]}


def render_prompt_text(text: Optional[str], label: Optional[str]) -> str:
    """Return ``text`` with ``{label}`` replaced by ``label`` (or ``the category``)."""

    if not text or not str(text).strip():
        return ""
    return str(text).replace(LABEL_PLACEHOLDER, label or "the category")


def render_prompt_footer(footer: Optional[str], label: Optional[str]) -> str:
    """Return the rendered footer, or ``""`` when no footer is configured."""

    return render_prompt_text(footer, label)
