"""Utilities for interacting with the OpenAI Responses API."""

from __future__ import annotations

# Standard Libraries
import logging
from typing import Optional

# Django Imports
from django.db.utils import OperationalError, ProgrammingError

# 3rd Party Libraries
from openai import OpenAI

# Ghostwriter Libraries
from ghostwriter.commandcenter.models import OpenAIConfiguration

logger = logging.getLogger(__name__)


def _extract_response_text(response: object) -> Optional[str]:
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    payload = response
    if hasattr(response, "model_dump"):
        payload = response.model_dump()

    if not isinstance(payload, dict):
        return None

    output_items = payload.get("output", [])
    parts: list[str] = []
    for item in output_items:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            if content.get("type") not in {"output_text", "text"}:
                continue
            text_value = content.get("text")
            if isinstance(text_value, dict):
                text_value = text_value.get("value")
            if isinstance(text_value, str) and text_value.strip():
                parts.append(text_value.strip())

    if parts:
        return " ".join(parts).strip()

    return None


def submit_prompt_to_assistant(prompt: str, config: Optional[OpenAIConfiguration] = None) -> Optional[str]:
    """Submit ``prompt`` to the OpenAI Responses API and return the response text.

    The model, system instructions and reasoning settings come from
    :class:`~ghostwriter.commandcenter.models.OpenAIConfiguration`; ``prompt`` is the
    per-call user content. Static instructions go first so the cached prefix is shared
    across calls. Returns ``None`` (never raises) when the feature is disabled, the
    configuration is incomplete, or the request fails.
    """

    if not prompt or not prompt.strip():
        return None

    try:
        active_config = config or OpenAIConfiguration.get_solo()
    except (OpenAIConfiguration.DoesNotExist, ProgrammingError, OperationalError):
        logger.debug("OpenAI configuration is unavailable; skipping prompt submission")
        return None

    if not active_config.enable:
        return None

    model = (active_config.model or "").strip()
    api_key = (active_config.api_key or "").strip()
    if not model or not api_key:
        return None

    request_kwargs = {
        "model": model,
        "input": prompt,
        "reasoning": {"effort": active_config.reasoning_effort},
        "text": {"verbosity": active_config.verbosity},
    }
    instructions = active_config.effective_instructions
    if instructions:
        request_kwargs["instructions"] = instructions

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(**request_kwargs)
    except Exception as exc:  # pragma: no cover - network safety
        logger.warning("Failed to submit OpenAI prompt: %s", exc)
        return None

    return _extract_response_text(response)
