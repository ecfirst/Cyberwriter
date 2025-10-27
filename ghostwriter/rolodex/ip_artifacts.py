"""Shared utilities for supplemental IP list artifacts."""

from __future__ import annotations

# Standard Libraries
from dataclasses import dataclass
from typing import Dict, Iterable, List

IP_ARTIFACT_TYPE_EXTERNAL = "external"
IP_ARTIFACT_TYPE_INTERNAL = "internal"


@dataclass(frozen=True)
class IPArtifactDefinition:
    """Metadata describing a supplemental IP list artifact."""

    slug: str
    label: str
    filename: str
    artifact_key: str


IP_ARTIFACT_DEFINITIONS: Dict[str, IPArtifactDefinition] = {
    IP_ARTIFACT_TYPE_EXTERNAL: IPArtifactDefinition(
        slug="supplemental-external-ips",
        label="External IP's",
        filename="external_ips.txt",
        artifact_key="external_ips",
    ),
    IP_ARTIFACT_TYPE_INTERNAL: IPArtifactDefinition(
        slug="supplemental-internal-ips",
        label="Internal IP's",
        filename="internal_ips.txt",
        artifact_key="internal_ips",
    ),
}


IP_ARTIFACT_ORDER: List[str] = [
    IP_ARTIFACT_TYPE_EXTERNAL,
    IP_ARTIFACT_TYPE_INTERNAL,
]


def normalize_ip_entries(candidates: Iterable[str]) -> List[str]:
    """Return a list of unique, ordered IP entries from the provided candidates."""

    ordered: List[str] = []
    seen = set()
    for candidate in candidates:
        value = (candidate or "").strip()
        if not value or value in seen:
            continue
        ordered.append(value)
        seen.add(value)
    return ordered


def iter_lines_from_text(text: str) -> List[str]:
    """Split text into individual lines, normalizing newline delimiters."""

    normalized_text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    return normalized_text.split("\n")


def parse_ip_text(text: str) -> List[str]:
    """Parse newline-delimited text into a list of normalized IP entries."""

    return normalize_ip_entries(iter_lines_from_text(text))

