from __future__ import annotations

import re
from pathlib import Path

from .models import Requirement

_REQ_RE = re.compile(
    r"^\s*(?:[-*]\s*\[[ xX]\]|\d+[.)])\s*(?:(?P<id>[A-Za-z][A-Za-z0-9_-]+)\s*:\s*)?(?P<text>.+?)\s*$"
)


def normalize_requirement_id(raw: str | None, ordinal: int) -> str:
    """Normalize IDs while preserving explicit project IDs."""
    if not raw:
        return f"REQ-{ordinal:03d}"
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", raw).strip("-").upper()
    if cleaned.startswith("REQ-"):
        return cleaned
    if cleaned == "REQ":
        return f"REQ-{ordinal:03d}"
    if cleaned.isdigit():
        return f"REQ-{int(cleaned):03d}"
    return cleaned


def parse_requirements(path: str | Path) -> list[Requirement]:
    """Parse checklist requirements such as ``- [ ] REQ-001: ...``."""
    path = Path(path)
    requirements: list[Requirement] = []
    for ordinal, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = _REQ_RE.match(line)
        if not match:
            continue
        text = match.group("text").strip()
        source_hint = None
        hint_match = re.search(r"\s+\(source:\s*(.+?)\)\s*$", text, re.I)
        if hint_match:
            source_hint = hint_match.group(1).strip()
            text = text[: hint_match.start()].rstrip()
        requirements.append(Requirement(normalize_requirement_id(match.group("id"), len(requirements) + 1), text, source_hint))
    if not requirements:
        raise ValueError(f"No checklist requirements found in {path}.")
    ids = [item.id for item in requirements]
    if len(ids) != len(set(ids)):
        raise ValueError("Requirement IDs must be unique.")
    return requirements
