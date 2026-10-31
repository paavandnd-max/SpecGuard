from __future__ import annotations

import re
from pathlib import Path

from .models import Requirement, SourceLocation


def map_requirements(
    requirements: list[Requirement], source_root: str | Path
) -> dict[str, list[SourceLocation]]:
    """Map requirement IDs to explicit ``specguard: REQ-*`` source markers."""
    source_root = Path(source_root)
    mapped = {requirement.id: [] for requirement in requirements}
    wanted = set(mapped)
    marker_re = re.compile(r"specguard\s*:\s*([A-Z][A-Z0-9_-]+)")
    for path in sorted(source_root.rglob("*.py")):
        if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in marker_re.finditer(line):
                requirement_id = match.group(1)
                if requirement_id in wanted:
                    mapped[requirement_id].append(
                        SourceLocation(path, line_number, match.group(0))
                    )
    return mapped
