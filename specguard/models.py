from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Classification(str, Enum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Requirement:
    id: str
    text: str
    source_hint: str | None = None


@dataclass(frozen=True)
class SourceLocation:
    path: Path
    line: int
    marker: str


@dataclass(frozen=True)
class MutationProposal:
    requirement_id: str
    description: str
    original: str
    replacement: str
    rationale: str


@dataclass
class RequirementResult:
    requirement: Requirement
    classification: Classification
    description: str = ""
    source: SourceLocation | None = None
    attempt: int = 1
    test_returncode: int | None = None
    test_output: str = ""
    reason: str = ""
    equivalent: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    baseline_passed: bool
    baseline_output: str
    results: list[RequirementResult]
    project: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        counts = {item.value: 0 for item in Classification}
        for result in self.results:
            counts[result.classification.value] += 1
        return counts
