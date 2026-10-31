from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .mapping import map_requirements
from .models import Requirement, SourceLocation
from .requirements import parse_requirements


@dataclass(frozen=True)
class RequirementInsight:
    requirement: Requirement
    atomic: bool
    ambiguous: bool
    ambiguity_reasons: tuple[str, ...] = ()
    source_locations: tuple[SourceLocation, ...] = ()
    test_locations: tuple[Path, ...] = ()


@dataclass
class TraceabilityGraph:
    requirements: list[RequirementInsight]
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        nodes = [{"id": item.requirement.id, "type": "requirement", "label": item.requirement.text} for item in self.requirements]
        edges: list[dict] = []
        for item in self.requirements:
            for location in item.source_locations:
                node_id = f"source:{location.path}:{location.line}"
                nodes.append({"id": node_id, "type": "source", "label": str(location.path)})
                edges.append({"from": item.requirement.id, "to": node_id, "type": "implemented_by"})
            for path in item.test_locations:
                node_id = f"test:{path}"
                nodes.append({"id": node_id, "type": "test", "label": str(path)})
                edges.append({"from": item.requirement.id, "to": node_id, "type": "verified_by"})
        return {"nodes": nodes, "edges": edges}


def _ambiguity(text: str) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if len(re.findall(r"\band\b|\bor\b|;", text, flags=re.I)) >= 2:
        reasons.append("multiple conjunctions may contain more than one behavior")
    if re.search(r"\b(may|might|should|appropriate|reasonable|etc)\b", text, flags=re.I):
        reasons.append("non-deterministic or optional language")
    if not re.search(r"\b(must|shall|cannot|cannot|only|required|accepted|reject|return|starts)\b", text, flags=re.I):
        reasons.append("no explicit normative behavior")
    return bool(reasons), tuple(reasons)


def build_traceability(requirements_path: str | Path, project_root: str | Path) -> TraceabilityGraph:
    requirements = parse_requirements(requirements_path)
    project_root = Path(project_root).resolve()
    locations = map_requirements(requirements, project_root)
    tests = [p for p in project_root.rglob("*") if p.is_file() and ("test" in p.name.lower() or "tests" in p.parts)]
    insights: list[RequirementInsight] = []
    for requirement in requirements:
        text = " ".join((requirement.id, requirement.text)).lower()
        test_locations = []
        for path in tests:
            content = path.read_text(encoding="utf-8", errors="ignore").lower()
            if requirement.id.lower() in content or any(token in content for token in re.findall(r"[a-z]{5,}", requirement.text.lower())):
                test_locations.append(path)
        ambiguous, reasons = _ambiguity(requirement.text)
        insights.append(RequirementInsight(requirement, not ambiguous, ambiguous, reasons, tuple(locations.get(requirement.id, [])), tuple(test_locations)))
    graph = TraceabilityGraph(insights)
    graph.nodes, graph.edges = graph.to_dict()["nodes"], graph.to_dict()["edges"]
    return graph
