from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from ..intelligence import build_traceability
from ..requirements import parse_requirements
from .models import (
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    Finding,
    RequirementV2,
    ReproducibilityMetadata,
    TestEffectiveness,
    TraceabilityLink,
    VerificationMode,
    ExpectedBehaviorContract,
)
from .oracle import ExpectedBehaviorService


@dataclass(frozen=True)
class RequirementIntelligenceResult:
    requirements: tuple[RequirementV2, ...]
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    traceability: tuple[TraceabilityLink, ...]
    behavior_contracts: tuple[ExpectedBehaviorContract, ...]

    def to_dict(self) -> dict:
        return {
            "requirements": [item.to_dict() for item in self.requirements],
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "traceability": [item.to_dict() for item in self.traceability],
            "behavior_contracts": [item.to_dict() for item in self.behavior_contracts],
        }


class RequirementIntelligenceEngine:
    """Deterministic Phase 1 analysis; it emits candidates, not AI assertions."""

    version = "requirements-v2-phase1"
    _normative = re.compile(r"\b(must|shall|cannot|only|required|accepted|reject|return|starts)\b", re.I)
    _vague = re.compile(r"\b(may|might|appropriate|reasonable|soon|fast|etc)\b", re.I)
    _conjunction = re.compile(r"\b(and|or)\b|;", re.I)
    _explicit_dependency = re.compile(r"\b(?:depends\s+on|after|requires)\s+(REQ[-\s]?\d+)\b", re.I)
    _requirement_ref = re.compile(r"\bREQ[-\s]?\d+\b", re.I)

    def __init__(self, oracle: ExpectedBehaviorService | None = None):
        self.oracle = oracle or ExpectedBehaviorService()

    @staticmethod
    def normalize_text(text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text)
        normalized = normalized.replace("\u201c", '"').replace("\u201d", '"').replace("\u2019", "'")
        return " ".join(normalized.split()).strip()

    @staticmethod
    def _id(prefix: str, *parts: str) -> str:
        digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
        return f"{prefix}-{digest}"

    def _evidence(self, run_id: str, kind: str, claim: str, requirement_id: str | None, details: dict, input_hash: str) -> Evidence:
        evidence_id = self._id("evidence", run_id, kind, requirement_id or "project", claim)
        repro = ReproducibilityMetadata(input_hashes={"requirements": input_hash}, parser_version=self.version, parent_evidence_ids=())
        return Evidence(evidence_id, run_id, kind, EvidenceStatus.OBSERVED, claim, requirement_id=requirement_id, input_hashes={"requirements": input_hash}, reproducibility=repro, details=details)

    def _finding(self, run_id: str, requirement_id: str | None, category: str, message: str, evidence_id: str, verdict: str = "candidate") -> Finding:
        return Finding(
            finding_id=self._id("finding", run_id, category, requirement_id or "project", message),
            requirement_id=requirement_id,
            category=category,
            severity="warning",
            verdict=verdict,
            compliance_status=ComplianceStatus.UNKNOWN,
            test_effectiveness_status=TestEffectiveness.NOT_EVALUATED,
            verification_mode=VerificationMode.STATIC,
            message=message,
            evidence_ids=(evidence_id,),
        )

    def analyze(self, requirements_path: str | Path, project_root: str | Path | None = None, run_id: str = "requirements-intelligence") -> RequirementIntelligenceResult:
        requirements_path = Path(requirements_path)
        source_bytes = requirements_path.read_bytes()
        input_hash = hashlib.sha256(source_bytes).hexdigest()
        legacy = parse_requirements(requirements_path)
        normalized: list[RequirementV2] = []
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        links: list[TraceabilityLink] = []
        contracts: list[ExpectedBehaviorContract] = []

        for item in legacy:
            text = self.normalize_text(item.text)
            conjunctions = tuple(sorted(set(match.group(1).lower() if match.group(1) else ";" for match in self._conjunction.finditer(text))))
            atomic = not conjunctions
            atomicity_reasons = (f"contains conjunctions: {', '.join(conjunctions)}",) if conjunctions else ()
            ambiguity_reasons: list[str] = []
            if self._vague.search(text):
                ambiguity_reasons.append("contains vague or optional language")
            if not self._normative.search(text):
                ambiguity_reasons.append("no explicit normative outcome recognized")
            if len(text) < 12:
                ambiguity_reasons.append("requirement text is too short to establish behavior")
            refs = {ref.replace(" ", "-").upper() for ref in self._requirement_ref.findall(text)}
            dependencies = tuple(sorted(ref for ref in refs if ref != item.id))
            requirement = RequirementV2(item.id, text, item.text, atomic, atomicity_reasons, bool(ambiguity_reasons), tuple(ambiguity_reasons), dependencies, item.source_hint)
            normalized.append(requirement)

            normalized_evidence = self._evidence(run_id, "normalized_requirement", "Requirement text normalized deterministically", item.id, {"source_text": item.text, "normalized_text": text}, input_hash)
            evidence.append(normalized_evidence)
            if not atomic:
                atomic_evidence = self._evidence(run_id, "atomicity_candidate", "Requirement contains multiple behavior clauses", item.id, {"reasons": atomicity_reasons}, input_hash)
                evidence.append(atomic_evidence)
                findings.append(self._finding(run_id, item.id, "atomicity_candidate", "Requirement may contain more than one atomic behavior", atomic_evidence.evidence_id))
            if ambiguity_reasons:
                ambiguity_evidence = self._evidence(run_id, "ambiguity_detection", "Deterministic ambiguity rule matched", item.id, {"reasons": ambiguity_reasons}, input_hash)
                evidence.append(ambiguity_evidence)
                findings.append(self._finding(run_id, item.id, "ambiguity", "; ".join(ambiguity_reasons), ambiguity_evidence.evidence_id))
            if dependencies:
                dependency_evidence = self._evidence(run_id, "dependency_candidate", "Explicit requirement references were found", item.id, {"dependencies": dependencies}, input_hash)
                evidence.append(dependency_evidence)
                findings.append(self._finding(run_id, item.id, "dependency_candidate", f"Requirement references {', '.join(dependencies)}", dependency_evidence.evidence_id))
            contract, oracle_evidence = self.oracle.derive(requirement, run_id)
            contracts.append(contract)
            evidence.append(oracle_evidence)

        for left_index, left in enumerate(normalized):
            for right in normalized[left_index + 1:]:
                if self._contradictory(left.normalized_text, right.normalized_text):
                    contradiction_evidence = self._evidence(run_id, "contradiction_detection", "Explicit opposing normative clauses share subject terms", None, {"left": left.requirement_id, "right": right.requirement_id}, input_hash)
                    evidence.append(contradiction_evidence)
                    findings.append(self._finding(run_id, left.requirement_id, "contradiction", f"Possible contradiction with {right.requirement_id}", contradiction_evidence.evidence_id))
                    findings.append(self._finding(run_id, right.requirement_id, "contradiction", f"Possible contradiction with {left.requirement_id}", contradiction_evidence.evidence_id))

        if project_root is not None:
            graph = build_traceability(requirements_path, project_root)
            evidence_by_id = {item.requirement_id: item for item in normalized}
            for insight in graph.requirements:
                requirement_evidence = evidence_by_id.get(insight.requirement.id)
                parent = next((item for item in evidence if item.requirement_id == insight.requirement.id and item.kind == "normalized_requirement"), None)
                if insight.source_locations:
                    for location in insight.source_locations:
                        link_evidence = self._evidence(run_id, "traceability_candidate", "Explicit source marker maps requirement to source", insight.requirement.id, {"path": str(location.path), "line": location.line}, input_hash)
                        evidence.append(link_evidence)
                        links.append(TraceabilityLink(self._id("link", insight.requirement.id, str(location.path), str(location.line)), insight.requirement.id, f"source:{location.path}:{location.line}", "source", "explicit_marker", 1.0, (link_evidence.evidence_id,)))
                if insight.test_locations:
                    for path in insight.test_locations:
                        link_evidence = self._evidence(run_id, "traceability_candidate", "Requirement text or ID appears in test source", insight.requirement.id, {"path": str(path)}, input_hash)
                        evidence.append(link_evidence)
                        links.append(TraceabilityLink(self._id("link", insight.requirement.id, str(path)), insight.requirement.id, f"test:{path}", "test", "heuristic_text_match", 0.5, (link_evidence.evidence_id,)))
                if not insight.source_locations:
                    gap_evidence = self._evidence(run_id, "traceability_gap", "No explicit source location was found", insight.requirement.id, {}, input_hash)
                    evidence.append(gap_evidence)
                    findings.append(self._finding(run_id, insight.requirement.id, "traceability_gap", "Requirement has no mapped source location", gap_evidence.evidence_id))

        return RequirementIntelligenceResult(tuple(normalized), tuple(findings), tuple(evidence), tuple(links), tuple(contracts))

    @classmethod
    def _contradictory(cls, left: str, right: str) -> bool:
        left_lower, right_lower = left.lower(), right.lower()
        opposing = (("must not" in left_lower and "must" in right_lower and "must not" not in right_lower), ("must not" in right_lower and "must" in left_lower and "must not" not in left_lower), ("cannot" in left_lower and "must" in right_lower), ("cannot" in right_lower and "must" in left_lower))
        if not any(opposing):
            return False
        left_terms = set(re.findall(r"[a-z]{5,}", left_lower))
        right_terms = set(re.findall(r"[a-z]{5,}", right_lower))
        return len((left_terms & right_terms) - {"cannot", "must"}) >= 1
