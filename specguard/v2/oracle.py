from __future__ import annotations

import hashlib
import re

from .models import Evidence, EvidenceStatus, ExpectedBehaviorContract, ReproducibilityMetadata, RequirementV2


class ExpectedBehaviorService:
    """Deterministic shared oracle builder; it never invents unstated behavior."""

    version = "deterministic-v1"

    def derive(self, requirement: RequirementV2, run_id: str = "oracle") -> tuple[ExpectedBehaviorContract, Evidence]:
        text = requirement.normalized_text.strip()
        lower = text.lower()
        preconditions: list[str] = []
        postconditions: list[str] = []
        uncertainty: list[str] = []
        if re.search(r"\bonly\s+[^.]+", text, flags=re.I):
            preconditions.append(re.search(r"(only\s+[^.]+)", text, flags=re.I).group(1))
        if re.search(r"\bif\b|\bwhen\b|\bafter\b", text, flags=re.I):
            preconditions.append("conditional context is present in requirement text")
        if re.search(r"\bmust\b|\bshall\b|\bcannot\b|\brequired\b|\bstarts\b", text, flags=re.I):
            postconditions.append(text)
        else:
            uncertainty.append("No explicit normative outcome was recognized")
        if requirement.ambiguous:
            uncertainty.extend(requirement.ambiguity_reasons)
        if not postconditions:
            uncertainty.append("Expected postcondition requires review")
        contract_id = "oracle-" + hashlib.sha256(f"{requirement.requirement_id}:{text}".encode()).hexdigest()[:20]
        evidence_id = "evidence-" + hashlib.sha256(f"{run_id}:{contract_id}".encode()).hexdigest()[:20]
        evidence = Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            kind="expected_behavior_extraction",
            status=EvidenceStatus.OBSERVED,
            claim="Deterministic behavioral contract extracted from normalized requirement text",
            requirement_id=requirement.requirement_id,
            input_hashes={"requirement_text": hashlib.sha256(text.encode()).hexdigest()},
            reproducibility=ReproducibilityMetadata(oracle_version=self.version, input_hashes={"requirement_text": hashlib.sha256(text.encode()).hexdigest()}),
            details={"preconditions": preconditions, "actions": [text], "postconditions": postconditions, "uncertainty": uncertainty},
        )
        contract = ExpectedBehaviorContract(
            contract_id=contract_id,
            requirement_id=requirement.requirement_id,
            preconditions=tuple(preconditions),
            actions=(text,),
            postconditions=tuple(postconditions),
            uncertainty=tuple(uncertainty),
            evidence_ids=(evidence_id,),
            oracle_version=self.version,
        )
        return contract, evidence
