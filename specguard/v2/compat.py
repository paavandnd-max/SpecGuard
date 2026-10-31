from __future__ import annotations

import hashlib
import time
import uuid
from pathlib import Path

from ..models import AnalysisReport, Classification, Requirement as LegacyRequirement
from .models import (
    ComplianceStatus,
    EvaluationRun,
    Evidence,
    EvidenceStatus,
    Finding,
    ReproducibilityMetadata,
    RunPolicy,
    RunStatus,
    TestEffectiveness,
    VerificationMode,
)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}-{digest}"


def legacy_requirement(requirement: LegacyRequirement):
    from .models import RequirementV2

    return RequirementV2(
        requirement_id=requirement.id,
        normalized_text=" ".join(requirement.text.split()),
        source_text=requirement.text,
        source_hint=requirement.source_hint,
    )


def legacy_report_to_v2(report: AnalysisReport, project_id: str = "legacy-project", run_id: str | None = None) -> tuple[EvaluationRun, list[Finding], list[Evidence]]:
    """Wrap v1 mutation results without changing the original report object."""
    run_id = run_id or uuid.uuid4().hex
    policy = RunPolicy(policy_id="legacy-v1-policy", provider="offline", execution_mode="unknown")
    reproducibility = ReproducibilityMetadata(
        input_hashes={"project": hashlib.sha256(report.project.encode("utf-8")).hexdigest()},
        provider="legacy-v1",
        execution_policy_id=policy.policy_id,
    )
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for result in report.results:
        evidence_id = _stable_id("evidence", run_id, result.requirement.id, result.classification.value, result.test_output)
        finding_id = _stable_id("finding", run_id, result.requirement.id, result.classification.value)
        if not report.baseline_passed or result.classification == Classification.INCONCLUSIVE:
            evidence_status = EvidenceStatus.INCONCLUSIVE
            effectiveness = TestEffectiveness.INCONCLUSIVE
        elif result.classification == Classification.PROTECTED:
            evidence_status = EvidenceStatus.VERIFIED
            effectiveness = TestEffectiveness.DETECTED
        elif result.classification == Classification.UNPROTECTED:
            evidence_status = EvidenceStatus.VERIFIED
            effectiveness = TestEffectiveness.SURVIVED
        else:
            evidence_status = EvidenceStatus.INCONCLUSIVE
            effectiveness = TestEffectiveness.NOT_EVALUATED
        evidence.append(Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            kind="legacy_mutation_result",
            status=evidence_status,
            claim=result.reason or result.description,
            requirement_id=result.requirement.id,
            source_spans=tuple(({"path": str(result.source.path), "line": result.source.line} for _ in [0])) if result.source else (),
            output_hash=hashlib.sha256(result.test_output.encode("utf-8")).hexdigest() if result.test_output else None,
            execution_context={"returncode": result.test_returncode, "attempt": result.attempt, "equivalent": result.equivalent},
            reproducibility=reproducibility,
            details={"legacy_classification": result.classification.value, "description": result.description},
        ))
        findings.append(Finding(
            finding_id=finding_id,
            requirement_id=result.requirement.id,
            category="mutation_test_effectiveness",
            severity="info" if effectiveness in {TestEffectiveness.DETECTED, TestEffectiveness.SURVIVED} else "unknown",
            verdict=result.classification.value,
            compliance_status=ComplianceStatus.UNKNOWN,
            test_effectiveness_status=effectiveness,
            verification_mode=VerificationMode.MUTATION,
            message=result.reason or result.description,
            evidence_ids=(evidence_id,),
        ))
    run = EvaluationRun(
        run_id=run_id,
        project_id=project_id,
        revision_id=None,
        policy=policy,
        status=RunStatus.COMPLETED if report.baseline_passed else RunStatus.INCONCLUSIVE,
        started_at=time.time(),
        finished_at=time.time(),
        finding_ids=tuple(item.finding_id for item in findings),
        evidence_ids=tuple(item.evidence_id for item in evidence),
        counts=report.counts(),
        error=None if report.baseline_passed else "Legacy baseline did not pass",
        reproducibility=reproducibility,
    )
    return run, findings, evidence
