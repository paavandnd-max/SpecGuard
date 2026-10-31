from __future__ import annotations

import ast
import hashlib
import re
import shutil
import tempfile
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..secure_execution import ExecutionPolicy
from .adversarial import MutationCandidate, _apply_text_patch, _copy_project_safely
from .behavioral import BaselineRunner, TestDiscovery
from .evidence_store import EvidenceStore, InMemoryEvidenceStore
from .models import (
    CandidateValidation,
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    ExpectedBehaviorContract,
    Finding,
    Mutant,
    MutationRun,
    MutationVerdict,
    ReproducibilityMetadata,
    RequirementMutationSummary,
    RequirementV2,
    TestCandidate,
    TestCandidateStatus,
    TestEffectiveness,
    TestEngineeringRun,
    VerificationGap,
    VerificationMode,
)


@dataclass(frozen=True)
class TestEngineeringResult:
    run: TestEngineeringRun
    gaps: tuple[VerificationGap, ...]
    candidates: tuple[TestCandidate, ...]
    validations: tuple[CandidateValidation, ...]
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.to_dict(),
            "gaps": [item.to_dict() for item in self.gaps],
            "candidates": [item.to_dict() for item in self.candidates],
            "validations": [item.to_dict() for item in self.validations],
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [item.to_dict() for item in self.findings],
        }


class AutonomousTestEngineeringEngine:
    """Deterministic Phase 5 candidate generation and Docker validation."""

    version = "test-engineering-v1"
    _module_name = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")

    def __init__(self, policy: ExecutionPolicy | None = None, store: EvidenceStore | None = None):
        self.policy = policy or ExecutionPolicy()
        self.store = store or InMemoryEvidenceStore()

    def run(
        self,
        project_root: str | Path,
        requirements: tuple[RequirementV2, ...],
        contracts: tuple[ExpectedBehaviorContract, ...],
        mutation_run: MutationRun,
        mutants: tuple[Mutant, ...] | None = None,
        invocation_profiles: dict[str, dict[str, Any]] | None = None,
        run_id: str = "test-engineering-run",
    ) -> TestEngineeringResult:
        root = Path(project_root).resolve()
        mutants = mutants or tuple(self.store.list_mutants(mutation_run.run_id))
        profiles = invocation_profiles or {}
        contract_by_id = {item.requirement_id: item for item in contracts}
        requirement_by_id = {item.requirement_id: item for item in requirements}
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        gaps: list[VerificationGap] = []
        candidates: list[TestCandidate] = []
        validations: list[CandidateValidation] = []

        for requirement in requirements:
            contract = contract_by_id.get(requirement.requirement_id)
            relevant = [item for item in mutants if item.requirement_id == requirement.requirement_id and item.relevant]
            gap = self._gap_for(requirement, contract, relevant, mutation_run, run_id)
            gaps.append(gap)
            gap_evidence = self._gap_evidence(gap, contract)
            evidence.append(gap_evidence)
            self.store.save_gap(gap)
            self.store.save_evidence(gap_evidence)
            gap_finding = Finding(
                self._stable("finding", run_id, "gap", requirement.requirement_id),
                requirement.requirement_id,
                "test_effectiveness_gap",
                "warning" if gap.status in {"gap", "blocked"} else "info",
                gap.status,
                ComplianceStatus.UNKNOWN,
                TestEffectiveness.SURVIVED if gap.survived else TestEffectiveness.NOT_EVALUATED,
                VerificationMode.MUTATION,
                gap.reason or f"Requirement gap status: {gap.status}",
                (gap_evidence.evidence_id,),
            )
            findings.append(gap_finding)
            self.store.save_finding(gap_finding)
            if gap.status != "gap":
                continue
            target_mutants = tuple(item for item in relevant if item.verdict == MutationVerdict.SURVIVED)
            candidate = self._generate_candidate(requirement, contract, target_mutants, profiles.get(requirement.requirement_id), run_id)
            candidates.append(candidate)
            candidate_evidence = self._candidate_evidence(candidate, contract)
            evidence.append(candidate_evidence)
            candidate = replace(candidate, evidence_ids=(candidate_evidence.evidence_id,))
            self.store.save_candidate(candidate)
            self.store.save_evidence(candidate_evidence)
            if candidate.status != TestCandidateStatus.PROPOSED:
                continue
            validation = self._validate_candidate(root, candidate, target_mutants, run_id)
            validations.append(validation)
            validation_evidence = self._validation_evidence(validation)
            evidence.append(validation_evidence)
            validation = replace(validation, evidence_ids=(validation_evidence.evidence_id,))
            self.store.save_validation(validation)
            self.store.save_evidence(validation_evidence)
            final_candidate = replace(candidate, status=validation.status, evidence_ids=(candidate_evidence.evidence_id, validation_evidence.evidence_id), details={**candidate.details, "validation_id": validation.validation_id})
            candidates[-1] = final_candidate
            self.store.save_candidate(final_candidate)
            validation_finding = Finding(
                self._stable("finding", run_id, "candidate", candidate.candidate_id),
                candidate.requirement_id,
                "autonomous_test_candidate",
                "info" if validation.status == TestCandidateStatus.VALIDATED else "warning",
                validation.status.value,
                ComplianceStatus.UNKNOWN,
                TestEffectiveness.DETECTED if validation.detected_mutant_ids else TestEffectiveness.INCONCLUSIVE,
                VerificationMode.GENERATED_TEST,
                f"Candidate {candidate.candidate_id}: {validation.details.get('reason', validation.status.value)}",
                (validation_evidence.evidence_id,),
                metadata={"candidate_id": candidate.candidate_id, "targeted_mutant_ids": list(candidate.targeted_mutant_ids)},
            )
            findings.append(validation_finding)
            self.store.save_finding(validation_finding)

        counts = {status.value: sum(item.status == status for item in candidates) for status in TestCandidateStatus}
        run_status = "inconclusive" if any(item.status in {"inconclusive", "blocked"} for item in gaps) or any(item.status in {TestCandidateStatus.INCONCLUSIVE, TestCandidateStatus.BLOCKED, TestCandidateStatus.PROPOSED} for item in candidates) else "completed"
        engineering_run = TestEngineeringRun(
            run_id=run_id,
            project_id=str(root),
            status=run_status,
            gap_ids=tuple(item.gap_id for item in gaps),
            candidate_ids=tuple(item.candidate_id for item in candidates),
            validation_ids=tuple(item.validation_id for item in validations),
            evidence_ids=tuple(item.evidence_id for item in evidence),
            counts=counts,
            reproducibility=ReproducibilityMetadata(parser_version=self.version, execution_policy_id=self.policy.docker_image or "unconfigured", image_digest=self.policy.docker_image, network_policy=self.policy.network, resource_policy={"timeout_seconds": self.policy.timeout_seconds, "memory_mb": self.policy.memory_mb, "cpu_count": self.policy.cpu_count, "pids_limit": self.policy.pids_limit}),
            error=None,
        )
        self.store.save_test_engineering_run(engineering_run)
        return TestEngineeringResult(engineering_run, tuple(gaps), tuple(candidates), tuple(validations), tuple(evidence), tuple(findings))

    def _gap_for(self, requirement: RequirementV2, contract: ExpectedBehaviorContract | None, mutants: list[Mutant], mutation_run: MutationRun, run_id: str) -> VerificationGap:
        valid = [item for item in mutants if item.verdict in {MutationVerdict.KILLED, MutationVerdict.SURVIVED}]
        killed = sum(item.verdict == MutationVerdict.KILLED for item in valid)
        survived = sum(item.verdict == MutationVerdict.SURVIVED for item in valid)
        reason = ""
        if contract is None:
            status, reason = "blocked", "No expected-behavior contract is available"
        elif contract.uncertainty:
            status, reason = "blocked", "Oracle contract is uncertain; no assertion may be invented"
        elif mutation_run.status != "completed":
            status, reason = "inconclusive", "Mutation run is incomplete; effectiveness evidence is not complete"
        elif survived:
            status, reason = "gap", "A valid relevant mutant survived; this indicates test weakness only"
        elif killed:
            status, reason = "protected", "All valid relevant mutants were detected"
        else:
            status, reason = "inconclusive", "No valid relevant killed/survived mutant denominator exists"
        gap_id = self._stable("gap", run_id, requirement.requirement_id, status, *(item.mutant_id for item in valid))
        return VerificationGap(gap_id, run_id, requirement.requirement_id, status, tuple(item.mutant_id for item in valid), killed, survived, reason, tuple(evidence_id for item in valid for evidence_id in item.evidence_ids))

    def _generate_candidate(self, requirement: RequirementV2, contract: ExpectedBehaviorContract | None, mutants: tuple[Mutant, ...], profile: dict[str, Any] | None, run_id: str) -> TestCandidate:
        expected = contract.postconditions if contract else ()
        source_refs = tuple(sorted({item.patch.file_path for item in mutants}))
        target_ids = tuple(item.mutant_id for item in mutants)
        status = TestCandidateStatus.PROPOSED
        reason = "Explicit invocation profile is required for executable deterministic generation"
        content = ""
        if contract is None or contract.uncertainty:
            status = TestCandidateStatus.BLOCKED
            reason = "Oracle uncertainty blocks assertion generation"
        elif not profile:
            status = TestCandidateStatus.BLOCKED
        else:
            try:
                content = self._render_candidate(requirement, profile)
                ast.parse(content, filename=f"test_{requirement.requirement_id}.py")
            except (KeyError, TypeError, ValueError, SyntaxError) as exc:
                status = TestCandidateStatus.BLOCKED
                reason = f"Invocation profile is invalid: {exc}"
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        candidate_id = self._stable("candidate", requirement.requirement_id, content_hash, *target_ids)
        return TestCandidate(candidate_id, run_id, requirement.requirement_id, status, content, content_hash, target_ids, source_refs, "deterministic_invocation_profile", tuple(expected), 0.8 if status == TestCandidateStatus.PROPOSED else 0.0, (), {"reason": reason, "profile_supplied": bool(profile)})

    def _render_candidate(self, requirement: RequirementV2, profile: dict[str, Any]) -> str:
        module = str(profile.get("module", ""))
        if not self._module_name.fullmatch(module):
            raise ValueError("module must be a Python module name")
        imports = profile.get("imports", ())
        if isinstance(imports, str):
            imports = (imports,)
        if not isinstance(imports, (list, tuple)) or not all(isinstance(item, str) and item.strip() for item in imports):
            raise ValueError("imports must be non-empty source lines")
        setup = str(profile.get("setup", "")).strip()
        action = str(profile.get("action", "")).strip()
        assertion = str(profile.get("assertion", "")).strip()
        if not action or not assertion:
            raise ValueError("action and assertion are required")
        class_name = "TestSpecGuard" + re.sub(r"\W+", "_", requirement.requirement_id)
        body = "\n".join(["import unittest", *imports, "", f"class {class_name}(unittest.TestCase):", "    def test_requirement(self):", textwrap.indent(setup, "        ") if setup else "        pass", textwrap.indent(action, "        "), textwrap.indent(assertion, "        "), ""])
        return body

    def _validate_candidate(self, root: Path, candidate: TestCandidate, mutants: tuple[Mutant, ...], run_id: str) -> CandidateValidation:
        validation_id = self._stable("validation", run_id, candidate.candidate_id)
        if not candidate.content:
            return CandidateValidation(validation_id, run_id, candidate.candidate_id, TestCandidateStatus.BLOCKED, "not_run", "not_run", (), (), {"reason": "Candidate has no executable content"})
        detected: list[str] = []
        original_status = "inconclusive"
        mutant_status = "not_run"
        try:
            with tempfile.TemporaryDirectory(prefix=f"specguard-candidate-{candidate.candidate_id}-") as temp_name:
                temp_root = Path(temp_name) / "original"
                _copy_project_safely(root, temp_root)
                self._write_candidate(temp_root, candidate)
                discovery = TestDiscovery().discover(temp_root)
                if discovery.status != "ready":
                    return CandidateValidation(validation_id, run_id, candidate.candidate_id, TestCandidateStatus.INCONCLUSIVE, discovery.status, "not_run", (), (), {"reason": "Generated candidate was not statically discoverable", "discovery": discovery.__dict__})
                original = self._run_generated(temp_root, candidate, f"{run_id}:{candidate.candidate_id}:original")
                original_status = original.status
                if original.status != "passed":
                    status = TestCandidateStatus.REJECTED if original.status == "failed_test" else TestCandidateStatus.INCONCLUSIVE
                    return CandidateValidation(validation_id, run_id, candidate.candidate_id, status, original.status, "not_run", (), (), {"reason": "Candidate does not pass the original implementation", "stdout": original.stdout, "stderr": original.stderr})
                for mutant in mutants:
                    mutant_root = Path(temp_name) / f"mutant-{mutant.mutant_id}"
                    _copy_project_safely(root, mutant_root)
                    self._write_candidate(mutant_root, candidate)
                    self._apply_mutant(mutant_root, mutant)
                    execution = self._run_generated(mutant_root, candidate, f"{run_id}:{candidate.candidate_id}:{mutant.mutant_id}")
                    mutant_status = execution.status
                    if execution.status == "failed_test":
                        detected.append(mutant.mutant_id)
                    elif execution.status in {"inconclusive", "execution_error"}:
                        return CandidateValidation(validation_id, run_id, candidate.candidate_id, TestCandidateStatus.INCONCLUSIVE, original.status, execution.status, tuple(detected), (), {"reason": "Mutant validation execution was incomplete", "mutant_id": mutant.mutant_id, "stderr": execution.stderr})
                    shutil.rmtree(mutant_root, ignore_errors=True)
        except (OSError, ValueError, SyntaxError) as exc:
            return CandidateValidation(validation_id, run_id, candidate.candidate_id, TestCandidateStatus.INCONCLUSIVE, original_status, mutant_status, tuple(detected), (), {"reason": f"Validation setup failed: {exc}"})
        if detected and len(detected) == len(mutants):
            status = TestCandidateStatus.VALIDATED
            reason = "Candidate passed the original and detected every targeted mutant"
        elif detected:
            status = TestCandidateStatus.INCONCLUSIVE
            reason = "Candidate detected only a subset of targeted mutants"
        else:
            status = TestCandidateStatus.REJECTED
            reason = "Candidate passed the original but demonstrated no intended mutant detection"
        return CandidateValidation(validation_id, run_id, candidate.candidate_id, status, original_status, mutant_status, tuple(detected), (), {"reason": reason})

    @staticmethod
    def _write_candidate(root: Path, candidate: TestCandidate) -> Path:
        directory = root / "specguard_generated_tests"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "__init__.py").write_text("", encoding="utf-8")
        safe_id = candidate.candidate_id.replace("-", "_")
        path = directory / f"test_{safe_id}.py"
        path.write_text(candidate.content, encoding="utf-8")
        return path

    def _run_generated(self, root: Path, candidate: TestCandidate, run_id: str):
        module = f"specguard_generated_tests.test_{candidate.candidate_id.replace('-', '_')}"
        return BaselineRunner(self.policy, self.store).run(root, run_id, ("python", "-m", "unittest", module))

    @staticmethod
    def _apply_mutant(root: Path, mutant: Mutant) -> None:
        patch = mutant.patch
        path = (root / patch.file_path).resolve()
        path.relative_to(root.resolve())
        source = path.read_text(encoding="utf-8")
        candidate = MutationCandidate(mutant.requirement_id, patch.operator, path, patch.target_symbol_id, patch.start_line, patch.start_col, patch.end_line, patch.end_col, patch.original_text, patch.replacement_text, patch.description)
        path.write_text(_apply_text_patch(source, candidate), encoding="utf-8")

    def export_candidate(self, candidate: TestCandidate, destination: str | Path) -> Path:
        destination = Path(destination).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / f"test_{candidate.candidate_id}.py"
        if path.exists() and path.read_text(encoding="utf-8") != candidate.content:
            raise FileExistsError(f"Refusing to overwrite a different candidate: {path}")
        path.write_text(candidate.content, encoding="utf-8")
        return path

    def _gap_evidence(self, gap: VerificationGap, contract: ExpectedBehaviorContract | None) -> Evidence:
        return Evidence(self._stable("evidence", gap.run_id, gap.gap_id), gap.run_id, "verification_gap", EvidenceStatus.OBSERVED if gap.status in {"gap", "protected"} else EvidenceStatus.INCONCLUSIVE, gap.reason or f"Verification gap status: {gap.status}", requirement_id=gap.requirement_id, parent_ids=gap.evidence_ids, reproducibility=ReproducibilityMetadata(oracle_version=contract.oracle_version if contract else None, adapter_id=self.version, adapter_version=self.version, parent_evidence_ids=gap.evidence_ids), details={"status": gap.status, "killed": gap.killed, "survived": gap.survived, "valid_mutant_ids": list(gap.valid_mutant_ids)})

    def _candidate_evidence(self, candidate: TestCandidate, contract: ExpectedBehaviorContract | None) -> Evidence:
        return Evidence(self._stable("evidence", candidate.run_id, candidate.candidate_id, "generation"), candidate.run_id, "test_candidate_generation", EvidenceStatus.OBSERVED if candidate.status == TestCandidateStatus.PROPOSED else EvidenceStatus.INCONCLUSIVE, "Deterministic test candidate generated from an explicit invocation profile", requirement_id=candidate.requirement_id, parent_ids=contract.evidence_ids if contract else (), output_hash=candidate.content_hash, reproducibility=ReproducibilityMetadata(oracle_version=contract.oracle_version if contract else None, adapter_id=self.version, adapter_version=self.version, parent_evidence_ids=contract.evidence_ids if contract else ()), details={"candidate_id": candidate.candidate_id, "strategy": candidate.strategy, "status": candidate.status.value, "targeted_mutant_ids": list(candidate.targeted_mutant_ids), "expected_behavior": list(candidate.expected_behavior)})

    def _validation_evidence(self, validation: CandidateValidation) -> Evidence:
        return Evidence(self._stable("evidence", validation.run_id, validation.validation_id), validation.run_id, "test_candidate_validation", EvidenceStatus.VERIFIED if validation.status == TestCandidateStatus.VALIDATED else EvidenceStatus.INCONCLUSIVE, validation.details.get("reason", "Candidate validation completed"), parent_ids=validation.evidence_ids, reproducibility=ReproducibilityMetadata(adapter_id=self.version, adapter_version=self.version, execution_policy_id=self.policy.docker_image or "unconfigured", image_digest=self.policy.docker_image, network_policy=self.policy.network, resource_policy={"timeout_seconds": self.policy.timeout_seconds, "memory_mb": self.policy.memory_mb, "cpu_count": self.policy.cpu_count, "pids_limit": self.policy.pids_limit}), details={"candidate_id": validation.candidate_id, "original_status": validation.original_status, "mutant_status": validation.mutant_status, "detected_mutant_ids": list(validation.detected_mutant_ids)})

    @staticmethod
    def _stable(prefix: str, *parts: str) -> str:
        return f"{prefix}-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:20]
