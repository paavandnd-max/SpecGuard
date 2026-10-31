from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from specguard.secure_execution import ExecutionPolicy
from specguard.v2 import (
    AutonomousTestEngineeringEngine,
    CandidateValidation,
    ExpectedBehaviorService,
    MutationOperatorKind,
    MutationPatch,
    MutationRun,
    MutationVerdict,
    Mutant,
    RequirementV2,
    SQLiteEvidenceStore,
    TestCandidateStatus as CandidateStatus,
)


def mutation_fixture(requirement_id: str = "REQ-001", verdict: MutationVerdict = MutationVerdict.SURVIVED) -> tuple[RequirementV2, object, MutationRun, Mutant]:
    requirement = RequirementV2(requirement_id, "Value must be positive.", "Value must be positive.", source_hint="service.py")
    contract, oracle_evidence = ExpectedBehaviorService().derive(requirement, "oracle")
    patch = MutationPatch("patch-1", "service.py", 2, 7, 2, 18, "amount <= 0", "amount < 0", MutationOperatorKind.COMPARISON_BOUNDARY, "source-hash", "mutated-hash")
    mutant = Mutant("mutant-1", "mutation-run", requirement_id, patch, verdict, True, "traceability", 1, (oracle_evidence.evidence_id,))
    run = MutationRun("mutation-run", "project", "passed", "completed", (mutant.mutant_id,), (oracle_evidence.evidence_id,), {verdict.value: 1}, (), error=None)
    return requirement, contract, run, mutant


def test_gap_analysis_blocks_uncertain_oracle_and_ignores_invalid_denominator(tmp_path):
    requirement, contract, mutation_run, mutant = mutation_fixture()
    engine = AutonomousTestEngineeringEngine()
    result = engine.run(tmp_path, (requirement,), (contract,), mutation_run, (mutant,), run_id="gap")
    assert result.gaps[0].status == "gap"
    assert result.candidates[0].status == CandidateStatus.BLOCKED
    assert not result.validations

    uncertain = RequirementV2("REQ-002", "The value may be okay soon.", "The value may be okay soon.", ambiguous=True, ambiguity_reasons=("vague",))
    uncertain_contract, _ = ExpectedBehaviorService().derive(uncertain, "oracle")
    result_uncertain = engine.run(tmp_path, (uncertain,), (uncertain_contract,), mutation_run, (), run_id="blocked")
    assert result_uncertain.gaps[0].status == "blocked"
    assert not result_uncertain.candidates


def test_deterministic_candidate_validation_requires_original_pass_and_mutant_detection(tmp_path):
    requirement, contract, mutation_run, mutant = mutation_fixture()
    (tmp_path / "service.py").write_text("def check(amount):\n    if amount <= 0:\n        raise ValueError('bad')\n    return amount\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_existing.py").write_text("def test_existing(): pass\n")
    profile = {
        "module": "service",
        "imports": ["from service import check"],
        "action": "value = 0",
        "assertion": "with self.assertRaises(ValueError):\n            check(0)",
    }
    calls = 0

    class FakeRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id, *args):
            nonlocal calls
            calls += 1
            text = (Path(root) / "service.py").read_text()
            return SimpleNamespace(status="failed_test" if "< 0" in text else "passed", stdout="", stderr="", returncode=1 if "< 0" in text else 0)

    import specguard.v2.test_engineering as engineering
    original = engineering.BaselineRunner
    engineering.BaselineRunner = FakeRunner
    try:
        result = AutonomousTestEngineeringEngine(policy=ExecutionPolicy(docker_image="approved")).run(tmp_path, (requirement,), (contract,), mutation_run, (mutant,), {requirement.requirement_id: profile}, run_id="validated")
    finally:
        engineering.BaselineRunner = original
    assert result.candidates[0].status == CandidateStatus.VALIDATED
    assert result.validations[0].detected_mutant_ids == (mutant.mutant_id,)
    assert calls == 2


def test_candidate_rejects_original_failure_and_no_detection(tmp_path):
    requirement, contract, mutation_run, mutant = mutation_fixture()
    (tmp_path / "service.py").write_text("def check(amount):\n    if amount <= 0:\n        raise ValueError('bad')\n    return amount\n")
    profile = {"module": "service", "imports": ["from service import check"], "action": "check(1)", "assertion": "self.assertEqual(1, 1)"}

    class OriginalFailRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id, *args):
            return SimpleNamespace(status="failed_test", stdout="unrelated failure", stderr="", returncode=1)

    import specguard.v2.test_engineering as engineering
    original = engineering.BaselineRunner
    engineering.BaselineRunner = OriginalFailRunner
    try:
        result = AutonomousTestEngineeringEngine(policy=ExecutionPolicy(docker_image="approved")).run(tmp_path, (requirement,), (contract,), mutation_run, (mutant,), {requirement.requirement_id: profile}, run_id="original-fail")
    finally:
        engineering.BaselineRunner = original
    assert result.candidates[0].status == CandidateStatus.REJECTED
    assert result.validations[0].original_status == "failed_test"

    class AlwaysPassingRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id, *args):
            return SimpleNamespace(status="passed", stdout="", stderr="", returncode=0)

    engineering.BaselineRunner = AlwaysPassingRunner
    try:
        no_detection = AutonomousTestEngineeringEngine(policy=ExecutionPolicy(docker_image="approved")).run(tmp_path, (requirement,), (contract,), mutation_run, (mutant,), {requirement.requirement_id: profile}, run_id="no-detection")
    finally:
        engineering.BaselineRunner = original
    assert no_detection.candidates[0].status == CandidateStatus.REJECTED
    assert no_detection.validations[0].detected_mutant_ids == ()


def test_candidate_generation_is_stable_and_export_does_not_overwrite_original(tmp_path):
    requirement, contract, mutation_run, mutant = mutation_fixture()
    engine = AutonomousTestEngineeringEngine()
    profile = {"module": "service", "imports": ["from service import check"], "action": "check(1)", "assertion": "self.assertEqual(1, 1)"}
    first = engine._generate_candidate(requirement, contract, (mutant,), profile, "stable")
    second = engine._generate_candidate(requirement, contract, (mutant,), profile, "stable")
    assert first == second
    original = tmp_path / "user_test.py"
    original.write_text("original\n")
    exported = engine.export_candidate(first, tmp_path / "exports")
    assert exported.read_text() == first.content
    assert original.read_text() == "original\n"


def test_sqlite_candidate_and_validation_restart_round_trip(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "phase5.db")
    validation = CandidateValidation("validation-1", "run", "candidate-1", CandidateStatus.INCONCLUSIVE, "passed", "inconclusive", details={"reason": "timeout"})
    store.save_validation(validation)
    assert store.get_validation(validation.validation_id) == validation
    store.close()
    reopened = SQLiteEvidenceStore(tmp_path / "phase5.db")
    assert reopened.get_validation(validation.validation_id) == validation
    reopened.close()


def test_sandbox_unavailable_is_inconclusive_not_host_execution(tmp_path):
    requirement, contract, mutation_run, mutant = mutation_fixture()
    profile = {"module": "service", "imports": ["from service import check"], "action": "check(1)", "assertion": "self.assertEqual(1, 1)"}
    result = AutonomousTestEngineeringEngine(policy=ExecutionPolicy(docker_image=None)).run(tmp_path, (requirement,), (contract,), mutation_run, (mutant,), {requirement.requirement_id: profile}, run_id="unavailable")
    assert result.candidates[0].status == CandidateStatus.INCONCLUSIVE
    assert result.validations[0].original_status == "inconclusive"
    assert result.run.status == "inconclusive"
