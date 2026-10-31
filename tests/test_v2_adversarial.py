from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from specguard.secure_execution import ExecutionPolicy
from specguard.v2 import (
    AdversarialTestingEngine,
    BehavioralVerdict,
    EvidenceStatus,
    ExpectedBehaviorService,
    MutationOperatorKind,
    MutationTarget,
    MutationVerdict,
    RequirementV2,
    SQLiteEvidenceStore,
    TraceabilityLink,
)
from specguard.v2.adversarial import MutationCandidate, PythonMutationOperatorSet


def _target(path: Path, line: int | None = None) -> MutationTarget:
    return MutationTarget("REQ-001", "ready", path, None, line)


def test_python_operator_set_covers_supported_operator_families(tmp_path):
    path = tmp_path / "service.py"
    source = """\ndef check(a, b, amount):
    if a and b:
        if amount <= 0:
            raise ValueError('bad')
    value = amount + 1
    try:
        return value
    except ValueError:
        return 0
"""
    path.write_text(source)
    candidates = PythonMutationOperatorSet.generate(source, path, _target(path))
    operators = {item.operator for item in candidates}
    assert MutationOperatorKind.COMPARISON_BOUNDARY in operators
    assert MutationOperatorKind.BOOLEAN_LOGIC in operators
    assert MutationOperatorKind.ARITHMETIC in operators
    assert MutationOperatorKind.RETURN_VALUE in operators
    assert MutationOperatorKind.INPUT_VALIDATION in operators
    assert MutationOperatorKind.EXCEPTION_HANDLING in operators


def test_targeting_requires_determinate_oracle_and_traceability(tmp_path):
    path = tmp_path / "service.py"
    path.write_text("def check(value):\n    return value\n")
    uncertain = RequirementV2("REQ-001", "The service may respond soon.", "The service may respond soon.", ambiguous=True, ambiguity_reasons=("vague",))
    uncertain_contract, _ = ExpectedBehaviorService().derive(uncertain, "run")
    result = AdversarialTestingEngine().run(tmp_path, (uncertain,), (uncertain_contract,), (), (), run_id="uncertain")
    assert result.run.status == "inconclusive"
    assert result.targeting.targets[0].status == "unsupported"
    assert not result.mutants

    determinate = RequirementV2("REQ-002", "Value must be positive.", "Value must be positive.")
    contract, _ = ExpectedBehaviorService().derive(determinate, "run")
    no_trace = AdversarialTestingEngine().run(tmp_path, (determinate,), (contract,), (), (), run_id="no-trace")
    assert no_trace.targeting.targets[0].status == "inconclusive"


def test_baseline_failure_fails_closed_without_mutants(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_ok.py").write_text("def test_ok(): pass\n")
    (tmp_path / "service.py").write_text("def check(value):\n    return value\n")
    requirement = RequirementV2("REQ-001", "Value must be positive.", "Value must be positive.", source_hint="service.py")
    contract, _ = ExpectedBehaviorService().derive(requirement, "run")
    source_link = TraceabilityLink("link", "REQ-001", "source:service.py:1", "source", "implemented_by", "explicit_marker", 1.0)

    class FailingRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id):
            return SimpleNamespace(status="failed_test", stdout="baseline failed", stderr="", returncode=1)

    import specguard.v2.adversarial as adversarial
    original = adversarial.BaselineRunner
    adversarial.BaselineRunner = FailingRunner
    try:
        result = AdversarialTestingEngine(policy=ExecutionPolicy(docker_image="approved"), max_mutants_per_requirement=1).run(tmp_path, (requirement,), (contract,), (source_link,), (), run_id="baseline-fail")
    finally:
        adversarial.BaselineRunner = original
    assert result.run.status == "inconclusive"
    assert not result.mutants
    assert "Baseline status failed_test" in result.run.summaries[0].reason


def test_engine_fails_closed_when_docker_is_unconfigured(tmp_path):
    (tmp_path / "service.py").write_text("def check(value):\n    return value\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_check.py").write_text("def test_check(): pass\n")
    requirement = RequirementV2("REQ-001", "Value must be positive.", "Value must be positive.", source_hint="service.py")
    contract, _ = ExpectedBehaviorService().derive(requirement, "run")
    link = TraceabilityLink("link", "REQ-001", "source:service.py:1", "source", "implemented_by", "explicit_marker", 1.0)
    result = AdversarialTestingEngine().run(tmp_path, (requirement,), (contract,), (link,), (), run_id="no-docker-image")
    assert result.run.baseline_status == "inconclusive"
    assert not result.mutants


def test_non_python_projects_are_explicitly_unsupported(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"node test.js"}}')
    (tmp_path / "index.js").write_text("module.exports = 1;\n")
    requirement = RequirementV2("REQ-001", "Value must be positive.", "Value must be positive.", source_hint="index.js")
    contract, _ = ExpectedBehaviorService().derive(requirement, "run")
    result = AdversarialTestingEngine().run(tmp_path, (requirement,), (contract,), (), (), run_id="javascript")
    assert result.run.baseline_status == "unsupported"
    assert result.targeting.targets[0].status == "unsupported"
    assert not result.mutants


def test_killed_survived_scores_persist_and_cleanup(tmp_path):
    source_file = tmp_path / "service.py"
    source_file.write_text("def check(amount):\n    if amount <= 0:\n        raise ValueError('bad')\n    return amount\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_check.py").write_text("def test_check(): pass\n")
    requirement = RequirementV2("REQ-001", "Value must be positive.", "Value must be positive.", source_hint="service.py")
    contract, _ = ExpectedBehaviorService().derive(requirement, "run")
    link = TraceabilityLink("link", "REQ-001", "source:service.py:2", "source", "implemented_by", "explicit_marker", 1.0)
    store = SQLiteEvidenceStore(tmp_path / "evidence.db")
    seen_paths: list[Path] = []

    class PassingOrKillingRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id):
            root = Path(root)
            seen_paths.append(root)
            if "< 0" in (root / "service.py").read_text():
                return SimpleNamespace(status="failed_test", stdout="killed", stderr="", returncode=1)
            return SimpleNamespace(status="passed", stdout="passed", stderr="", returncode=0)

    import specguard.v2.adversarial as adversarial
    original = adversarial.BaselineRunner
    adversarial.BaselineRunner = PassingOrKillingRunner
    try:
        result = AdversarialTestingEngine(policy=ExecutionPolicy(docker_image="approved"), store=store, max_mutants_per_requirement=2, retry_limit=0).run(tmp_path, (requirement,), (contract,), (link,), (), run_id="persisted")
    finally:
        adversarial.BaselineRunner = original
    assert {item.verdict for item in result.mutants} >= {MutationVerdict.KILLED, MutationVerdict.SURVIVED}
    summary = result.run.summaries[0]
    assert summary.score is not None
    assert summary.complete is True
    assert all(not path.exists() for path in seen_paths[1:])
    assert store.get_mutation_run("persisted") == result.run
    assert len(store.list_mutants("persisted")) == len(result.mutants)
    store.close()
    reopened = SQLiteEvidenceStore(tmp_path / "evidence.db")
    assert reopened.get_mutation_run("persisted") == result.run
    assert reopened.get_mutant(result.mutants[0].mutant_id) == result.mutants[0]
    reopened.close()


def test_equivalent_and_invalid_mutants_are_not_counted_as_effective(tmp_path):
    source_file = tmp_path / "service.py"
    source_file.write_text("def check(value):\n    return value\n")
    engine = AdversarialTestingEngine(policy=ExecutionPolicy(docker_image="approved"), retry_limit=0)
    equivalent = MutationCandidate("REQ-001", MutationOperatorKind.RETURN_VALUE, source_file, None, 2, 11, 2, 16, "value", "value", "no-op")
    mutant, _, _ = engine._evaluate_candidate(tmp_path, tmp_path / "work", equivalent, "equivalent")
    assert mutant.verdict == MutationVerdict.EQUIVALENT
    invalid = MutationCandidate("REQ-001", MutationOperatorKind.RETURN_VALUE, source_file, None, 2, 11, 2, 16, "changed", "None", "stale span")
    invalid_mutant, _, _ = engine._evaluate_candidate(tmp_path, tmp_path / "work2", invalid, "invalid")
    assert invalid_mutant.verdict == MutationVerdict.INVALID
    summary = engine._summary("REQ-001", [MutationVerdict.EQUIVALENT, MutationVerdict.INVALID])
    assert summary.score is None
    assert summary.complete is False


def test_inconclusive_mutant_retries_once_then_classifies(tmp_path):
    (tmp_path / "service.py").write_text("def check(value):\n    if value <= 0:\n        raise ValueError('bad')\n    return value\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_check.py").write_text("def test_check(): pass\n")
    requirement = RequirementV2("REQ-001", "Value must be positive.", "Value must be positive.", source_hint="service.py")
    contract, _ = ExpectedBehaviorService().derive(requirement, "run")
    link = TraceabilityLink("link", "REQ-001", "source:service.py:2", "source", "implemented_by", "explicit_marker", 1.0)
    calls = 0

    class RetryRunner:
        def __init__(self, policy, store=None):
            pass

        def run(self, root, run_id):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(status="passed", stdout="", stderr="", returncode=0)
            if calls == 2:
                return SimpleNamespace(status="inconclusive", stdout="", stderr="timeout", returncode=None)
            return SimpleNamespace(status="passed", stdout="", stderr="", returncode=0)

    import specguard.v2.adversarial as adversarial
    original = adversarial.BaselineRunner
    adversarial.BaselineRunner = RetryRunner
    try:
        result = AdversarialTestingEngine(policy=ExecutionPolicy(docker_image="approved"), max_mutants_per_requirement=1, retry_limit=1).run(tmp_path, (requirement,), (contract,), (link,), (), run_id="retry")
    finally:
        adversarial.BaselineRunner = original
    assert result.mutants[0].verdict == MutationVerdict.SURVIVED
    assert result.mutants[0].attempt == 2
