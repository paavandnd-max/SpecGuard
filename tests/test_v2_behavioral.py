from __future__ import annotations

import subprocess
from pathlib import Path

from specguard.secure_execution import ExecutionPolicy, IsolationUnavailable
from specguard.v2 import (
    BehavioralObservation,
    BehavioralVerdict,
    ComplianceStatus,
    EvidenceStatus,
    ExpectedBehaviorService,
    RequirementV2,
    SQLiteEvidenceStore,
    TestEffectiveness as Effectiveness,
)
from specguard.v2.behavioral import BaselineRunner, BehavioralVerificationEngine, TestDiscovery


def write_unittest_project(root: Path) -> None:
    (root / "tests").mkdir()
    (root / "tests" / "__init__.py").write_text("")
    (root / "tests" / "test_behavior.py").write_text(
        "import unittest\nclass TestBehavior(unittest.TestCase):\n    def test_ok(self): self.assertTrue(True)\n"
    )


def test_discovery_is_static_and_does_not_execute_module_code(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_malicious.py").write_text("raise RuntimeError('must not execute')\ndef test_ok(): pass\n")
    discovery = TestDiscovery().discover(tmp_path)
    assert discovery.status == "ready"
    assert discovery.tests[0].name == "test_ok"


def test_discovery_marks_ambiguous_and_unsupported_frameworks(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_mixed.py").write_text("import unittest\nimport pytest\ndef test_ok(): pass\n")
    mixed = TestDiscovery().discover(tmp_path)
    assert mixed.status == "inconclusive"
    (tmp_path / "tests" / "test_mixed.py").write_text("import nose\ndef test_ok(): pass\n")
    unsupported = TestDiscovery().discover(tmp_path)
    assert unsupported.status == "unsupported"


def test_discovery_rejects_symlinked_test_outside_project(tmp_path):
    outside = tmp_path.parent / "specguard-outside-test.py"
    outside.write_text("def test_outside(): pass\n")
    (tmp_path / "tests").mkdir()
    link = tmp_path / "tests" / "test_link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        outside.unlink(missing_ok=True)
        return
    discovery = TestDiscovery().discover(tmp_path)
    outside.unlink(missing_ok=True)
    assert discovery.status == "inconclusive"


def test_baseline_runner_fails_closed_without_docker_or_image(tmp_path):
    write_unittest_project(tmp_path)
    result = BaselineRunner(ExecutionPolicy(docker_image=None)).run(tmp_path, "baseline-no-image")
    assert result.status == "inconclusive"
    assert result.evidence.status == EvidenceStatus.INCONCLUSIVE
    assert result.returncode is None


def test_baseline_runner_records_redacted_reproducible_evidence(tmp_path, monkeypatch):
    write_unittest_project(tmp_path)

    class FakeSandbox:
        def __init__(self, policy):
            self.policy = policy

        def available(self):
            return True

        def run(self, project, command):
            return subprocess.CompletedProcess(command, 0, "PASS token=secret-value", "")

    monkeypatch.setattr("specguard.v2.behavioral.DockerSandbox", FakeSandbox)
    result = BaselineRunner(ExecutionPolicy(docker_image="python:test-image")).run(tmp_path, "baseline-fake")
    assert result.status == "passed"
    assert "secret-value" not in result.stdout
    assert "<redacted>" in result.stdout
    assert result.evidence.reproducibility.command
    assert result.evidence.execution_context["secrets_redacted"] is True
    assert result.evidence.execution_context["started_at"]
    assert result.evidence.execution_context["finished_at"]


def test_baseline_runner_classifies_failed_tests_without_host_fallback(tmp_path, monkeypatch):
    write_unittest_project(tmp_path)

    class FakeSandbox:
        def __init__(self, policy):
            self.policy = policy

        def available(self):
            return True

        def run(self, project, command):
            return subprocess.CompletedProcess(command, 1, "FAIL", "assertion failed")

    monkeypatch.setattr("specguard.v2.behavioral.DockerSandbox", FakeSandbox)
    result = BaselineRunner(ExecutionPolicy(docker_image="python:test-image")).run(tmp_path, "baseline-failed")
    assert result.status == "failed_test"
    assert result.returncode == 1
    assert result.evidence.execution_context["runtime"] == "python-in-docker"


def test_baseline_runner_distinguishes_missing_framework_from_failed_test(tmp_path, monkeypatch):
    write_unittest_project(tmp_path)

    class FakeSandbox:
        def __init__(self, policy):
            self.policy = policy

        def available(self):
            return True

        def run(self, project, command):
            return subprocess.CompletedProcess(command, 1, "", "ModuleNotFoundError: No module named 'pytest'")

    monkeypatch.setattr("specguard.v2.behavioral.DockerSandbox", FakeSandbox)
    result = BaselineRunner(ExecutionPolicy(docker_image="python:test-image")).run(tmp_path, "baseline-missing-framework")
    assert result.status == "execution_error"
    assert result.evidence.status == EvidenceStatus.INCONCLUSIVE


def test_baseline_runner_classifies_timeout_as_inconclusive(tmp_path, monkeypatch):
    write_unittest_project(tmp_path)

    class FakeSandbox:
        def __init__(self, policy):
            self.policy = policy

        def available(self):
            return True

        def run(self, project, command):
            raise IsolationUnavailable("Sandbox timed out after 1s")

    monkeypatch.setattr("specguard.v2.behavioral.DockerSandbox", FakeSandbox)
    result = BaselineRunner(ExecutionPolicy(docker_image="python:test-image", timeout_seconds=1)).run(tmp_path, "baseline-timeout")
    assert result.status == "inconclusive"
    assert "timed out" in result.stderr
    assert result.evidence.status == EvidenceStatus.INCONCLUSIVE


def test_behavioral_verification_requires_determinate_oracle_and_expected_match(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "behavior.db")
    engine = BehavioralVerificationEngine(store)
    determinate = RequirementV2("REQ-001", "Amount must be positive.", "Amount must be positive.")
    contract, oracle_evidence = ExpectedBehaviorService().derive(determinate, "oracle-run")
    passed_observation = BehavioralObservation("obs-1", "behavior-run", "REQ-001", BehavioralVerdict.PASSED, actual="positive", expected=contract.postconditions[0], evidence_ids=(oracle_evidence.evidence_id,))
    findings, evidence = engine.evaluate((contract,), (passed_observation,), "behavior-run")
    assert findings[0].verdict == "passed"
    assert findings[0].compliance_status == ComplianceStatus.COMPLIANT
    assert evidence[0].status == EvidenceStatus.VERIFIED
    assert store.get_evidence(evidence[0].evidence_id) == evidence[0]

    uncertain = RequirementV2("REQ-002", "The system may respond soon.", "The system may respond soon.", ambiguous=True, ambiguity_reasons=("vague",))
    uncertain_contract, _ = ExpectedBehaviorService().derive(uncertain, "oracle-run")
    uncertain_findings, _ = engine.evaluate((uncertain_contract,), (passed_observation,), "behavior-uncertain")
    assert uncertain_findings[0].verdict == "unsupported"
    assert uncertain_findings[0].compliance_status == ComplianceStatus.INCONCLUSIVE
    store.close()


def test_behavior_without_observation_is_not_evaluated(tmp_path):
    contract, _ = ExpectedBehaviorService().derive(RequirementV2("REQ-001", "Amount must be positive.", "Amount must be positive."), "oracle-run")
    findings, evidence = BehavioralVerificationEngine().evaluate((contract,), (), "not-evaluated")
    assert findings[0].verdict == "not_evaluated"
    assert findings[0].test_effectiveness_status == Effectiveness.NOT_EVALUATED
    assert evidence[0].status == EvidenceStatus.INCONCLUSIVE


def test_behavioral_observation_round_trips_with_versioned_schema():
    observation = BehavioralObservation(
        "obs-roundtrip", "run-roundtrip", "REQ-001", BehavioralVerdict.VIOLATION_OBSERVED,
        actual={"status": 500}, expected={"status": 200}, evidence_ids=("evidence-1",),
    )
    restored = BehavioralObservation.from_dict(observation.to_dict())
    assert restored == observation
    assert restored.to_dict()["schema_version"] == "2.0"
