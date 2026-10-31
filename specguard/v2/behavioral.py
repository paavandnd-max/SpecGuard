from __future__ import annotations

import ast
import hashlib
import os
import re
import sys
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..adapters import LanguageAdapter, PythonAdapter, adapter_for, detect_project
from ..secure_execution import DockerSandbox, ExecutionPolicy, IsolationUnavailable
from .evidence_store import EvidenceStore, InMemoryEvidenceStore
from .models import (
    BehavioralObservation,
    BehavioralVerdict,
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    ExpectedBehaviorContract,
    Finding,
    ReproducibilityMetadata,
    TestEffectiveness,
    VerificationMode,
)


_SECRET_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization|cookie)\s*[:=]\s*([^\s,;]+)")


def redact_text(value: str) -> str:
    """Redact common secret-shaped log values before persistence."""
    return _SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", value)


@dataclass(frozen=True)
class DiscoveredTest:
    path: str
    name: str
    kind: str
    framework: str
    line: int


@dataclass(frozen=True)
class TestDiscoveryResult:
    status: str
    framework: str | None
    command: tuple[str, ...] | None
    tests: tuple[DiscoveredTest, ...] = ()
    errors: tuple[str, ...] = ()
    unsupported_reasons: tuple[str, ...] = ()


class TestDiscovery:
    """Static Python test discovery; it parses source and never imports it."""

    supported_frameworks = {"pytest", "unittest"}

    def discover(self, project_root: str | Path, adapter: LanguageAdapter | None = None) -> TestDiscoveryResult:
        root = Path(project_root).resolve()
        adapter = adapter or adapter_for(detect_project(root).language)
        if adapter is None or getattr(adapter, "language", None) != "python":
            return TestDiscoveryResult("unsupported", None, None, unsupported_reasons=("Only Python test discovery is implemented in Phase 3",))
        files = [path for path in adapter.test_files(root) if self._safe_project_path(root, path)]
        if not files:
            return TestDiscoveryResult("inconclusive", None, None, unsupported_reasons=("No test files discovered",))
        tests: list[DiscoveredTest] = []
        frameworks: set[str] = set()
        errors: list[str] = []
        for path in files:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError) as exc:
                errors.append(f"{path}: {exc}")
                continue
            file_frameworks = self._frameworks(tree)
            frameworks.update(file_frameworks)
            framework = next(iter(file_frameworks), "unittest" if "TestCase" in ast.dump(tree) else "unknown")
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                    tests.append(DiscoveredTest(str(path.relative_to(root)), node.name, "function", framework, node.lineno))
                elif isinstance(node, ast.ClassDef) and (node.name.startswith("Test") or any(base_name.endswith("TestCase") for base_name in self._base_names(node))):
                    tests.append(DiscoveredTest(str(path.relative_to(root)), node.name, "class", framework, node.lineno))
        if errors:
            return TestDiscoveryResult("inconclusive", next(iter(frameworks), None), None, tuple(tests), tuple(errors))
        if not tests:
            return TestDiscoveryResult("inconclusive", next(iter(frameworks), None), None, (), (), ("No test functions or test classes found",))
        if not frameworks:
            frameworks = {"unittest"}
        if not frameworks <= self.supported_frameworks:
            return TestDiscoveryResult("unsupported", ",".join(sorted(frameworks)), None, tuple(tests), unsupported_reasons=(f"Unsupported Python test framework(s): {', '.join(sorted(frameworks - self.supported_frameworks))}",))
        if len(frameworks) > 1:
            return TestDiscoveryResult("inconclusive", ",".join(sorted(frameworks)), None, tuple(tests), unsupported_reasons=("Multiple test frameworks were detected",))
        framework = next(iter(frameworks))
        command = adapter.test_command(root)
        return TestDiscoveryResult("ready", framework, command, tuple(tests))

    @staticmethod
    def _frameworks(tree: ast.AST) -> set[str]:
        frameworks: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "pytest" or alias.name.startswith("pytest."):
                        frameworks.add("pytest")
                    if alias.name == "unittest" or alias.name.startswith("unittest."):
                        frameworks.add("unittest")
                    if alias.name == "nose" or alias.name.startswith("nose."):
                        frameworks.add("nose")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "pytest" or node.module.startswith("pytest."):
                    frameworks.add("pytest")
                if node.module == "unittest" or node.module.startswith("unittest."):
                    frameworks.add("unittest")
                if node.module == "nose" or node.module.startswith("nose."):
                    frameworks.add("nose")
        return frameworks

    @staticmethod
    def _safe_project_path(root: Path, path: Path) -> bool:
        """Reject symlinks and paths resolving outside the uploaded project."""
        if path.is_symlink():
            return False
        try:
            path.resolve().relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _base_names(node: ast.ClassDef) -> list[str]:
        names: list[str] = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                names.append(base.id)
            elif isinstance(base, ast.Attribute):
                names.append(base.attr)
        return names


@dataclass(frozen=True)
class BaselineExecution:
    run_id: str
    status: str
    discovery: TestDiscoveryResult
    evidence: Evidence
    command: tuple[str, ...] | None
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float


class BaselineRunner:
    """Runs an original project only through Docker and records reproducibility."""

    version = "baseline-runner-v1"

    def __init__(self, policy: ExecutionPolicy | None = None, store: EvidenceStore | None = None):
        self.policy = policy or ExecutionPolicy()
        self.store = store or InMemoryEvidenceStore()
        self.discovery = TestDiscovery()

    def run(self, project_root: str | Path, run_id: str = "baseline", test_command: tuple[str, ...] | None = None) -> BaselineExecution:
        root = Path(project_root).resolve()
        detection = detect_project(root)
        adapter = adapter_for(detection.language)
        discovery = self.discovery.discover(root, adapter)
        input_hashes = self._project_hashes(root)
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.perf_counter()
        if discovery.status != "ready":
            finished_at = datetime.now(timezone.utc).isoformat()
            evidence = self._evidence(run_id, "baseline_test_discovery", "Baseline test discovery did not produce an executable supported suite", discovery.__dict__, input_hashes, None, None, 0.0, EvidenceStatus.INCONCLUSIVE, started_at, finished_at)
            self.store.save_evidence(evidence)
            return BaselineExecution(run_id, discovery.status, discovery, evidence, discovery.command, None, "", "", 0.0)
        sandbox = DockerSandbox(self.policy)
        if not sandbox.available():
            message = sandbox.explain_unavailable()
            finished_at = datetime.now(timezone.utc).isoformat()
            evidence = self._evidence(run_id, "baseline_execution", message, {"discovery": discovery.__dict__}, input_hashes, test_command or discovery.command, None, 0.0, EvidenceStatus.INCONCLUSIVE, started_at, finished_at)
            self.store.save_evidence(evidence)
            return BaselineExecution(run_id, "inconclusive", discovery, evidence, test_command or discovery.command, None, "", redact_text(message), 0.0)
        command = tuple("python" if item == sys.executable else item for item in (test_command or discovery.command or ()))
        try:
            completed = sandbox.run(root, command)
            duration = time.perf_counter() - started
            finished_at = datetime.now(timezone.utc).isoformat()
            stdout = redact_text(completed.stdout or "")
            stderr = redact_text(completed.stderr or "")
            infrastructure_error = self._infrastructure_error(completed.returncode, stderr)
            status = "execution_error" if infrastructure_error else "passed" if completed.returncode == 0 else "failed_test"
            evidence_status = EvidenceStatus.INCONCLUSIVE if infrastructure_error else EvidenceStatus.OBSERVED
            evidence = self._evidence(run_id, "baseline_test_execution", "Original test suite executed in Docker", {"discovery": discovery.__dict__, "stdout": stdout, "stderr": stderr, "status": status}, input_hashes, command, completed.returncode, duration, evidence_status, started_at, finished_at)
            self.store.save_evidence(evidence)
            return BaselineExecution(run_id, status, discovery, evidence, command, completed.returncode, stdout, stderr, duration)
        except (IsolationUnavailable, OSError) as exc:
            duration = time.perf_counter() - started
            finished_at = datetime.now(timezone.utc).isoformat()
            message = redact_text(str(exc))
            evidence = self._evidence(run_id, "baseline_execution", message, {"discovery": discovery.__dict__, "status": "inconclusive"}, input_hashes, command, None, duration, EvidenceStatus.INCONCLUSIVE, started_at, finished_at)
            self.store.save_evidence(evidence)
            return BaselineExecution(run_id, "inconclusive", discovery, evidence, command, None, "", message, duration)

    @staticmethod
    def _project_hashes(root: Path) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink() and not any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in path.relative_to(root).parts):
                hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes

    @staticmethod
    def _infrastructure_error(returncode: int, stderr: str) -> bool:
        """Recognize sandbox/toolchain failures separately from assertion failures."""
        lowered = stderr.lower()
        markers = (
            "docker:", "oci runtime", "error response from daemon", "unable to find image",
            "cannot connect to the docker daemon", "no module named", "executable file not found",
            "command not found", "permission denied",
        )
        return returncode in {126, 127} or returncode >= 125 or any(marker in lowered for marker in markers)

    def _evidence(self, run_id: str, kind: str, claim: str, details: dict[str, Any], input_hashes: dict[str, str], command: tuple[str, ...] | None, returncode: int | None, duration: float, status: EvidenceStatus, started_at: str | None = None, finished_at: str | None = None) -> Evidence:
        evidence_id = "evidence-" + hashlib.sha256(f"{run_id}:{kind}:{jsonish(details)}".encode()).hexdigest()[:20]
        repro = ReproducibilityMetadata(
            input_hashes=input_hashes,
            parser_version=self.version,
            adapter_id="python-test-discovery",
            adapter_version=self.version,
            execution_policy_id=self.policy.docker_image or "unconfigured",
            image_digest=self.policy.docker_image,
            command=command or (),
            environment_fingerprint="docker-no-host-environment",
            network_policy=self.policy.network,
            resource_policy={"timeout_seconds": self.policy.timeout_seconds, "memory_mb": self.policy.memory_mb, "cpu_count": self.policy.cpu_count, "pids_limit": self.policy.pids_limit},
        )
        return Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            kind=kind,
            status=status,
            claim=claim,
            input_hashes=input_hashes,
            execution_context={"returncode": returncode, "duration_seconds": duration, "started_at": started_at, "finished_at": finished_at, "runtime": "python-in-docker", "interpreter": command[0] if command else None, "seed": None, "secrets_redacted": True},
            reproducibility=repro,
            details=details,
        )


class BehavioralVerificationEngine:
    """Compares explicit observations with oracle contracts; it does not infer behavior."""

    version = "behavioral-comparison-v1"

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or InMemoryEvidenceStore()

    @staticmethod
    def _same_behavior(left: Any, right: Any) -> bool:
        """Compare oracle/observation values without executing project code."""
        if isinstance(left, (dict, list, tuple)) or isinstance(right, (dict, list, tuple)):
            return jsonish(left) == jsonish(right)
        return left == right or str(left).strip() == str(right).strip()

    def evaluate(self, contracts: tuple[ExpectedBehaviorContract, ...], observations: tuple[BehavioralObservation, ...], run_id: str = "behavioral") -> tuple[tuple[Finding, ...], tuple[Evidence, ...]]:
        observations_by_requirement = {item.requirement_id: item for item in observations}
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for contract in contracts:
            observation = observations_by_requirement.get(contract.requirement_id)
            if contract.uncertainty:
                verdict = BehavioralVerdict.UNSUPPORTED
                evidence_status = EvidenceStatus.INCONCLUSIVE
                message = "Expected behavior is uncertain; dynamic compliance was not evaluated"
                compliance = ComplianceStatus.INCONCLUSIVE
                effectiveness = TestEffectiveness.NOT_EVALUATED
            elif observation is None:
                verdict = BehavioralVerdict.NOT_EVALUATED
                evidence_status = EvidenceStatus.INCONCLUSIVE
                message = "No behavioral observation was supplied"
                compliance = ComplianceStatus.INCONCLUSIVE
                effectiveness = TestEffectiveness.NOT_EVALUATED
            elif observation.expected is None or not any(self._same_behavior(observation.expected, expected) for expected in contract.postconditions):
                verdict = BehavioralVerdict.INCONCLUSIVE
                evidence_status = EvidenceStatus.INCONCLUSIVE
                message = "Observation did not carry an expected outcome matching the oracle contract"
                compliance = ComplianceStatus.INCONCLUSIVE
                effectiveness = TestEffectiveness.INCONCLUSIVE
            else:
                verdict = observation.verdict
                evidence_status = EvidenceStatus.VERIFIED if verdict in {BehavioralVerdict.PASSED, BehavioralVerdict.VIOLATION_OBSERVED} else EvidenceStatus.INCONCLUSIVE
                message = f"Behavioral outcome: {verdict.value}"
                compliance = ComplianceStatus.COMPLIANT if verdict == BehavioralVerdict.PASSED else ComplianceStatus.VIOLATION if verdict == BehavioralVerdict.VIOLATION_OBSERVED else ComplianceStatus.INCONCLUSIVE
                effectiveness = TestEffectiveness.NOT_EVALUATED
            evidence_id = "evidence-" + hashlib.sha256(f"{run_id}:comparison:{contract.requirement_id}:{verdict.value}".encode()).hexdigest()[:20]
            comparison = Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                kind="behavioral_comparison",
                status=evidence_status,
                claim=message,
                requirement_id=contract.requirement_id,
                parent_ids=contract.evidence_ids + ((observation.evidence_ids if observation else ())),
                reproducibility=ReproducibilityMetadata(oracle_version=contract.oracle_version, provider="none", execution_policy_id="comparison-only", parent_evidence_ids=contract.evidence_ids),
                details={"verdict": verdict.value, "uncertainty": list(contract.uncertainty), "actual": observation.actual if observation else None, "expected": observation.expected if observation else None},
            )
            finding = Finding(
                finding_id="finding-" + hashlib.sha256(f"{run_id}:behavior:{contract.requirement_id}:{verdict.value}".encode()).hexdigest()[:20],
                requirement_id=contract.requirement_id,
                category="behavioral_verification",
                severity="error" if verdict == BehavioralVerdict.VIOLATION_OBSERVED else "info",
                verdict=verdict.value,
                compliance_status=compliance,
                test_effectiveness_status=effectiveness,
                verification_mode=VerificationMode.DYNAMIC,
                message=message,
                evidence_ids=(evidence_id,),
            )
            self.store.save_evidence(comparison)
            self.store.save_finding(finding)
            evidence.append(comparison)
            findings.append(finding)
        return tuple(findings), tuple(evidence)


def jsonish(value: Any) -> str:
    if isinstance(value, dict):
        return "{" + ",".join(f"{key}:{jsonish(value[key])}" for key in sorted(value)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jsonish(item) for item in value) + "]"
    return str(value)
