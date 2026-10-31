from __future__ import annotations

import ast
import copy
import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..adapters import detect_project
from ..secure_execution import ExecutionPolicy
from .behavioral import BaselineExecution, BaselineRunner
from .code_intelligence import CodeIntelligenceEngine
from .evidence_store import EvidenceStore, InMemoryEvidenceStore
from .models import (
    CodeSymbol,
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    ExpectedBehaviorContract,
    Finding,
    Mutant,
    MutationOperatorKind,
    MutationPatch,
    MutationRun,
    MutationVerdict,
    RequirementMutationSummary,
    RequirementV2,
    ReproducibilityMetadata,
    TestEffectiveness,
    TraceabilityLink,
    VerificationMode,
)
from .requirement_intelligence import RequirementIntelligenceEngine


@dataclass(frozen=True)
class MutationTarget:
    requirement_id: str
    status: str
    source_path: Path | None = None
    target_symbol_id: str | None = None
    target_line: int | None = None
    target_end_line: int | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class MutationCandidate:
    requirement_id: str
    operator: MutationOperatorKind
    file_path: Path
    target_symbol_id: str | None
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    original_text: str
    replacement_text: str
    description: str


@dataclass(frozen=True)
class MutationTargetingResult:
    targets: tuple[MutationTarget, ...]
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class AdversarialResult:
    run: MutationRun
    mutants: tuple[Mutant, ...]
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    targeting: MutationTargetingResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.to_dict(),
            "mutants": [item.to_dict() for item in self.mutants],
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "targeting": {
                "targets": [item.__dict__ | {"source_path": str(item.source_path) if item.source_path else None} for item in self.targeting.targets],
                "evidence": [item.to_dict() for item in self.targeting.evidence],
                "findings": [item.to_dict() for item in self.targeting.findings],
            },
        }


class MutationTargetSelector:
    """Selects only traceability- and oracle-backed Python mutation targets."""

    version = "targeting-v1"

    def __init__(self, root: Path, store: EvidenceStore):
        self.root = root
        self.store = store

    def select(
        self,
        requirements: tuple[RequirementV2, ...],
        contracts: tuple[ExpectedBehaviorContract, ...],
        traceability: tuple[TraceabilityLink, ...],
        symbols: tuple[CodeSymbol, ...],
        run_id: str,
    ) -> MutationTargetingResult:
        contract_by_id = {item.requirement_id: item for item in contracts}
        links_by_id: dict[str, list[TraceabilityLink]] = {}
        for link in traceability:
            links_by_id.setdefault(link.requirement_id, []).append(link)
        symbols_by_id = {item.symbol_id: item for item in symbols}
        detected_language = detect_project(self.root).language
        targets: list[MutationTarget] = []
        evidence: list[Evidence] = []
        findings: list[Finding] = []
        for requirement in requirements:
            contract = contract_by_id.get(requirement.requirement_id)
            links = links_by_id.get(requirement.requirement_id, [])
            status = "ready"
            reason = ""
            source_path: Path | None = None
            symbol_id: str | None = None
            target_line: int | None = None
            target_end_line: int | None = None
            evidence_ids = tuple(evidence_id for link in links for evidence_id in link.evidence_ids)
            if contract is None:
                status, reason = "inconclusive", "No expected-behavior contract was supplied"
            elif detected_language != "python":
                status, reason = "unsupported", f"Python mutation operators do not support detected language: {detected_language}"
            elif contract.uncertainty:
                status, reason = "unsupported", "Oracle contract is uncertain: " + "; ".join(contract.uncertainty)
            else:
                source_links = [item for item in links if item.target_kind == "source"]
                code_links = [item for item in links if item.target_kind == "code_symbol"]
                if source_links:
                    source_path, target_line = self._resolve_source_link(source_links[0])
                    if source_path is None:
                        status, reason = "inconclusive", "Source traceability path is unavailable"
                elif code_links:
                    symbol_id = code_links[0].target_id
                    symbol = symbols_by_id.get(symbol_id)
                    if symbol is None:
                        status, reason = "inconclusive", "Traceability points to an unavailable code symbol"
                    else:
                        source_path = self._resolve_symbol_path(symbol)
                        target_line = int(symbol.span.get("start_line", 0)) + 1
                        target_end_line = int(symbol.span.get("end_line", target_line))
                        if source_path is None:
                            status, reason = "inconclusive", "Code symbol path is outside the project or unavailable"
                elif requirement.source_hint:
                    source_path = self._safe_path(requirement.source_hint)
                    if source_path is None:
                        status, reason = "inconclusive", "Requirement source hint is unavailable or outside the project"
                else:
                    status, reason = "inconclusive", "No evidence-backed requirement-to-code traceability"
                if status == "ready" and source_path is None:
                    status, reason = "inconclusive", "No safe source target was resolved"
            target = MutationTarget(requirement.requirement_id, status, source_path, symbol_id, target_line, target_end_line, tuple(evidence_ids), reason)
            targets.append(target)
            claim = "Requirement mutation target selected" if status == "ready" else "Requirement mutation targeting was not established"
            ev = self._evidence(run_id, "mutation_targeting", claim, requirement.requirement_id, {"status": status, "reason": reason, "source_path": str(source_path) if source_path else None, "target_symbol_id": symbol_id, "target_line": target_line}, evidence_ids)
            evidence.append(ev)
            finding = Finding(
                finding_id=self._stable("finding", run_id, "targeting", requirement.requirement_id, status),
                requirement_id=requirement.requirement_id,
                category="mutation_targeting",
                severity="info" if status == "ready" else "warning",
                verdict=status,
                compliance_status=ComplianceStatus.UNKNOWN,
                test_effectiveness_status=TestEffectiveness.NOT_EVALUATED,
                verification_mode=VerificationMode.MUTATION,
                message=claim + (f": {reason}" if reason else ""),
                evidence_ids=(ev.evidence_id,),
            )
            findings.append(finding)
            self.store.save_evidence(ev)
            self.store.save_finding(finding)
        return MutationTargetingResult(tuple(targets), tuple(evidence), tuple(findings))

    def _safe_path(self, value: str) -> Path | None:
        candidate = (self.root / value).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            return None
        return candidate if candidate.is_file() and not candidate.is_symlink() else None

    def _resolve_symbol_path(self, symbol: CodeSymbol) -> Path | None:
        path = Path(str(symbol.span.get("path", "")))
        if not path.is_absolute():
            path = self.root / path
        return self._safe_path(str(path.relative_to(self.root)) if path.is_absolute() and path.is_relative_to(self.root) else str(path))

    def _resolve_source_link(self, link: TraceabilityLink) -> tuple[Path | None, int | None]:
        value = link.target_id.removeprefix("source:")
        path_text, _, line_text = value.rpartition(":")
        try:
            line = int(line_text)
        except ValueError:
            return None, None
        return self._safe_path(path_text), line

    def _evidence(self, run_id: str, kind: str, claim: str, requirement_id: str, details: dict[str, Any], parent_ids: tuple[str, ...]) -> Evidence:
        evidence_id = self._stable("evidence", run_id, kind, requirement_id, repr(sorted(details.items())))
        evidence = Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            kind=kind,
            status=EvidenceStatus.OBSERVED if details.get("status") == "ready" else EvidenceStatus.INCONCLUSIVE,
            claim=claim,
            requirement_id=requirement_id,
            parent_ids=parent_ids,
            reproducibility=ReproducibilityMetadata(adapter_id=self.version, adapter_version=self.version, parent_evidence_ids=parent_ids),
            details=details,
        )
        return evidence

    @staticmethod
    def _stable(prefix: str, *parts: str) -> str:
        return f"{prefix}-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:20]


class PythonMutationOperatorSet:
    """Deterministic, AST-span-aware Python mutation operators."""

    @staticmethod
    def generate(source: str, path: Path, target: MutationTarget, max_candidates: int = 32) -> list[MutationCandidate]:
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []
        nodes = [node for node in ast.walk(tree) if PythonMutationOperatorSet._in_target(node, target)]
        if target.target_line is not None:
            line_nodes = [node for node in nodes if getattr(node, "lineno", 0) >= target.target_line]
            if line_nodes:
                nearest = min(getattr(node, "lineno", target.target_line) for node in line_nodes)
                nodes = [node for node in line_nodes if getattr(node, "lineno", 0) == nearest]
        candidates: list[MutationCandidate] = []
        for node in nodes:
            candidates.extend(PythonMutationOperatorSet._comparison(node, source, path, target))
            candidates.extend(PythonMutationOperatorSet._boolean(node, source, path, target))
            candidates.extend(PythonMutationOperatorSet._arithmetic(node, source, path, target))
            candidates.extend(PythonMutationOperatorSet._return(node, source, path, target))
            candidates.extend(PythonMutationOperatorSet._validation(node, source, path, target))
            candidates.extend(PythonMutationOperatorSet._exception(node, source, path, target))
            if len(candidates) >= max_candidates:
                break
        return candidates[:max_candidates]

    @staticmethod
    def _in_target(node: ast.AST, target: MutationTarget) -> bool:
        if target.target_symbol_id is None:
            return True
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if start < 1:
            return False
        if target.target_line is None:
            return True
        if target.target_symbol_id is not None and target.target_end_line is not None:
            return end >= target.target_line and start <= target.target_end_line
        return end >= target.target_line

    @staticmethod
    def _candidate(node: ast.AST, source: str, path: Path, target: MutationTarget, operator: MutationOperatorKind, replacement: str, description: str, original_node: ast.AST | None = None) -> MutationCandidate | None:
        original_node = original_node or node
        original = ast.get_source_segment(source, original_node)
        if not original or original == replacement:
            return None
        return MutationCandidate(target.requirement_id, operator, path, target.target_symbol_id, original_node.lineno, original_node.col_offset, getattr(original_node, "end_lineno", original_node.lineno), getattr(original_node, "end_col_offset", original_node.col_offset), original, replacement, description)

    @staticmethod
    def _comparison(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            return []
        op = node.ops[0]
        replacements: dict[type[ast.cmpop], str] = {ast.Lt: "<=", ast.LtE: "<", ast.Gt: ">=", ast.GtE: ">", ast.Eq: "!=", ast.NotEq: "=="}
        replacement = replacements.get(type(op))
        if replacement is None:
            return []
        mutated = copy.deepcopy(node)
        mutated.ops[0] = {ast.Lt: ast.LtE(), ast.LtE: ast.Lt(), ast.Gt: ast.GtE(), ast.GtE: ast.Gt(), ast.Eq: ast.NotEq(), ast.NotEq: ast.Eq()}[type(op)]
        candidate = PythonMutationOperatorSet._candidate(node, source, path, target, MutationOperatorKind.COMPARISON_BOUNDARY, ast.unparse(mutated), f"Replace comparison operator {type(op).__name__} with {replacement}")
        return [candidate] if candidate else []

    @staticmethod
    def _boolean(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if not isinstance(node, ast.BoolOp):
            return []
        mutated = copy.deepcopy(node)
        mutated.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        candidate = PythonMutationOperatorSet._candidate(node, source, path, target, MutationOperatorKind.BOOLEAN_LOGIC, ast.unparse(mutated), "Replace boolean conjunction/disjunction")
        return [candidate] if candidate else []

    @staticmethod
    def _arithmetic(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if not isinstance(node, ast.BinOp):
            return []
        replacements: dict[type[ast.operator], ast.operator] = {ast.Add: ast.Sub(), ast.Sub: ast.Add(), ast.Mult: ast.Div(), ast.Div: ast.Mult()}
        replacement_op = replacements.get(type(node.op))
        if replacement_op is None:
            return []
        mutated = copy.deepcopy(node)
        mutated.op = replacement_op
        candidate = PythonMutationOperatorSet._candidate(node, source, path, target, MutationOperatorKind.ARITHMETIC, ast.unparse(mutated), "Replace arithmetic operator")
        return [candidate] if candidate else []

    @staticmethod
    def _return(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if not isinstance(node, ast.Return) or node.value is None:
            return []
        candidate = PythonMutationOperatorSet._candidate(node.value, source, path, target, MutationOperatorKind.RETURN_VALUE, "None", "Replace returned value with None")
        return [candidate] if candidate else []

    @staticmethod
    def _validation(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if not isinstance(node, ast.If) or not any(isinstance(child, ast.Raise) for child in ast.walk(node)):
            return []
        candidate = PythonMutationOperatorSet._candidate(node.test, source, path, target, MutationOperatorKind.INPUT_VALIDATION, "False", "Disable an input-validation guard")
        return [candidate] if candidate else []

    @staticmethod
    def _exception(node: ast.AST, source: str, path: Path, target: MutationTarget) -> list[MutationCandidate]:
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            candidate = PythonMutationOperatorSet._candidate(node.type, source, path, target, MutationOperatorKind.EXCEPTION_HANDLING, "Exception", "Broaden caught exception type")
            return [candidate] if candidate else []
        if isinstance(node, ast.Raise):
            candidate = PythonMutationOperatorSet._candidate(node, source, path, target, MutationOperatorKind.EXCEPTION_HANDLING, "pass", "Suppress an explicit raise")
            return [candidate] if candidate else []
        return []


class AdversarialTestingEngine:
    """Phase 4 Python mutation engine with Docker-only mutant execution."""

    version = "adversarial-v1"

    def __init__(self, policy: ExecutionPolicy | None = None, store: EvidenceStore | None = None, max_mutants_per_requirement: int = 8, retry_limit: int = 1):
        self.policy = policy or ExecutionPolicy()
        self.store = store or InMemoryEvidenceStore()
        self.max_mutants_per_requirement = max_mutants_per_requirement
        self.retry_limit = max(0, retry_limit)

    def run(
        self,
        project_root: str | Path,
        requirements: tuple[RequirementV2, ...],
        contracts: tuple[ExpectedBehaviorContract, ...] = (),
        traceability: tuple[TraceabilityLink, ...] = (),
        symbols: tuple[CodeSymbol, ...] = (),
        requirements_path: str | Path | None = None,
        run_id: str = "mutation-run",
    ) -> AdversarialResult:
        root = Path(project_root).resolve()
        if requirements_path is not None and (not contracts or not traceability):
            intelligence = RequirementIntelligenceEngine().analyze(requirements_path, root, run_id)
            contracts = contracts or intelligence.behavior_contracts
            traceability = traceability or intelligence.traceability
        if not symbols:
            code = CodeIntelligenceEngine(self.store).analyze(root, requirements_path, f"{run_id}:code")
            symbols = code.symbols
            if not traceability:
                traceability = code.traceability
        targeting = MutationTargetSelector(root, self.store).select(requirements, contracts, traceability, symbols, run_id)
        baseline = self._baseline(root, run_id)
        all_evidence = list(targeting.evidence)
        baseline_evidence = getattr(baseline, "evidence", None)
        if baseline_evidence is not None:
            all_evidence.append(baseline_evidence)
        all_findings = list(targeting.findings)
        mutants: list[Mutant] = []
        summaries: list[RequirementMutationSummary] = []
        if baseline.status != "passed":
            for target in targeting.targets:
                summaries.append(RequirementMutationSummary(target.requirement_id, target.status, target.status == "ready", reason=f"Baseline status {baseline.status}; mutant execution was not started"))
            run = self._save_run(run_id, root, baseline, mutants, summaries, all_evidence, "inconclusive", "Baseline did not pass")
            return AdversarialResult(run, tuple(mutants), tuple(all_findings), tuple(all_evidence), targeting)
        with tempfile.TemporaryDirectory(prefix="specguard-mutants-") as temp_name:
            temp_root = Path(temp_name)
            for target in targeting.targets:
                if target.status != "ready" or target.source_path is None:
                    summaries.append(RequirementMutationSummary(target.requirement_id, target.status, False, reason=target.reason))
                    continue
                source = target.source_path.read_text(encoding="utf-8")
                candidates = PythonMutationOperatorSet.generate(source, target.source_path, target, self.max_mutants_per_requirement)
                if not candidates:
                    summaries.append(RequirementMutationSummary(target.requirement_id, "inconclusive", True, reason="No supported AST mutation location was found"))
                    continue
                outcomes: list[MutationVerdict] = []
                for candidate in candidates:
                    mutant, evidence, finding = self._evaluate_candidate(root, temp_root, candidate, run_id)
                    mutants.append(mutant)
                    outcomes.append(mutant.verdict)
                    all_evidence.extend(evidence)
                    all_findings.append(finding)
                summaries.append(self._summary(target.requirement_id, outcomes))
        counts = {item.value: sum(mutant.verdict == item for mutant in mutants) for item in MutationVerdict}
        status = "completed" if mutants and all(item.verdict not in {MutationVerdict.INCONCLUSIVE, MutationVerdict.EXECUTION_ERROR} for item in mutants) else "inconclusive"
        run = self._save_run(run_id, root, baseline, mutants, summaries, all_evidence, status, None)
        return AdversarialResult(run, tuple(mutants), tuple(all_findings), tuple(all_evidence), targeting)

    def _baseline(self, root: Path, run_id: str) -> BaselineExecution:
        return BaselineRunner(self.policy, self.store).run(root, f"{run_id}:baseline")

    def _evaluate_candidate(self, root: Path, temp_root: Path, candidate: MutationCandidate, run_id: str) -> tuple[Mutant, list[Evidence], Finding]:
        source = candidate.file_path.read_text(encoding="utf-8")
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        patch_error: str | None = None
        try:
            mutated_source = _apply_text_patch(source, candidate)
        except ValueError as exc:
            mutated_source = source
            patch_error = str(exc)
        mutated_hash = hashlib.sha256(mutated_source.encode()).hexdigest()
        patch_id = self._stable("patch", source_hash, str(candidate.file_path), str(candidate.start_line), candidate.operator.value, candidate.replacement_text)
        mutant_id = self._stable("mutant", candidate.requirement_id, patch_id)
        patch = MutationPatch(patch_id, str(candidate.file_path.relative_to(root)), candidate.start_line, candidate.start_col, candidate.end_line, candidate.end_col, candidate.original_text, candidate.replacement_text, candidate.operator, source_hash, mutated_hash, candidate.target_symbol_id, candidate.description)
        evidence: list[Evidence] = []
        verdict = MutationVerdict.INVALID
        details: dict[str, Any] = {"operator": candidate.operator.value, "description": candidate.description}
        if patch_error is not None:
            verdict = MutationVerdict.INVALID
            details["reason"] = patch_error
        elif mutated_source == source:
            verdict = MutationVerdict.EQUIVALENT
            details["reason"] = "Patch produced no source change"
        elif _ast_equivalent(source, mutated_source):
            verdict = MutationVerdict.EQUIVALENT
            details["reason"] = "Normalized ASTs are identical"
        elif not _valid_python(mutated_source, candidate.file_path):
            verdict = MutationVerdict.INVALID
            details["reason"] = "Mutated source failed static Python parsing"
        else:
            for attempt in range(1, self.retry_limit + 2):
                candidate_root = temp_root / f"{mutant_id}-attempt-{attempt}"
                try:
                    _copy_project_safely(root, candidate_root)
                    target_file = candidate_root / patch.file_path
                    target_file.write_text(mutated_source, encoding="utf-8")
                    execution = BaselineRunner(self.policy, self.store).run(candidate_root, f"{run_id}:{mutant_id}:{attempt}")
                    if execution.status == "failed_test":
                        verdict = MutationVerdict.KILLED
                    elif execution.status == "passed":
                        verdict = MutationVerdict.SURVIVED
                    elif execution.status == "execution_error":
                        verdict = MutationVerdict.EXECUTION_ERROR
                    else:
                        verdict = MutationVerdict.INCONCLUSIVE
                    details.update({"attempt": attempt, "baseline_status": execution.status, "returncode": execution.returncode, "stdout": execution.stdout, "stderr": execution.stderr})
                    if verdict not in {MutationVerdict.INCONCLUSIVE, MutationVerdict.EXECUTION_ERROR} or attempt > self.retry_limit:
                        break
                except (OSError, ValueError) as exc:
                    verdict = MutationVerdict.EXECUTION_ERROR
                    details.update({"attempt": attempt, "error": str(exc)})
                    if attempt > self.retry_limit:
                        break
                finally:
                    if candidate_root.exists():
                        shutil.rmtree(candidate_root, ignore_errors=True)
        patch_evidence = Evidence(
            evidence_id=self._stable("evidence", run_id, mutant_id, "patch"),
            run_id=run_id,
            kind="mutation_patch",
            status=EvidenceStatus.OBSERVED,
            claim="Deterministic AST-scoped mutation patch generated",
            requirement_id=candidate.requirement_id,
            input_hashes={patch.file_path: source_hash},
            output_hash=mutated_hash,
            reproducibility=ReproducibilityMetadata(input_hashes={patch.file_path: source_hash}, parser_version=self.version, adapter_id="python-ast-mutator", adapter_version=self.version, execution_policy_id=self.policy.docker_image or "unconfigured", image_digest=self.policy.docker_image, network_policy=self.policy.network, resource_policy={"timeout_seconds": self.policy.timeout_seconds, "memory_mb": self.policy.memory_mb, "cpu_count": self.policy.cpu_count, "pids_limit": self.policy.pids_limit}, retry_policy=f"retry-{self.retry_limit}"),
            details={"patch": patch.to_dict(), "mutant_id": mutant_id},
        )
        evidence.append(patch_evidence)
        classification_evidence = Evidence(
            evidence_id=self._stable("evidence", run_id, mutant_id, "classification"),
            run_id=run_id,
            kind="mutation_classification",
            status=EvidenceStatus.VERIFIED if verdict in {MutationVerdict.KILLED, MutationVerdict.SURVIVED} else EvidenceStatus.INCONCLUSIVE,
            claim=f"Mutant classified as {verdict.value}",
            requirement_id=candidate.requirement_id,
            parent_ids=(patch_evidence.evidence_id,),
            reproducibility=patch_evidence.reproducibility,
            details=details,
        )
        evidence.append(classification_evidence)
        for item in evidence:
            self.store.save_evidence(item)
        mutant = Mutant(mutant_id, run_id, candidate.requirement_id, patch, verdict, True, "Traceability and determinate oracle target", int(details.get("attempt", 1)), tuple(item.evidence_id for item in evidence), details)
        self.store.save_mutant(mutant)
        effectiveness = TestEffectiveness.DETECTED if verdict == MutationVerdict.KILLED else TestEffectiveness.SURVIVED if verdict == MutationVerdict.SURVIVED else TestEffectiveness.INCONCLUSIVE
        finding = Finding(self._stable("finding", run_id, mutant_id), candidate.requirement_id, "mutation_testing", "info" if verdict != MutationVerdict.KILLED else "warning", verdict.value, ComplianceStatus.UNKNOWN, effectiveness, VerificationMode.MUTATION, f"Mutant {mutant_id} was {verdict.value}; this does not establish implementation compliance", tuple(item.evidence_id for item in evidence), metadata={"mutant_id": mutant_id, "operator": candidate.operator.value})
        self.store.save_finding(finding)
        return mutant, evidence, finding

    def _summary(self, requirement_id: str, outcomes: list[MutationVerdict]) -> RequirementMutationSummary:
        counts = {item: outcomes.count(item) for item in MutationVerdict}
        valid = counts[MutationVerdict.KILLED] + counts[MutationVerdict.SURVIVED]
        incomplete = counts[MutationVerdict.INVALID] + counts[MutationVerdict.INCONCLUSIVE] + counts[MutationVerdict.EXECUTION_ERROR]
        complete = valid > 0 and incomplete == 0
        score = counts[MutationVerdict.KILLED] / valid if complete else None
        reason = "" if complete else "No complete mutation denominator" if valid == 0 else "Execution contains invalid, inconclusive, or infrastructure outcomes"
        return RequirementMutationSummary(requirement_id, "ready", True, counts[MutationVerdict.KILLED], counts[MutationVerdict.SURVIVED], counts[MutationVerdict.EQUIVALENT], counts[MutationVerdict.INVALID], counts[MutationVerdict.INCONCLUSIVE], counts[MutationVerdict.EXECUTION_ERROR], score, complete, reason)

    def _save_run(self, run_id: str, root: Path, baseline: BaselineExecution, mutants: list[Mutant], summaries: list[RequirementMutationSummary], evidence: list[Evidence], status: str, error: str | None) -> MutationRun:
        counts = {item.value: sum(mutant.verdict == item for mutant in mutants) for item in MutationVerdict}
        run = MutationRun(run_id, str(root), baseline.status, status, tuple(item.mutant_id for item in mutants), tuple(item.evidence_id for item in evidence), counts, tuple(summaries), ReproducibilityMetadata(parser_version=self.version, execution_policy_id=self.policy.docker_image or "unconfigured", image_digest=self.policy.docker_image, network_policy=self.policy.network, resource_policy={"timeout_seconds": self.policy.timeout_seconds, "memory_mb": self.policy.memory_mb, "cpu_count": self.policy.cpu_count, "pids_limit": self.policy.pids_limit}, retry_policy=f"retry-{self.retry_limit}"), error)
        self.store.save_mutation_run(run)
        return run

    @staticmethod
    def _stable(prefix: str, *parts: str) -> str:
        return f"{prefix}-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:20]


def _apply_text_patch(source: str, candidate: MutationCandidate) -> str:
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:candidate.start_line - 1]) + candidate.start_col
    end = sum(len(line) for line in lines[:candidate.end_line - 1]) + candidate.end_col
    if source[start:end] != candidate.original_text:
        raise ValueError("Source span changed before patch application")
    return source[:start] + candidate.replacement_text + source[end:]


def _ast_equivalent(original: str, mutated: str) -> bool:
    try:
        return ast.dump(ast.parse(original), annotate_fields=False, include_attributes=False) == ast.dump(ast.parse(mutated), annotate_fields=False, include_attributes=False)
    except SyntaxError:
        return False


def _valid_python(source: str, path: Path) -> bool:
    try:
        ast.parse(source, filename=str(path))
        return True
    except SyntaxError:
        return False


def _copy_project_safely(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Symlinked project input is not permitted: {path}")
    shutil.copytree(source, destination, symlinks=True)
