from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..adapters import detect_project
from ..requirements import parse_requirements
from ..secure_execution import ExecutionPolicy
from .adversarial import AdversarialResult, AdversarialTestingEngine
from .behavioral import BaselineExecution, BaselineRunner, BehavioralVerificationEngine
from .code_intelligence import CodeIntelligenceEngine, CodeIntelligenceResult
from .evidence_store import EvidenceStore, InMemoryEvidenceStore
from .models import (
    ChangeRecord,
    ChangeSet,
    CodeSymbol,
    ComplianceStatus,
    EvaluationPlan,
    EvaluationPlanItem,
    EvaluationRun,
    Evidence,
    EvidenceLifecycleRecord,
    EvidenceLifecycleState,
    FileChangeKind,
    Finding,
    ImpactAnalysis,
    MonitoringConfiguration,
    Mutant,
    MutationRun,
    PlanActionKind,
    ProjectSnapshot,
    RegressionFinding,
    RegressionKind,
    RequirementChange,
    RequirementChangeKind,
    RequirementComparison,
    RequirementV2,
    ReproducibilityMetadata,
    RunComparison,
    RunPolicy,
    RunStatus,
    TestEffectiveness,
    TraceabilityLink,
    VerificationMode,
)
from .oracle import ExpectedBehaviorService
from .requirement_intelligence import RequirementIntelligenceEngine, RequirementIntelligenceResult


def classify_file(relative_path: str) -> str:
    path_str = relative_path.replace("\\", "/").lower()
    name = Path(path_str).name

    if name in {
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "pipfile",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "cargo.toml",
        "go.mod",
    }:
        return "dependency"

    if (name.endswith(".md") and ("requirement" in name or "spec" in name)) or name in {"requirements.md", "specification.md", "specs.md"} or path_str.startswith("requirements/"):
        return "requirement"

    if path_str.startswith("tests/") or path_str.startswith("test/") or "/tests/" in path_str or name.startswith("test_") or name.endswith("_test.py"):
        return "test"

    if name in {
        "dockerfile",
        "docker-compose.yml",
        ".dockerignore",
        "pytest.ini",
        "setup.cfg",
        "tox.ini",
        ".env",
        ".flake8",
        "tsconfig.json",
    } or name.startswith(".docker"):
        return "config"

    if any(path_str.endswith(ext) for ext in [".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".cpp", ".c", ".h"]):
        return "source"

    return "other"


def _hash_file_safely(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class SnapshotBuilder:
    """Builds an immutable, content-hashed snapshot of a project directory."""

    IGNORE_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules", ".tox"}

    def __init__(self, limits_max_files: int = 5000):
        self.limits_max_files = limits_max_files

    def build(self, project_root: str | Path, metadata: dict[str, Any] | None = None) -> ProjectSnapshot:
        root = Path(project_root).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Project root does not exist or is not a directory: {root}")

        files: dict[str, str] = {}
        categories: dict[str, str] = {}
        file_count = 0

        for path in root.rglob("*"):
            if any(part in self.IGNORE_DIRS for part in path.parts):
                continue
            if path.is_symlink():
                target = path.resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise ValueError(f"Unsafe symlink escapes project root: {path} -> {target}") from exc
                if not target.exists():
                    continue

            if path.is_file():
                file_count += 1
                if file_count > self.limits_max_files:
                    raise ValueError(f"Project exceeds maximum allowed file count ({self.limits_max_files})")
                rel_path = str(path.relative_to(root)).replace("\\", "/")
                file_hash = _hash_file_safely(path)
                files[rel_path] = file_hash
                categories[rel_path] = classify_file(rel_path)

        requirement_hashes: dict[str, str] = {}
        req_file = root / "requirements.md"
        if req_file.exists() and req_file.is_file():
            try:
                parsed = parse_requirements(req_file)
                for req in parsed:
                    text_val = getattr(req, "text", getattr(req, "description", ""))
                    normalized = " ".join(text_val.strip().split())
                    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                    requirement_hashes[req.id] = h
            except Exception:
                pass

        snapshot_content = [
            f"root:{str(root)}",
            *sorted(f"{k}:{v}" for k, v in files.items()),
            *sorted(f"req:{k}:{v}" for k, v in requirement_hashes.items()),
        ]
        snapshot_id = "snap-" + hashlib.sha256("\n".join(snapshot_content).encode("utf-8")).hexdigest()[:24]

        return ProjectSnapshot(
            snapshot_id=snapshot_id,
            project_root=str(root),
            created_at=time.time(),
            files=files,
            file_categories=categories,
            requirement_hashes=requirement_hashes,
            metadata=dict(metadata or {}),
        )


class ChangeDetector:
    """Detects file and requirement changes between two project snapshots."""

    def detect(self, base_snapshot: ProjectSnapshot | None, target_snapshot: ProjectSnapshot) -> ChangeSet:
        if base_snapshot is None:
            file_changes = [
                ChangeRecord(
                    path=path,
                    kind=FileChangeKind.ADDED,
                    old_hash=None,
                    new_hash=file_hash,
                    category=target_snapshot.file_categories.get(path, "other"),
                )
                for path, file_hash in sorted(target_snapshot.files.items())
            ]
            requirement_changes = [
                RequirementChange(
                    requirement_id=req_id,
                    kind=RequirementChangeKind.ADDED,
                    old_text=None,
                    new_text=req_hash,
                )
                for req_id, req_hash in sorted(target_snapshot.requirement_hashes.items())
            ]
            has_source = any(c.category == "source" for c in file_changes)
            has_test = any(c.category == "test" for c in file_changes)
            has_req = len(requirement_changes) > 0
            has_dep = any(c.category == "dependency" for c in file_changes)
            cid = "change-" + hashlib.sha256(f"initial:{target_snapshot.snapshot_id}".encode()).hexdigest()[:24]
            return ChangeSet(
                changeset_id=cid,
                base_snapshot_id=None,
                target_snapshot_id=target_snapshot.snapshot_id,
                file_changes=tuple(file_changes),
                requirement_changes=tuple(requirement_changes),
                created_at=time.time(),
                has_source_changes=has_source,
                has_test_changes=has_test,
                has_requirement_changes=has_req,
                has_dependency_changes=has_dep,
            )

        base_files = base_snapshot.files
        target_files = target_snapshot.files

        added_paths = set(target_files) - set(base_files)
        deleted_paths = set(base_files) - set(target_files)
        common_paths = set(base_files) & set(target_files)

        # Detect renames by content hash matching
        renamed_from: dict[str, str] = {}  # deleted_path -> added_path
        renamed_to: dict[str, str] = {}    # added_path -> deleted_path

        deleted_by_hash: dict[str, list[str]] = {}
        for p in deleted_paths:
            h = base_files[p]
            deleted_by_hash.setdefault(h, []).append(p)

        for a in sorted(added_paths):
            h = target_files[a]
            candidates = deleted_by_hash.get(h, [])
            if len(candidates) == 1:
                d = candidates[0]
                renamed_from[d] = a
                renamed_to[a] = d
                deleted_by_hash[h].remove(d)

        file_changes: list[ChangeRecord] = []

        # Record modifications
        for p in sorted(common_paths):
            if base_files[p] != target_files[p]:
                file_changes.append(
                    ChangeRecord(
                        path=p,
                        kind=FileChangeKind.MODIFIED,
                        old_hash=base_files[p],
                        new_hash=target_files[p],
                        category=target_snapshot.file_categories.get(p, "other"),
                    )
                )

        # Record additions and renames
        for p in sorted(added_paths):
            if p in renamed_to:
                old_p = renamed_to[p]
                file_changes.append(
                    ChangeRecord(
                        path=p,
                        kind=FileChangeKind.RENAMED,
                        old_hash=base_files[old_p],
                        new_hash=target_files[p],
                        old_path=old_p,
                        category=target_snapshot.file_categories.get(p, "other"),
                    )
                )
            else:
                file_changes.append(
                    ChangeRecord(
                        path=p,
                        kind=FileChangeKind.ADDED,
                        old_hash=None,
                        new_hash=target_files[p],
                        category=target_snapshot.file_categories.get(p, "other"),
                    )
                )

        # Record deletions (excluding renamed)
        for p in sorted(deleted_paths):
            if p not in renamed_from:
                file_changes.append(
                    ChangeRecord(
                        path=p,
                        kind=FileChangeKind.DELETED,
                        old_hash=base_files[p],
                        new_hash=None,
                        category=base_snapshot.file_categories.get(p, "other"),
                    )
                )

        # Requirement changes
        base_reqs = base_snapshot.requirement_hashes
        target_reqs = target_snapshot.requirement_hashes
        req_changes: list[RequirementChange] = []

        for req_id in sorted(set(target_reqs) - set(base_reqs)):
            req_changes.append(
                RequirementChange(
                    requirement_id=req_id,
                    kind=RequirementChangeKind.ADDED,
                    old_text=None,
                    new_text=target_reqs[req_id],
                )
            )

        for req_id in sorted(set(base_reqs) - set(target_reqs)):
            req_changes.append(
                RequirementChange(
                    requirement_id=req_id,
                    kind=RequirementChangeKind.REMOVED,
                    old_text=base_reqs[req_id],
                    new_text=None,
                )
            )

        for req_id in sorted(set(base_reqs) & set(target_reqs)):
            if base_reqs[req_id] != target_reqs[req_id]:
                req_changes.append(
                    RequirementChange(
                        requirement_id=req_id,
                        kind=RequirementChangeKind.MODIFIED,
                        old_text=base_reqs[req_id],
                        new_text=target_reqs[req_id],
                    )
                )

        has_source = any(c.category == "source" for c in file_changes)
        has_test = any(c.category == "test" for c in file_changes)
        has_req = len(req_changes) > 0
        has_dep = any(c.category == "dependency" for c in file_changes)

        change_summary = [
            f"{c.kind.value}:{c.path}" for c in file_changes
        ] + [
            f"req_{r.kind.value}:{r.requirement_id}" for r in req_changes
        ]
        cid = "change-" + hashlib.sha256("\n".join([base_snapshot.snapshot_id, target_snapshot.snapshot_id, *change_summary]).encode()).hexdigest()[:24]

        return ChangeSet(
            changeset_id=cid,
            base_snapshot_id=base_snapshot.snapshot_id,
            target_snapshot_id=target_snapshot.snapshot_id,
            file_changes=tuple(file_changes),
            requirement_changes=tuple(req_changes),
            created_at=time.time(),
            has_source_changes=has_source,
            has_test_changes=has_test,
            has_requirement_changes=has_req,
            has_dependency_changes=has_dep,
        )


class ImpactAnalyzer:
    """Computes the affected scope of changes on requirements, symbols, tests, and evidence."""

    def analyze(
        self,
        changeset: ChangeSet,
        requirements: list[RequirementV2],
        symbols: list[CodeSymbol] = (),
        traceability: list[TraceabilityLink] = (),
        evidence: list[Evidence] = (),
        findings: list[Finding] = (),
    ) -> ImpactAnalysis:
        impacted_reqs: set[str] = set()
        impacted_symbols: set[str] = set()
        impacted_tests: set[str] = set()
        stale_evidence: set[str] = set()
        stale_findings: set[str] = set()
        reasons: dict[str, list[str]] = {}

        req_map = {r.requirement_id: r for r in requirements}

        # Case 1: Dependency changes affect everything
        if changeset.has_dependency_changes:
            for r in requirements:
                impacted_reqs.add(r.requirement_id)
                reasons.setdefault(r.requirement_id, []).append("Dependency manifest changed; full verification rerun required")
            for e in evidence:
                stale_evidence.add(e.evidence_id)
            for f in findings:
                stale_findings.add(f.finding_id)

            unaffected = set(req_map) - impacted_reqs
            iid = "impact-" + hashlib.sha256(f"{changeset.changeset_id}:dep".encode()).hexdigest()[:24]
            return ImpactAnalysis(
                impact_id=iid,
                changeset_id=changeset.changeset_id,
                impacted_requirement_ids=tuple(sorted(impacted_reqs)),
                unaffected_requirement_ids=tuple(sorted(unaffected)),
                impacted_symbol_ids=tuple(sorted(s.symbol_id for s in symbols)),
                impacted_test_ids=tuple(sorted(impacted_tests)),
                stale_evidence_ids=tuple(sorted(stale_evidence)),
                stale_finding_ids=tuple(sorted(stale_findings)),
                reasons=reasons,
            )

        # Case 2: Requirement changes (direct and transitive)
        direct_req_changes: set[str] = set()
        for rc in changeset.requirement_changes:
            if rc.kind in {RequirementChangeKind.MODIFIED, RequirementChangeKind.REMOVED}:
                direct_req_changes.add(rc.requirement_id)
                impacted_reqs.add(rc.requirement_id)
                reasons.setdefault(rc.requirement_id, []).append(f"Requirement specification {rc.kind.value}")

        # Transitive dependency propagation
        changed_and_propagated = set(direct_req_changes)
        queue = list(direct_req_changes)
        while queue:
            current = queue.pop(0)
            for r in requirements:
                if current in r.dependencies and r.requirement_id not in changed_and_propagated:
                    changed_and_propagated.add(r.requirement_id)
                    impacted_reqs.add(r.requirement_id)
                    reasons.setdefault(r.requirement_id, []).append(f"Depends on modified requirement {current}")
                    queue.append(r.requirement_id)

        # Case 3: Source file changes -> symbols -> linked requirements
        for fc in changeset.file_changes:
            if fc.category == "source":
                fc_path = fc.path.replace("\\", "/")
                # Find symbols in this file
                matching_syms = [
                    s for s in symbols
                    if s.span.get("path", "").replace("\\", "/").endswith(fc_path)
                    or Path(s.span.get("path", "")).name == Path(fc_path).name
                ]
                for ms in matching_syms:
                    impacted_symbols.add(ms.symbol_id)
                    # Find callers of ms
                    callers = [
                        s for s in symbols
                        if ms.symbol_id in s.calls or ms.symbol_id in s.dependency_ids
                    ]
                    for c in callers:
                        impacted_symbols.add(c.symbol_id)

                # Trace symbols to requirements
                for link in traceability:
                    if link.target_id in impacted_symbols or any(
                        link.target_id.endswith(s_id) for s_id in impacted_symbols
                    ):
                        r_id = link.requirement_id
                        impacted_reqs.add(r_id)
                        reasons.setdefault(r_id, []).append(f"Implementation source {fc.path} was {fc.kind.value}")

                    # Also check marker links pointing to this file path
                    if fc_path in link.target_id or Path(fc_path).name in link.target_id:
                        r_id = link.requirement_id
                        impacted_reqs.add(r_id)
                        reasons.setdefault(r_id, []).append(f"Traceable source {fc.path} was {fc.kind.value}")

        # Case 4: Test file changes -> tests -> linked requirements
        for fc in changeset.file_changes:
            if fc.category == "test":
                fc_path = fc.path.replace("\\", "/")
                impacted_tests.add(fc_path)
                for link in traceability:
                    if link.target_kind == "test" or "test" in link.relation or fc_path in link.target_id:
                        r_id = link.requirement_id
                        impacted_reqs.add(r_id)
                        reasons.setdefault(r_id, []).append(f"Test file {fc.path} was {fc.kind.value}")

        # Invalidate evidence & findings for impacted requirements
        for e in evidence:
            if e.requirement_id and e.requirement_id in impacted_reqs:
                stale_evidence.add(e.evidence_id)
            elif any(aid in impacted_symbols for aid in e.artifact_ids):
                stale_evidence.add(e.evidence_id)

        for f in findings:
            if f.requirement_id and f.requirement_id in impacted_reqs:
                stale_findings.add(f.finding_id)
            elif any(eid in stale_evidence for eid in f.evidence_ids):
                stale_findings.add(f.finding_id)

        all_known_reqs = set(req_map) | {rc.requirement_id for rc in changeset.requirement_changes if rc.kind != RequirementChangeKind.REMOVED}
        unaffected = all_known_reqs - impacted_reqs

        iid = "impact-" + hashlib.sha256(
            "\n".join([changeset.changeset_id, *sorted(impacted_reqs), *sorted(stale_evidence)]).encode()
        ).hexdigest()[:24]

        return ImpactAnalysis(
            impact_id=iid,
            changeset_id=changeset.changeset_id,
            impacted_requirement_ids=tuple(sorted(impacted_reqs)),
            unaffected_requirement_ids=tuple(sorted(unaffected)),
            impacted_symbol_ids=tuple(sorted(impacted_symbols)),
            impacted_test_ids=tuple(sorted(impacted_tests)),
            stale_evidence_ids=tuple(sorted(stale_evidence)),
            stale_finding_ids=tuple(sorted(stale_findings)),
            reasons=reasons,
        )


class EvaluationPlanner:
    """Constructs an incremental evaluation plan based on impact analysis."""

    def plan(
        self,
        impact: ImpactAnalysis,
        target_snapshot: ProjectSnapshot,
        base_run: EvaluationRun | None = None,
        all_findings: list[Finding] = (),
        all_evidence: list[Evidence] = (),
    ) -> EvaluationPlan:
        items: list[EvaluationPlanItem] = []
        rerun_count = 0
        reuse_count = 0
        invalidate_count = 0

        # Rerun items
        for r_id in impact.impacted_requirement_ids:
            reasons = impact.reasons.get(r_id, ["Affected by project changes"])
            item = EvaluationPlanItem(
                item_id=f"plan-item-rerun-{r_id}",
                requirement_id=r_id,
                action=PlanActionKind.RERUN,
                engines=("requirement_intelligence", "code_intelligence", "behavioral", "adversarial"),
                reason="; ".join(reasons),
                reusable_finding_ids=(),
                reusable_evidence_ids=(),
            )
            items.append(item)
            rerun_count += 1

        # Reuse items
        for r_id in impact.unaffected_requirement_ids:
            reusable_f = [f.finding_id for f in all_findings if f.requirement_id == r_id and f.finding_id not in impact.stale_finding_ids]
            reusable_e = [e.evidence_id for e in all_evidence if e.requirement_id == r_id and e.evidence_id not in impact.stale_evidence_ids]
            item = EvaluationPlanItem(
                item_id=f"plan-item-reuse-{r_id}",
                requirement_id=r_id,
                action=PlanActionKind.REUSE,
                engines=(),
                reason="Requirement specification and code/tests are unaffected; reusing verified evidence",
                reusable_finding_ids=tuple(sorted(reusable_f)),
                reusable_evidence_ids=tuple(sorted(reusable_e)),
            )
            items.append(item)
            reuse_count += 1

        pid = "plan-" + hashlib.sha256(
            "\n".join([impact.impact_id, target_snapshot.snapshot_id, str(rerun_count), str(reuse_count)]).encode()
        ).hexdigest()[:24]

        return EvaluationPlan(
            plan_id=pid,
            impact_id=impact.impact_id,
            base_run_id=base_run.run_id if base_run else None,
            target_snapshot_id=target_snapshot.snapshot_id,
            items=tuple(items),
            total_requirements=len(items),
            rerun_count=rerun_count,
            reuse_count=reuse_count,
            invalidate_count=invalidate_count,
            created_at=time.time(),
        )


class RunComparator:
    """Compares base and target evaluation runs to identify genuine regressions and improvements."""

    def compare(
        self,
        base_run: EvaluationRun,
        target_run: EvaluationRun,
        base_findings: list[Finding],
        target_findings: list[Finding],
        base_mutations: MutationRun | None = None,
        target_mutations: MutationRun | None = None,
        requirement_changes: list[RequirementChange] = (),
    ) -> RunComparison:
        changed_req_ids = {rc.requirement_id for rc in requirement_changes}

        # Index findings by requirement
        base_f_by_req: dict[str, list[Finding]] = {}
        for f in base_findings:
            if f.requirement_id:
                base_f_by_req.setdefault(f.requirement_id, []).append(f)

        target_f_by_req: dict[str, list[Finding]] = {}
        for f in target_findings:
            if f.requirement_id:
                target_f_by_req.setdefault(f.requirement_id, []).append(f)

        all_req_ids = sorted(set(base_f_by_req) | set(target_f_by_req))
        req_comparisons: list[RequirementComparison] = []
        regressions: list[RegressionFinding] = []

        for r_id in all_req_ids:
            b_list = base_f_by_req.get(r_id, [])
            t_list = target_f_by_req.get(r_id, [])

            b_comp = b_list[0].compliance_status if b_list else None
            t_comp = t_list[0].compliance_status if t_list else None

            b_eff = b_list[0].test_effectiveness_status if b_list else None
            t_eff = t_list[0].test_effectiveness_status if t_list else None

            is_req_change = r_id in changed_req_ids

            # Find mutation scores if available
            b_score: float | None = None
            if base_mutations:
                for s in base_mutations.summaries:
                    if s.requirement_id == r_id:
                        b_score = s.score
                        break

            t_score: float | None = None
            if target_mutations:
                for s in target_mutations.summaries:
                    if s.requirement_id == r_id:
                        t_score = s.score
                        break

            delta = "no_change"
            explanation = "No change in verification state"

            # Check compliance regression
            if b_comp == ComplianceStatus.COMPLIANT and t_comp == ComplianceStatus.VIOLATION:
                delta = "regressed"
                explanation = "Behavior regression: previously compliant requirement now observed as violation"
                reg = RegressionFinding(
                    regression_id=f"reg-comp-{r_id}",
                    requirement_id=r_id,
                    kind=RegressionKind.COMPLIANCE_REGRESSION,
                    severity="critical",
                    message=explanation,
                    base_verdict=b_comp.value,
                    target_verdict=t_comp.value,
                    evidence_ids=tuple(target_findings[0].evidence_ids if target_findings else ()),
                    is_requirement_change=is_req_change,
                )
                regressions.append(reg)

            elif b_eff == TestEffectiveness.DETECTED and t_eff in {TestEffectiveness.SURVIVED, TestEffectiveness.INCONCLUSIVE}:
                delta = "regressed"
                explanation = f"Effectiveness regression: previously detected mutants now {t_eff.value}"
                reg = RegressionFinding(
                    regression_id=f"reg-eff-{r_id}",
                    requirement_id=r_id,
                    kind=RegressionKind.EFFECTIVENESS_REGRESSION,
                    severity="high",
                    message=explanation,
                    base_verdict=b_eff.value,
                    target_verdict=t_eff.value,
                    is_requirement_change=is_req_change,
                )
                regressions.append(reg)

            elif b_score is not None and t_score is not None and t_score < b_score:
                delta = "regressed"
                explanation = f"Mutation protection score decreased from {b_score} to {t_score}"
                reg = RegressionFinding(
                    regression_id=f"reg-score-{r_id}",
                    requirement_id=r_id,
                    kind=RegressionKind.COVERAGE_REGRESSION,
                    severity="medium",
                    message=explanation,
                    base_verdict=str(b_score),
                    target_verdict=str(t_score),
                    is_requirement_change=is_req_change,
                )
                regressions.append(reg)

            elif b_list and not t_list:
                delta = "removed"
                explanation = "Requirement removed from evaluation scope"

            elif not b_list and t_list:
                delta = "added"
                explanation = "Requirement newly added to evaluation scope"

            elif (b_comp != ComplianceStatus.COMPLIANT and t_comp == ComplianceStatus.COMPLIANT) or \
                 (b_eff != TestEffectiveness.DETECTED and t_eff == TestEffectiveness.DETECTED):
                delta = "improved"
                explanation = "Verification status improved"

            comp = RequirementComparison(
                requirement_id=r_id,
                base_compliance=b_comp,
                target_compliance=t_comp,
                base_effectiveness=b_eff,
                target_effectiveness=t_eff,
                base_score=b_score,
                target_score=t_score,
                status_delta=delta,
                is_requirement_change=is_req_change,
                explanation=explanation,
            )
            req_comparisons.append(comp)

        counts = {
            "regressed": sum(1 for c in req_comparisons if c.status_delta == "regressed"),
            "improved": sum(1 for c in req_comparisons if c.status_delta == "improved"),
            "no_change": sum(1 for c in req_comparisons if c.status_delta == "no_change"),
            "added": sum(1 for c in req_comparisons if c.status_delta == "added"),
            "removed": sum(1 for c in req_comparisons if c.status_delta == "removed"),
        }

        cid = "comp-" + hashlib.sha256(f"{base_run.run_id}:{target_run.run_id}".encode()).hexdigest()[:24]
        summary = f"{counts['regressed']} regressions, {counts['improved']} improvements, {counts['no_change']} unchanged"

        return RunComparison(
            comparison_id=cid,
            base_run_id=base_run.run_id,
            target_run_id=target_run.run_id,
            timestamp=time.time(),
            requirement_comparisons=tuple(req_comparisons),
            regressions=tuple(regressions),
            counts=counts,
            summary=summary,
        )


class RepositoryMonitor:
    """Stateless check helper for repository file changes without uncontrolled background threads."""

    def __init__(self, builder: SnapshotBuilder | None = None, detector: ChangeDetector | None = None):
        self.builder = builder or SnapshotBuilder()
        self.detector = detector or ChangeDetector()

    def check_for_changes(
        self,
        config: MonitoringConfiguration,
        last_snapshot: ProjectSnapshot | None,
    ) -> tuple[bool, ChangeSet | None, ProjectSnapshot]:
        current_snapshot = self.builder.build(config.root_path)
        if last_snapshot is None:
            return False, None, current_snapshot

        changeset = self.detector.detect(last_snapshot, current_snapshot)
        has_changes = bool(changeset.file_changes or changeset.requirement_changes)
        return has_changes, (changeset if has_changes else None), current_snapshot


class ContinuousAssuranceEngine:
    """The Continuous Assurance Engine orchestrates change detection, impact analysis,

    selective evaluation, and regression tracking across the SpecGuard platform.
    """

    def __init__(
        self,
        store: EvidenceStore,
        policy: ExecutionPolicy | None = None,
        snapshot_builder: SnapshotBuilder | None = None,
        change_detector: ChangeDetector | None = None,
        impact_analyzer: ImpactAnalyzer | None = None,
        planner: EvaluationPlanner | None = None,
        comparator: RunComparator | None = None,
    ):
        self.store = store
        self.policy = policy or ExecutionPolicy()
        self.snapshot_builder = snapshot_builder or SnapshotBuilder()
        self.change_detector = change_detector or ChangeDetector()
        self.impact_analyzer = impact_analyzer or ImpactAnalyzer()
        self.planner = planner or EvaluationPlanner()
        self.comparator = comparator or RunComparator()

    def create_snapshot(self, project_root: str | Path, metadata: dict[str, Any] | None = None) -> ProjectSnapshot:
        snapshot = self.snapshot_builder.build(project_root, metadata)
        self.store.save_snapshot(snapshot)
        return snapshot

    def detect_changes(self, base_snapshot: ProjectSnapshot | None, target_snapshot: ProjectSnapshot) -> ChangeSet:
        changeset = self.change_detector.detect(base_snapshot, target_snapshot)
        self.store.save_changeset(changeset)
        return changeset

    def analyze_impact(
        self,
        changeset: ChangeSet,
        requirements: list[RequirementV2],
        symbols: list[CodeSymbol] = (),
        traceability: list[TraceabilityLink] = (),
        evidence: list[Evidence] = (),
        findings: list[Finding] = (),
    ) -> ImpactAnalysis:
        impact = self.impact_analyzer.analyze(
            changeset,
            requirements,
            symbols=symbols,
            traceability=traceability,
            evidence=evidence,
            findings=findings,
        )
        return impact

    def generate_plan(
        self,
        impact: ImpactAnalysis,
        target_snapshot: ProjectSnapshot,
        base_run: EvaluationRun | None = None,
        all_findings: list[Finding] = (),
        all_evidence: list[Evidence] = (),
    ) -> EvaluationPlan:
        plan = self.planner.plan(
            impact,
            target_snapshot,
            base_run=base_run,
            all_findings=all_findings,
            all_evidence=all_evidence,
        )
        self.store.save_plan(plan)
        return plan

    def invalidate_stale_evidence(self, impact: ImpactAnalysis, changeset_id: str) -> list[EvidenceLifecycleRecord]:
        records: list[EvidenceLifecycleRecord] = []
        for eid in impact.stale_evidence_ids:
            rec = EvidenceLifecycleRecord(
                record_id=f"life-stale-{eid}",
                evidence_id=eid,
                state=EvidenceLifecycleState.STALE,
                reason="Input source or requirement modified in changeset",
                updated_at=time.time(),
                invalidated_by_change_id=changeset_id,
            )
            self.store.save_lifecycle_record(rec)
            records.append(rec)
        return records

    def execute_plan(
        self,
        plan: EvaluationPlan,
        project_root: str | Path,
        base_run: EvaluationRun | None = None,
        run_id: str | None = None,
    ) -> EvaluationRun:
        root = Path(project_root).resolve()
        run_id = run_id or f"run-inc-{int(time.time()*1000)}"

        # Prepare new run record
        run_policy = RunPolicy(
            policy_id="cont-policy-1",
            image=self.policy.docker_image,
            timeout_seconds=self.policy.timeout_seconds,
            memory_mb=self.policy.memory_mb,
            cpu_count=self.policy.cpu_count,
            pids_limit=self.policy.pids_limit,
            network_policy=self.policy.network,
        )

        all_findings: list[Finding] = []
        all_evidence: list[Evidence] = []
        all_engine_runs: list[dict[str, Any]] = []

        # Items to rerun
        rerun_items = [it for it in plan.items if it.action == PlanActionKind.RERUN]
        reuse_items = [it for it in plan.items if it.action == PlanActionKind.REUSE]

        # 1. Reuse unaffected items
        for it in reuse_items:
            for fid in it.reusable_finding_ids:
                f = self.store.get_finding(fid)
                if f:
                    all_findings.append(f)
            for eid in it.reusable_evidence_ids:
                e = self.store.get_evidence(eid)
                if e:
                    all_evidence.append(e)
                    # Revalidate evidence
                    rec = EvidenceLifecycleRecord(
                        record_id=f"life-reval-{eid}-{run_id}",
                        evidence_id=eid,
                        state=EvidenceLifecycleState.REVALIDATED,
                        reason="Reused without change in incremental evaluation",
                        updated_at=time.time(),
                    )
                    self.store.save_lifecycle_record(rec)

        # 2. Rerun affected items using existing engines
        if rerun_items:
            req_file = root / "requirements.md"
            if req_file.exists():
                req_engine = RequirementIntelligenceEngine()
                req_result = req_engine.analyze(req_file, root, run_id=run_id)
                all_findings.extend(req_result.findings)
                all_evidence.extend(req_result.evidence)
                all_engine_runs.append({
                    "engine": "requirement_intelligence",
                    "status": "completed",
                    "requirement_count": len(req_result.requirements),
                })
                # Re-evaluate code intelligence
                code_engine = CodeIntelligenceEngine(store=self.store)
                code_result = code_engine.analyze(root, req_file, run_id=run_id)
                all_findings.extend(code_result.findings)
                all_evidence.extend(code_result.evidence)
                all_engine_runs.append({
                    "engine": "code_intelligence",
                    "status": code_result.status,
                    "symbol_count": len(code_result.symbols),
                })

                rerun_req_ids = {it.requirement_id for it in rerun_items}
                rerun_req_objs = tuple(r for r in req_result.requirements if r.requirement_id in rerun_req_ids)
                rerun_contracts = tuple(c for c in req_result.behavior_contracts if c.requirement_id in rerun_req_ids)

                # Baseline execution and behavioral verification
                baseline_runner = BaselineRunner(self.policy, self.store)
                baseline_exec = baseline_runner.run(root, run_id=run_id)
                if baseline_exec.evidence:
                    all_evidence.append(baseline_exec.evidence)
                all_engine_runs.append({
                    "engine": "baseline_runner",
                    "status": baseline_exec.status,
                })

                # Adversarial testing for rerun items
                adv_engine = AdversarialTestingEngine(
                    policy=self.policy,
                    store=self.store,
                )
                adv_res = adv_engine.run(
                    root,
                    requirements=rerun_req_objs,
                    contracts=rerun_contracts,
                    traceability=code_result.traceability,
                    symbols=code_result.symbols,
                    run_id=run_id,
                )
                all_findings.extend(adv_res.findings)
                all_evidence.extend(adv_res.evidence)
                all_engine_runs.append({
                    "engine": "adversarial_testing",
                    "status": adv_res.run.status,
                    "mutants_count": len(adv_res.mutants),
                })

        counts = {
            "compliant": sum(1 for f in all_findings if f.compliance_status == ComplianceStatus.COMPLIANT),
            "violation": sum(1 for f in all_findings if f.compliance_status == ComplianceStatus.VIOLATION),
            "detected": sum(1 for f in all_findings if f.test_effectiveness_status == TestEffectiveness.DETECTED),
            "survived": sum(1 for f in all_findings if f.test_effectiveness_status == TestEffectiveness.SURVIVED),
            "findings_count": len(all_findings),
            "evidence_count": len(all_evidence),
        }

        eval_run = EvaluationRun(
            run_id=run_id,
            project_id=str(root),
            revision_id=plan.target_snapshot_id,
            policy=run_policy,
            status=RunStatus.COMPLETED,
            started_at=plan.created_at,
            finished_at=time.time(),
            engine_runs=tuple(all_engine_runs),
            finding_ids=tuple(sorted(set(f.finding_id for f in all_findings))),
            evidence_ids=tuple(sorted(set(e.evidence_id for e in all_evidence))),
            counts=counts,
        )
        self.store.save_run(eval_run)
        return eval_run

    def compare_runs(self, base_run_id: str, target_run_id: str, requirement_changes: list[RequirementChange] = ()) -> RunComparison:
        base_run = self.store.get_run(base_run_id)
        target_run = self.store.get_run(target_run_id)
        if not base_run or not target_run:
            raise ValueError(f"One or both runs not found: {base_run_id}, {target_run_id}")

        base_findings = [self.store.get_finding(fid) for fid in base_run.finding_ids]
        target_findings = [self.store.get_finding(fid) for fid in target_run.finding_ids]

        base_mutations = self.store.get_mutation_run(base_run_id)
        target_mutations = self.store.get_mutation_run(target_run_id)

        comparison = self.comparator.compare(
            base_run,
            target_run,
            [f for f in base_findings if f is not None],
            [f for f in target_findings if f is not None],
            base_mutations=base_mutations,
            target_mutations=target_mutations,
            requirement_changes=requirement_changes,
        )
        self.store.save_comparison(comparison)
        return comparison
