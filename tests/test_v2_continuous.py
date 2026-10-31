from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from specguard.api import create_app
from specguard.backend import BackendStore
from specguard.secure_execution import ExecutionPolicy
from specguard.v2 import (
    ChangeDetector,
    ChangeRecord,
    ChangeSet,
    CodeIntelligenceEngine,
    CodeSymbol,
    ComplianceStatus,
    ContinuousAssuranceEngine,
    EvaluationPlan,
    EvaluationPlanItem,
    EvaluationPlanner,
    EvaluationRun,
    Evidence,
    EvidenceLifecycleRecord,
    EvidenceLifecycleState,
    EvidenceStatus,
    FileChangeKind,
    Finding,
    ImpactAnalysis,
    ImpactAnalyzer,
    InMemoryEvidenceStore,
    MonitoringConfiguration,
    Mutant,
    MutationPatch,
    MutationRun,
    MutationVerdict,
    MutationOperatorKind,
    PlanActionKind,
    ProjectSnapshot,
    RegressionFinding,
    RegressionKind,
    RepositoryMonitor,
    RequirementChange,
    RequirementChangeKind,
    RequirementComparison,
    RequirementMutationSummary,
    RequirementV2,
    ReproducibilityMetadata,
    RunComparison,
    RunComparator,
    RunPolicy,
    RunStatus,
    SnapshotBuilder,
    SQLiteEvidenceStore,
    TestEffectiveness,
    TraceabilityLink,
    VerificationMode,
    classify_file,
)


@pytest.fixture
def sample_project(tmp_path):
    proj = tmp_path / "sample_proj"
    proj.mkdir()
    (proj / "requirements.md").write_text(
        "- [ ] REQ-001: Amount must be positive\n"
        "- [ ] REQ-002: Order status must be paid (depends: REQ-001)\n"
        "- [ ] REQ-003: Customer must be verified\n",
        encoding="utf-8",
    )
    src_dir = proj / "demo"
    src_dir.mkdir()
    (src_dir / "__init__.py").write_text("", encoding="utf-8")
    (src_dir / "service.py").write_text(
        "# req: REQ-001\n"
        "def validate_amount(amt):\n"
        "    if amt <= 0:\n"
        "        raise ValueError('Must be positive')\n"
        "    return amt\n\n"
        "# req: REQ-002\n"
        "def process_order(order, amt):\n"
        "    validate_amount(amt)\n"
        "    if order.get('status') != 'paid':\n"
        "        raise ValueError('Order not paid')\n"
        "    return True\n",
        encoding="utf-8",
    )
    test_dir = proj / "tests"
    test_dir.mkdir()
    (test_dir / "__init__.py").write_text("", encoding="utf-8")
    (test_dir / "test_service.py").write_text(
        "import pytest\n"
        "from demo.service import validate_amount, process_order\n\n"
        "def test_amount():\n"
        "    assert validate_amount(10) == 10\n"
        "    with pytest.raises(ValueError):\n"
        "        validate_amount(0)\n\n"
        "def test_order():\n"
        "    assert process_order({'status': 'paid'}, 10) is True\n"
        "    with pytest.raises(ValueError):\n"
        "        process_order({'status': 'pending'}, 10)\n",
        encoding="utf-8",
    )
    return proj


def test_file_classification():
    assert classify_file("requirements.md") == "requirement"
    assert classify_file("specs/requirements.md") == "requirement"
    assert classify_file("tests/test_flow.py") == "test"
    assert classify_file("test/unit_test.py") == "test"
    assert classify_file("pyproject.toml") == "dependency"
    assert classify_file("requirements.txt") == "dependency"
    assert classify_file("Dockerfile") == "config"
    assert classify_file(".dockerignore") == "config"
    assert classify_file("demo/refund_flow.py") == "source"
    assert classify_file("notes.txt") == "other"


def test_snapshot_builder_and_change_detection_lifecycle(sample_project):
    builder = SnapshotBuilder()
    detector = ChangeDetector()

    # Initial snapshot
    snap1 = builder.build(sample_project)
    assert snap1.snapshot_id.startswith("snap-")
    assert "requirements.md" in snap1.files
    assert "demo/service.py" in snap1.files
    assert "tests/test_service.py" in snap1.files
    assert "REQ-001" in snap1.requirement_hashes
    assert "REQ-002" in snap1.requirement_hashes
    assert "REQ-003" in snap1.requirement_hashes

    # Add a file
    new_file = sample_project / "demo" / "helper.py"
    new_file.write_text("def helper(): return 1\n", encoding="utf-8")
    snap2 = builder.build(sample_project)
    changes_add = detector.detect(snap1, snap2)
    assert changes_add.has_source_changes
    assert any(c.path == "demo/helper.py" and c.kind == FileChangeKind.ADDED for c in changes_add.file_changes)

    # Modify a file
    (sample_project / "demo" / "service.py").write_text("# modified\ndef validate_amount(a): return a\n", encoding="utf-8")
    snap3 = builder.build(sample_project)
    changes_mod = detector.detect(snap2, snap3)
    assert any(c.path == "demo/service.py" and c.kind == FileChangeKind.MODIFIED for c in changes_mod.file_changes)

    # Delete a file
    new_file.unlink()
    snap4 = builder.build(sample_project)
    changes_del = detector.detect(snap3, snap4)
    assert any(c.path == "demo/helper.py" and c.kind == FileChangeKind.DELETED for c in changes_del.file_changes)


def test_rename_detection(tmp_path):
    root = tmp_path / "rename_proj"
    root.mkdir()
    content = "def original_func(): return 42\n"
    (root / "orig.py").write_text(content, encoding="utf-8")

    builder = SnapshotBuilder()
    detector = ChangeDetector()

    snap1 = builder.build(root)
    # Rename orig.py to renamed.py
    (root / "orig.py").unlink()
    (root / "renamed.py").write_text(content, encoding="utf-8")

    snap2 = builder.build(root)
    changes = detector.detect(snap1, snap2)
    assert any(c.kind == FileChangeKind.RENAMED and c.path == "renamed.py" and c.old_path == "orig.py" for c in changes.file_changes)


def test_requirement_change_detection(sample_project):
    builder = SnapshotBuilder()
    detector = ChangeDetector()
    snap1 = builder.build(sample_project)

    # Modify requirements.md: modify REQ-001, remove REQ-003, add REQ-004
    (sample_project / "requirements.md").write_text(
        "- [ ] REQ-001: Amount must be strictly greater than zero and positive\n"
        "- [ ] REQ-002: Order status must be paid (depends: REQ-001)\n"
        "- [ ] REQ-004: Newly added requirement\n",
        encoding="utf-8",
    )
    snap2 = builder.build(sample_project)
    changes = detector.detect(snap1, snap2)
    assert changes.has_requirement_changes

    kinds = {rc.requirement_id: rc.kind for rc in changes.requirement_changes}
    assert kinds.get("REQ-001") == RequirementChangeKind.MODIFIED
    assert kinds.get("REQ-003") == RequirementChangeKind.REMOVED
    assert kinds.get("REQ-004") == RequirementChangeKind.ADDED
    assert "REQ-002" not in kinds  # unchanged


def test_impact_analysis_for_source_and_calls(sample_project):
    builder = SnapshotBuilder()
    detector = ChangeDetector()
    snap1 = builder.build(sample_project)

    # Modify service.py
    (sample_project / "demo" / "service.py").write_text(
        "# req: REQ-001\n"
        "def validate_amount(amt):\n"
        "    if amt < 0:\n"
        "        raise ValueError('Must be positive')\n"
        "    return amt\n\n"
        "# req: REQ-002\n"
        "def process_order(order, amt):\n"
        "    validate_amount(amt)\n"
        "    return True\n",
        encoding="utf-8",
    )
    snap2 = builder.build(sample_project)
    changes = detector.detect(snap1, snap2)

    # Code intelligence symbols
    sym1 = CodeSymbol(
        symbol_id="sym-validate",
        artifact_id="art-1",
        language="python",
        kind="function",
        qualified_name="service.validate_amount",
        span={"path": "demo/service.py", "start_line": 2, "end_line": 5},
    )
    sym2 = CodeSymbol(
        symbol_id="sym-process",
        artifact_id="art-1",
        language="python",
        kind="function",
        qualified_name="service.process_order",
        span={"path": "demo/service.py", "start_line": 7, "end_line": 10},
        calls=("sym-validate",),
    )
    reqs = [
        RequirementV2(requirement_id="REQ-001", normalized_text="Amount positive", source_text=""),
        RequirementV2(requirement_id="REQ-002", normalized_text="Order paid", source_text="", dependencies=("REQ-001",)),
        RequirementV2(requirement_id="REQ-003", normalized_text="Customer verified", source_text=""),
    ]
    trace = [
        TraceabilityLink(link_id="link-1", requirement_id="REQ-001", target_id="sym-validate", target_kind="code_symbol", relation="implemented_by", origin="explicit_marker", confidence=1.0),
        TraceabilityLink(link_id="link-2", requirement_id="REQ-002", target_id="sym-process", target_kind="code_symbol", relation="implemented_by", origin="explicit_marker", confidence=1.0),
    ]

    analyzer = ImpactAnalyzer()
    impact = analyzer.analyze(changes, reqs, symbols=[sym1, sym2], traceability=trace)

    assert "REQ-001" in impact.impacted_requirement_ids
    assert "REQ-002" in impact.impacted_requirement_ids
    assert "REQ-003" in impact.unaffected_requirement_ids
    assert "sym-validate" in impact.impacted_symbol_ids
    assert "sym-process" in impact.impacted_symbol_ids


def test_transitive_requirement_dependency_impact(sample_project):
    builder = SnapshotBuilder()
    detector = ChangeDetector()
    snap1 = builder.build(sample_project)

    # Modify only REQ-001 text in requirements.md
    (sample_project / "requirements.md").write_text(
        "- [ ] REQ-001: Amount must be non-zero positive number\n"
        "- [ ] REQ-002: Order status must be paid (depends: REQ-001)\n"
        "- [ ] REQ-003: Customer must be verified\n",
        encoding="utf-8",
    )
    snap2 = builder.build(sample_project)
    changes = detector.detect(snap1, snap2)

    reqs = [
        RequirementV2(requirement_id="REQ-001", normalized_text="Amount positive", source_text=""),
        RequirementV2(requirement_id="REQ-002", normalized_text="Order paid", source_text="", dependencies=("REQ-001",)),
        RequirementV2(requirement_id="REQ-003", normalized_text="Customer verified", source_text=""),
    ]

    analyzer = ImpactAnalyzer()
    impact = analyzer.analyze(changes, reqs)

    assert "REQ-001" in impact.impacted_requirement_ids
    assert "REQ-002" in impact.impacted_requirement_ids  # transitive dependent
    assert "REQ-003" in impact.unaffected_requirement_ids


def test_dependency_change_impacts_all_requirements(sample_project):
    (sample_project / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    builder = SnapshotBuilder()
    detector = ChangeDetector()
    snap1 = builder.build(sample_project)

    # Modify pyproject.toml
    (sample_project / "pyproject.toml").write_text("[project]\nname='demo'\nversion='2.0'\n", encoding="utf-8")
    snap2 = builder.build(sample_project)
    changes = detector.detect(snap1, snap2)
    assert changes.has_dependency_changes

    reqs = [
        RequirementV2(requirement_id="REQ-001", normalized_text="Amount positive", source_text=""),
        RequirementV2(requirement_id="REQ-002", normalized_text="Order paid", source_text=""),
    ]
    analyzer = ImpactAnalyzer()
    impact = analyzer.analyze(changes, reqs)

    assert set(impact.impacted_requirement_ids) == {"REQ-001", "REQ-002"}
    assert len(impact.unaffected_requirement_ids) == 0


def test_evidence_invalidation_and_lifecycle_retention():
    store = InMemoryEvidenceStore()
    e1 = Evidence(
        evidence_id="ev-1",
        run_id="run-1",
        kind="behavioral_verification",
        status=EvidenceStatus.OBSERVED,
        claim="Amount positive verified",
        requirement_id="REQ-001",
    )
    e2 = Evidence(
        evidence_id="ev-2",
        run_id="run-1",
        kind="behavioral_verification",
        status=EvidenceStatus.OBSERVED,
        claim="Customer verified",
        requirement_id="REQ-003",
    )
    store.save_evidence(e1)
    store.save_evidence(e2)

    engine = ContinuousAssuranceEngine(store=store)
    impact = ImpactAnalysis(
        impact_id="imp-1",
        changeset_id="ch-1",
        impacted_requirement_ids=("REQ-001",),
        unaffected_requirement_ids=("REQ-003",),
        stale_evidence_ids=("ev-1",),
    )

    records = engine.invalidate_stale_evidence(impact, "ch-1")
    assert len(records) == 1
    assert records[0].evidence_id == "ev-1"
    assert records[0].state == EvidenceLifecycleState.STALE

    # Historical evidence is retained in the store!
    assert store.get_evidence("ev-1") is not None
    assert store.get_evidence("ev-2") is not None

    # Lifecycle query
    lifecycle = store.get_lifecycle_record("ev-1")
    assert lifecycle is not None
    assert lifecycle.state == EvidenceLifecycleState.STALE
    assert store.get_lifecycle_record("ev-2") is None


def test_evaluation_planner_selection():
    target_snap = ProjectSnapshot(
        snapshot_id="snap-target",
        project_root="/path",
        requirement_hashes={"REQ-001": "h1", "REQ-002": "h2"},
    )
    f1 = Finding(
        finding_id="find-1",
        requirement_id="REQ-001",
        category="compliance",
        severity="info",
        verdict="passed",
        compliance_status=ComplianceStatus.COMPLIANT,
        test_effectiveness_status=TestEffectiveness.DETECTED,
        verification_mode=VerificationMode.DYNAMIC,
        message="Ok",
    )
    f2 = Finding(
        finding_id="find-2",
        requirement_id="REQ-002",
        category="compliance",
        severity="info",
        verdict="passed",
        compliance_status=ComplianceStatus.COMPLIANT,
        test_effectiveness_status=TestEffectiveness.DETECTED,
        verification_mode=VerificationMode.DYNAMIC,
        message="Ok",
    )
    impact = ImpactAnalysis(
        impact_id="imp-1",
        changeset_id="ch-1",
        impacted_requirement_ids=("REQ-001",),
        unaffected_requirement_ids=("REQ-002",),
        stale_finding_ids=("find-1",),
    )

    planner = EvaluationPlanner()
    plan = planner.plan(impact, target_snap, all_findings=[f1, f2])

    assert plan.total_requirements == 2
    assert plan.rerun_count == 1
    assert plan.reuse_count == 1

    item1 = next(it for it in plan.items if it.requirement_id == "REQ-001")
    assert item1.action == PlanActionKind.RERUN

    item2 = next(it for it in plan.items if it.requirement_id == "REQ-002")
    assert item2.action == PlanActionKind.REUSE
    assert "find-2" in item2.reusable_finding_ids


def test_run_comparison_and_regression_detection():
    base_run = EvaluationRun(
        run_id="run-base",
        project_id="demo",
        revision_id="rev-1",
        policy=RunPolicy("p-1"),
        status=RunStatus.COMPLETED,
    )
    target_run = EvaluationRun(
        run_id="run-target",
        project_id="demo",
        revision_id="rev-2",
        policy=RunPolicy("p-1"),
        status=RunStatus.COMPLETED,
    )

    # Base findings: REQ-001 is compliant, REQ-002 detected
    f_base_1 = Finding("fb-1", "REQ-001", "behavioral", "info", "passed", ComplianceStatus.COMPLIANT, TestEffectiveness.DETECTED, VerificationMode.DYNAMIC, "OK")
    f_base_2 = Finding("fb-2", "REQ-002", "mutation", "info", "killed", ComplianceStatus.UNKNOWN, TestEffectiveness.DETECTED, VerificationMode.MUTATION, "OK")

    # Target findings: REQ-001 becomes violation, REQ-002 becomes survived
    f_target_1 = Finding("ft-1", "REQ-001", "behavioral", "error", "violation", ComplianceStatus.VIOLATION, TestEffectiveness.DETECTED, VerificationMode.DYNAMIC, "Violation")
    f_target_2 = Finding("ft-2", "REQ-002", "mutation", "warning", "survived", ComplianceStatus.UNKNOWN, TestEffectiveness.SURVIVED, VerificationMode.MUTATION, "Survived")

    comparator = RunComparator()
    comparison = comparator.compare(
        base_run,
        target_run,
        [f_base_1, f_base_2],
        [f_target_1, f_target_2],
    )

    assert comparison.counts["regressed"] == 2
    reg_kinds = {r.requirement_id: r.kind for r in comparison.regressions}
    assert reg_kinds.get("REQ-001") == RegressionKind.COMPLIANCE_REGRESSION
    assert reg_kinds.get("REQ-002") == RegressionKind.EFFECTIVENESS_REGRESSION
    assert all(r.is_requirement_change is False for r in comparison.regressions)

    # Now verify with requirement change: if REQ-001 was intentionally modified
    rc = [RequirementChange(requirement_id="REQ-001", kind=RequirementChangeKind.MODIFIED)]
    comparison2 = comparator.compare(
        base_run,
        target_run,
        [f_base_1, f_base_2],
        [f_target_1, f_target_2],
        requirement_changes=rc,
    )
    reg1 = next(r for r in comparison2.regressions if r.requirement_id == "REQ-001")
    assert reg1.is_requirement_change is True  # distinguished from unintentional regression


def test_sqlite_persistence_and_restart_durability(tmp_path):
    db_file = tmp_path / "evidence.db"
    store1 = SQLiteEvidenceStore(db_file)

    snap = ProjectSnapshot("snap-1", str(tmp_path), 1000.0, {"a.py": "hash_a"}, {"a.py": "source"}, {"REQ-1": "h_req"})
    store1.save_snapshot(snap)

    cs = ChangeSet("change-1", "snap-0", "snap-1", (ChangeRecord("a.py", FileChangeKind.MODIFIED),), ())
    store1.save_changeset(cs)

    plan = EvaluationPlan("plan-1", "imp-1", "run-0", "snap-1", (EvaluationPlanItem("item-1", "REQ-1", PlanActionKind.RERUN),), 1, 1, 0, 0)
    store1.save_plan(plan)

    comp = RunComparison("comp-1", "run-0", "run-1", 1000.0, (), (), {"regressed": 0}, "clean")
    store1.save_comparison(comp)

    rec = EvidenceLifecycleRecord("rec-1", "ev-1", EvidenceLifecycleState.STALE, "stale input", 1000.0)
    store1.save_lifecycle_record(rec)

    mon = MonitoringConfiguration("mon-1", "proj-1", str(tmp_path))
    store1.save_monitoring_config(mon)

    store1.close()

    # Restart store from disk
    store2 = SQLiteEvidenceStore(db_file)

    loaded_snap = store2.get_snapshot("snap-1")
    assert loaded_snap is not None
    assert loaded_snap.snapshot_id == "snap-1"
    assert loaded_snap.files == {"a.py": "hash_a"}

    loaded_cs = store2.get_changeset("change-1")
    assert loaded_cs is not None
    assert loaded_cs.file_changes[0].path == "a.py"

    loaded_plan = store2.get_plan("plan-1")
    assert loaded_plan is not None
    assert loaded_plan.items[0].requirement_id == "REQ-1"

    loaded_comp = store2.get_comparison("comp-1")
    assert loaded_comp is not None
    assert loaded_comp.summary == "clean"

    loaded_rec = store2.get_lifecycle_record("ev-1")
    assert loaded_rec is not None
    assert loaded_rec.state == EvidenceLifecycleState.STALE

    loaded_mon = store2.get_monitoring_config("mon-1")
    assert loaded_mon is not None
    assert loaded_mon.project_id == "proj-1"

    store2.close()


def test_safe_execution_and_symlink_rejection(tmp_path):
    root = tmp_path / "unsafe_proj"
    root.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("secret", encoding="utf-8")

    link = root / "symlink_to_outside"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation not permitted on this platform/privilege level")

    builder = SnapshotBuilder()
    with pytest.raises(ValueError, match="Unsafe symlink escapes project root"):
        builder.build(root)


def test_repository_monitor_check(sample_project):
    builder = SnapshotBuilder()
    detector = ChangeDetector()
    monitor = RepositoryMonitor(builder=builder, detector=detector)

    config = MonitoringConfiguration("cfg-1", "p-1", str(sample_project))

    # First check: returns False, None, and initial snapshot
    has_changes, changeset, snap1 = monitor.check_for_changes(config, None)
    assert not has_changes
    assert changeset is None
    assert snap1 is not None

    # Check again without changes: returns False, None, snap2
    has_changes, changeset, snap2 = monitor.check_for_changes(config, snap1)
    assert not has_changes
    assert changeset is None

    # Add a file
    (sample_project / "new_module.py").write_text("X = 1\n", encoding="utf-8")
    has_changes, changeset, snap3 = monitor.check_for_changes(config, snap2)
    assert has_changes
    assert changeset is not None
    assert any(c.path == "new_module.py" for c in changeset.file_changes)


def test_api_v2_continuous_assurance_endpoints(sample_project):
    store = InMemoryEvidenceStore()
    app = create_app(evidence_store=store)
    client = TestClient(app)

    # V1 health check preserved
    v1_health = client.get("/api/v1/health")
    assert v1_health.status_code == 200
    assert v1_health.json()["version"] == "1.0.0"

    # V2 health check
    v2_health = client.get("/api/v2/health")
    assert v2_health.status_code == 200
    assert v2_health.json()["version"] == "2.0.0"

    # Snapshot creation
    snap_resp = client.post("/api/v2/snapshots", json={"project_path": str(sample_project)})
    assert snap_resp.status_code == 201
    snap_data = snap_resp.json()
    snap_id = snap_data["snapshot_id"]

    # Snapshot retrieval
    get_snap = client.get(f"/api/v2/snapshots/{snap_id}")
    assert get_snap.status_code == 200
    assert get_snap.json()["snapshot_id"] == snap_id

    # Change detection (initial)
    detect_resp = client.post("/api/v2/changes/detect", json={"target_snapshot_id": snap_id})
    assert detect_resp.status_code == 200
    changeset = detect_resp.json()
    changeset_id = changeset["changeset_id"]

    # Impact analysis
    impact_resp = client.post("/api/v2/impact/analyze", json={"changeset_id": changeset_id, "project_path": str(sample_project)})
    assert impact_resp.status_code == 200
    impact = impact_resp.json()
    impact_id = impact["impact_id"]

    # Plan generation
    plan_resp = client.post("/api/v2/plans/generate", json={"impact_id": impact_id, "target_snapshot_id": snap_id})
    assert plan_resp.status_code == 201
    plan = plan_resp.json()
    plan_id = plan["plan_id"]

    # Plan retrieval
    get_plan = client.get(f"/api/v2/plans/{plan_id}")
    assert get_plan.status_code == 200
    assert get_plan.json()["plan_id"] == plan_id

    # Monitoring config
    mon_resp = client.post("/api/v2/monitoring/config", json={"project_id": "proj-1", "root_path": str(sample_project)})
    assert mon_resp.status_code == 201
    cfg_id = mon_resp.json()["config_id"]

    # Monitoring check
    chk_resp = client.post("/api/v2/monitoring/check", json={"config_id": cfg_id, "last_snapshot_id": snap_id})
    assert chk_resp.status_code == 200
    assert "has_changes" in chk_resp.json()


def test_phase6_end_to_end_complete_workflow(sample_project):
    """Demonstrates the complete Phase 6 Continuous Assurance workflow from Section 12:

    1. Create a project snapshot.
    2. Run an initial evaluation.
    3. Modify a source file.
    4. Detect the change.
    5. Identify impacted requirements.
    6. Identify stale evidence.
    7. Generate an incremental evaluation plan.
    8. Execute the necessary reevaluation safely.
    9. Compare the previous and current runs.
    10. Identify regressions where supported.
    11. Preserve historical evidence.
    12. Show unaffected findings remain valid where appropriate.
    """
    store = InMemoryEvidenceStore()
    engine = ContinuousAssuranceEngine(store=store)

    # 1. Create a project snapshot
    snap1 = engine.create_snapshot(sample_project)
    assert snap1.snapshot_id.startswith("snap-")
    assert "demo/service.py" in snap1.files
    assert "REQ-001" in snap1.requirement_hashes

    # 2. Run an initial evaluation
    # Seed initial findings and evidence for REQ-001, REQ-002, REQ-003
    ev1 = Evidence("ev-r1-req1", "run-1", "behavioral", EvidenceStatus.VERIFIED, "Amount positive", "REQ-001")
    ev2 = Evidence("ev-r1-req2", "run-1", "behavioral", EvidenceStatus.VERIFIED, "Order paid", "REQ-002")
    ev3 = Evidence("ev-r1-req3", "run-1", "behavioral", EvidenceStatus.VERIFIED, "Customer verified", "REQ-003")
    store.save_evidence(ev1)
    store.save_evidence(ev2)
    store.save_evidence(ev3)

    f1 = Finding("find-r1-req1", "REQ-001", "compliance", "info", "passed", ComplianceStatus.COMPLIANT, TestEffectiveness.DETECTED, VerificationMode.DYNAMIC, "OK", evidence_ids=("ev-r1-req1",))
    f2 = Finding("find-r1-req2", "REQ-002", "compliance", "info", "passed", ComplianceStatus.COMPLIANT, TestEffectiveness.DETECTED, VerificationMode.DYNAMIC, "OK", evidence_ids=("ev-r1-req2",))
    f3 = Finding("find-r1-req3", "REQ-003", "compliance", "info", "passed", ComplianceStatus.COMPLIANT, TestEffectiveness.DETECTED, VerificationMode.DYNAMIC, "OK", evidence_ids=("ev-r1-req3",))
    store.save_finding(f1)
    store.save_finding(f2)
    store.save_finding(f3)

    run1 = EvaluationRun(
        run_id="run-1",
        project_id=str(sample_project),
        revision_id=snap1.snapshot_id,
        policy=RunPolicy("p-1"),
        status=RunStatus.COMPLETED,
        finding_ids=("find-r1-req1", "find-r1-req2", "find-r1-req3"),
        evidence_ids=("ev-r1-req1", "ev-r1-req2", "ev-r1-req3"),
        counts={"compliant": 3, "violation": 0},
    )
    store.save_run(run1)

    # 3. Modify a source file (break validate_amount logic)
    service_file = sample_project / "demo" / "service.py"
    service_file.write_text(
        "# req: REQ-001\n"
        "def validate_amount(amt):\n"
        "    # Removed non-positive check; causes regression\n"
        "    return amt\n\n"
        "# req: REQ-002\n"
        "def process_order(order, amt):\n"
        "    validate_amount(amt)\n"
        "    if order.get('status') != 'paid':\n"
        "        raise ValueError('Order not paid')\n"
        "    return True\n",
        encoding="utf-8",
    )

    # 4. Detect the change
    snap2 = engine.create_snapshot(sample_project)
    changeset = engine.detect_changes(snap1, snap2)
    assert changeset.has_source_changes
    assert any(c.path == "demo/service.py" and c.kind == FileChangeKind.MODIFIED for c in changeset.file_changes)

    # 5. Identify impacted requirements
    # Traceability links
    sym1 = CodeSymbol("sym-v", "art-1", "python", "function", "service.validate_amount", {"path": "demo/service.py"})
    sym2 = CodeSymbol("sym-p", "art-1", "python", "function", "service.process_order", {"path": "demo/service.py"}, calls=("sym-v",))
    trace = [
        TraceabilityLink("t1", "REQ-001", "sym-v", "code_symbol", "implemented_by", "explicit_marker", 1.0),
        TraceabilityLink("t2", "REQ-002", "sym-p", "code_symbol", "implemented_by", "explicit_marker", 1.0),
    ]
    reqs = [
        RequirementV2("REQ-001", "Amount must be positive", ""),
        RequirementV2("REQ-002", "Order status must be paid", "", dependencies=("REQ-001",)),
        RequirementV2("REQ-003", "Customer must be verified", ""),
    ]

    impact = engine.analyze_impact(
        changeset,
        reqs,
        symbols=[sym1, sym2],
        traceability=trace,
        evidence=store.list_evidence(),
        findings=store.list_findings(),
    )
    assert "REQ-001" in impact.impacted_requirement_ids
    assert "REQ-002" in impact.impacted_requirement_ids
    assert "REQ-003" in impact.unaffected_requirement_ids

    # 6. Identify stale evidence
    stale_records = engine.invalidate_stale_evidence(impact, changeset.changeset_id)
    assert any(r.evidence_id == "ev-r1-req1" and r.state == EvidenceLifecycleState.STALE for r in stale_records)

    # 7. Generate an incremental evaluation plan
    plan = engine.generate_plan(
        impact,
        snap2,
        base_run=run1,
        all_findings=store.list_findings(),
        all_evidence=store.list_evidence(),
    )
    assert plan.rerun_count == 2
    assert plan.reuse_count == 1
    req3_item = next(it for it in plan.items if it.requirement_id == "REQ-003")
    assert req3_item.action == PlanActionKind.REUSE
    assert "find-r1-req3" in req3_item.reusable_finding_ids
    assert "ev-r1-req3" in req3_item.reusable_evidence_ids

    # 8. Execute the necessary reevaluation safely
    run2 = engine.execute_plan(plan, sample_project, base_run=run1, run_id="run-2")
    assert run2.run_id == "run-2"
    assert run2.status == RunStatus.COMPLETED

    # 9. Compare the previous and current runs
    # Add new findings for run-2 (REQ-001 has violation)
    f1_r2 = Finding("find-r2-req1", "REQ-001", "compliance", "error", "violation", ComplianceStatus.VIOLATION, TestEffectiveness.SURVIVED, VerificationMode.DYNAMIC, "Amount <= 0 allowed", evidence_ids=())
    store.save_finding(f1_r2)
    # Update run-2 finding ids
    run2 = EvaluationRun(
        run_id="run-2",
        project_id=str(sample_project),
        revision_id=snap2.snapshot_id,
        policy=RunPolicy("p-1"),
        status=RunStatus.COMPLETED,
        finding_ids=("find-r2-req1", "find-r1-req3"),  # REQ-001 regressed, REQ-003 reused
    )
    store.save_run(run2)

    comparison = engine.compare_runs(run1.run_id, run2.run_id)

    # 10. Identify regressions where supported
    assert comparison.counts["regressed"] >= 1
    comp_reg = next((r for r in comparison.regressions if r.requirement_id == "REQ-001"), None)
    assert comp_reg is not None
    assert comp_reg.kind == RegressionKind.COMPLIANCE_REGRESSION
    assert comp_reg.is_requirement_change is False  # Genuine code regression!

    # 11. Preserve historical evidence
    # ev-r1-req1 is still safely stored in EvidenceStore
    historical_ev1 = store.get_evidence("ev-r1-req1")
    assert historical_ev1 is not None
    # Marked as STALE in lifecycle
    lifecycle_ev1 = store.get_lifecycle_record("ev-r1-req1")
    assert lifecycle_ev1 is not None
    assert lifecycle_ev1.state == EvidenceLifecycleState.STALE

    # 12. Show unaffected findings remain valid where appropriate
    assert "find-r1-req3" in run2.finding_ids
    reused_f3 = store.get_finding("find-r1-req3")
    assert reused_f3 is not None
    assert reused_f3.compliance_status == ComplianceStatus.COMPLIANT

