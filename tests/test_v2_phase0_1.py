from __future__ import annotations

from pathlib import Path

from specguard.models import AnalysisReport, Classification, Requirement, RequirementResult
from specguard.reporting import report_dict
from specguard.v2.compat import legacy_report_to_v2
from specguard.v2.evidence_store import InMemoryEvidenceStore, SQLiteEvidenceStore
from specguard.v2.models import (
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    EvaluationRun,
    Finding,
    RequirementV2,
    ReproducibilityMetadata,
    RunPolicy,
    RunStatus,
    TestEffectiveness as Effectiveness,
    VerificationMode,
)
from specguard.v2.oracle import ExpectedBehaviorService
from specguard.v2.requirement_intelligence import RequirementIntelligenceEngine


def sample_records():
    requirement = RequirementV2("REQ-001", "Amount must be positive.", "Amount must be positive.")
    repro = ReproducibilityMetadata(input_hashes={"requirements": "abc"}, seed="seed-1")
    evidence = Evidence("e-1", "run-1", "unit", EvidenceStatus.OBSERVED, "observed", requirement_id="REQ-001", reproducibility=repro)
    finding = Finding("f-1", "REQ-001", "ambiguity", "warning", "candidate", ComplianceStatus.UNKNOWN, Effectiveness.NOT_EVALUATED, VerificationMode.STATIC, "candidate", evidence_ids=("e-1",))
    run = EvaluationRun("run-1", "project-1", "revision-1", RunPolicy("policy-1"), RunStatus.COMPLETED, finding_ids=("f-1",), evidence_ids=("e-1",))
    return requirement, evidence, finding, run


def test_versioned_schema_serialization_round_trip():
    requirement, evidence, finding, run = sample_records()
    assert RequirementV2.from_dict(requirement.to_dict()) == requirement
    assert Evidence.from_dict(evidence.to_dict()) == evidence
    assert Finding.from_dict(finding.to_dict()) == finding
    assert EvaluationRun.from_dict(run.to_dict()) == run
    assert evidence.to_dict()["schema_version"] == "2.0"


def test_in_memory_and_sqlite_evidence_stores(tmp_path):
    requirement, evidence, finding, run = sample_records()
    memory = InMemoryEvidenceStore()
    memory.save_evidence(evidence)
    memory.save_finding(finding)
    memory.save_run(run)
    assert memory.get_evidence("e-1") == evidence
    assert memory.list_evidence(run_id="run-1") == [evidence]
    assert memory.get_finding("f-1") == finding
    assert memory.get_run("run-1") == run

    database = SQLiteEvidenceStore(tmp_path / "evidence.db")
    database.save_evidence(evidence)
    database.save_finding(finding)
    database.save_run(run)
    database.close()
    reopened = SQLiteEvidenceStore(tmp_path / "evidence.db")
    assert reopened.get_evidence("e-1") == evidence
    assert reopened.get_finding("f-1") == finding
    assert reopened.get_run("run-1") == run
    reopened.close()


def test_legacy_mutation_results_wrap_without_changing_v1_report():
    report = AnalysisReport(True, "baseline", [
        RequirementResult(Requirement("REQ-001", "Amount must be positive."), Classification.PROTECTED),
    ])
    before = report_dict(report)
    run, findings, evidence = legacy_report_to_v2(report, project_id="project-1", run_id="run-1")
    assert report_dict(report) == before
    assert run.status == RunStatus.COMPLETED
    assert findings[0].compliance_status == ComplianceStatus.UNKNOWN
    assert findings[0].test_effectiveness_status == Effectiveness.DETECTED
    assert evidence[0].status == EvidenceStatus.VERIFIED


def test_requirement_intelligence_finding_types_and_stable_ids(tmp_path):
    requirements = tmp_path / "requirements.md"
    requirements.write_text(
        "# Requirements\n"
        "- [ ] REQ-001: Amount must be positive and account must be active.\n"
        "- [ ] REQ-002: The system may respond soon.\n"
        "- [ ] REQ-003: Amount must be positive.\n"
        "- [ ] REQ-004: Amount must not be positive.\n"
        "- [ ] REQ-005: Depends on REQ-003 and must return a receipt.\n"
    )
    (tmp_path / "app.py").write_text("# specguard: REQ-001\n# specguard: REQ-003\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("# verifies REQ-003\n")
    engine = RequirementIntelligenceEngine()
    first = engine.analyze(requirements, tmp_path, run_id="run-1")
    second = engine.analyze(requirements, tmp_path, run_id="run-1")
    assert [item.requirement_id for item in first.requirements] == ["REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"]
    assert [item.requirement_id for item in first.requirements] == [item.requirement_id for item in second.requirements]
    assert [item.evidence_id for item in first.evidence] == [item.evidence_id for item in second.evidence]
    categories = {item.category for item in first.findings}
    assert {"atomicity_candidate", "ambiguity", "contradiction", "dependency_candidate", "traceability_gap"} <= categories
    contradiction = [item for item in first.findings if item.category == "contradiction"]
    assert contradiction and all(item.compliance_status == ComplianceStatus.UNKNOWN for item in contradiction)
    assert any(item.uncertainty for item in first.behavior_contracts if item.requirement_id == "REQ-002")


def test_expected_behavior_oracle_preserves_uncertainty():
    requirement = RequirementV2("REQ-001", "The system may respond soon.", "The system may respond soon.", ambiguous=True, ambiguity_reasons=("vague language",))
    contract, evidence = ExpectedBehaviorService().derive(requirement, run_id="oracle-run")
    assert contract.uncertainty
    assert evidence.status == EvidenceStatus.OBSERVED
    assert contract.evidence_ids == (evidence.evidence_id,)
