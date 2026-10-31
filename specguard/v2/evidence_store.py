"""Evidence store implementations for SpecGuard V2 persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
import sqlite3
from threading import RLock
from typing import Any

from .models import (
    CandidateValidation,
    ChangeSet,
    EvaluationPlan,
    EvaluationRun,
    Evidence,
    EvidenceLifecycleRecord,
    EvidenceLifecycleState,
    Finding,
    MonitoringConfiguration,
    Mutant,
    MutationRun,
    ProjectSnapshot,
    RunComparison,
    TestCandidate,
    TestCandidateStatus,
    TestEngineeringRun,
    VerificationGap,
)


class EvidenceStore(ABC):
    @abstractmethod
    def save_evidence(self, evidence: Evidence) -> Evidence: ...

    @abstractmethod
    def get_evidence(self, evidence_id: str) -> Evidence | None: ...

    @abstractmethod
    def list_evidence(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Evidence]: ...

    @abstractmethod
    def save_finding(self, finding: Finding) -> Finding: ...

    @abstractmethod
    def get_finding(self, finding_id: str) -> Finding | None: ...

    @abstractmethod
    def list_findings(self, requirement_id: str | None = None) -> list[Finding]: ...

    @abstractmethod
    def save_run(self, run: EvaluationRun) -> EvaluationRun: ...

    @abstractmethod
    def get_run(self, run_id: str) -> EvaluationRun | None: ...

    @abstractmethod
    def save_mutation_run(self, run: MutationRun) -> MutationRun: ...

    @abstractmethod
    def get_mutation_run(self, run_id: str) -> MutationRun | None: ...

    @abstractmethod
    def save_mutant(self, mutant: Mutant) -> Mutant: ...

    @abstractmethod
    def get_mutant(self, mutant_id: str) -> Mutant | None: ...

    @abstractmethod
    def list_mutants(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Mutant]: ...

    @abstractmethod
    def save_gap(self, gap: VerificationGap) -> VerificationGap: ...

    @abstractmethod
    def get_gap(self, gap_id: str) -> VerificationGap | None: ...

    @abstractmethod
    def list_gaps(self, run_id: str | None = None, requirement_id: str | None = None) -> list[VerificationGap]: ...

    @abstractmethod
    def save_candidate(self, candidate: TestCandidate) -> TestCandidate: ...

    @abstractmethod
    def get_candidate(self, candidate_id: str) -> TestCandidate | None: ...

    @abstractmethod
    def list_candidates(self, run_id: str | None = None, requirement_id: str | None = None) -> list[TestCandidate]: ...

    @abstractmethod
    def save_validation(self, validation: CandidateValidation) -> CandidateValidation: ...

    @abstractmethod
    def get_validation(self, validation_id: str) -> CandidateValidation | None: ...

    @abstractmethod
    def list_validations(self, run_id: str | None = None, candidate_id: str | None = None) -> list[CandidateValidation]: ...

    @abstractmethod
    def save_test_engineering_run(self, run: TestEngineeringRun) -> TestEngineeringRun: ...

    @abstractmethod
    def get_test_engineering_run(self, run_id: str) -> TestEngineeringRun | None: ...

    @abstractmethod
    def save_snapshot(self, snapshot: ProjectSnapshot) -> ProjectSnapshot: ...

    @abstractmethod
    def get_snapshot(self, snapshot_id: str) -> ProjectSnapshot | None: ...

    @abstractmethod
    def list_snapshots(self, project_root: str | None = None) -> list[ProjectSnapshot]: ...

    @abstractmethod
    def save_changeset(self, changeset: ChangeSet) -> ChangeSet: ...

    @abstractmethod
    def get_changeset(self, changeset_id: str) -> ChangeSet | None: ...

    @abstractmethod
    def save_plan(self, plan: EvaluationPlan) -> EvaluationPlan: ...

    @abstractmethod
    def get_plan(self, plan_id: str) -> EvaluationPlan | None: ...

    @abstractmethod
    def save_comparison(self, comparison: RunComparison) -> RunComparison: ...

    @abstractmethod
    def get_comparison(self, comparison_id: str) -> RunComparison | None: ...

    @abstractmethod
    def save_lifecycle_record(self, record: EvidenceLifecycleRecord) -> EvidenceLifecycleRecord: ...

    @abstractmethod
    def get_lifecycle_record(self, evidence_id: str) -> EvidenceLifecycleRecord | None: ...

    @abstractmethod
    def list_lifecycle_records(self, state: EvidenceLifecycleState | None = None, evidence_id: str | None = None) -> list[EvidenceLifecycleRecord]: ...

    @abstractmethod
    def save_monitoring_config(self, config: MonitoringConfiguration) -> MonitoringConfiguration: ...

    @abstractmethod
    def get_monitoring_config(self, config_id: str) -> MonitoringConfiguration | None: ...


class InMemoryEvidenceStore(EvidenceStore):
    def __init__(self):
        self._evidence: dict[str, Evidence] = {}
        self._findings: dict[str, Finding] = {}
        self._runs: dict[str, EvaluationRun] = {}
        self._mutation_runs: dict[str, MutationRun] = {}
        self._mutants: dict[str, Mutant] = {}
        self._gaps: dict[str, VerificationGap] = {}
        self._candidates: dict[str, TestCandidate] = {}
        self._validations: dict[str, CandidateValidation] = {}
        self._test_engineering_runs: dict[str, TestEngineeringRun] = {}
        self._snapshots: dict[str, ProjectSnapshot] = {}
        self._changesets: dict[str, ChangeSet] = {}
        self._plans: dict[str, EvaluationPlan] = {}
        self._comparisons: dict[str, RunComparison] = {}
        self._lifecycle: dict[str, EvidenceLifecycleRecord] = {}
        self._monitoring: dict[str, MonitoringConfiguration] = {}

    def save_evidence(self, evidence: Evidence) -> Evidence:
        self._evidence[evidence.evidence_id] = evidence
        return evidence

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        return self._evidence.get(evidence_id)

    def list_evidence(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Evidence]:
        return [item for item in self._evidence.values() if (run_id is None or item.run_id == run_id) and (requirement_id is None or item.requirement_id == requirement_id)]

    def save_finding(self, finding: Finding) -> Finding:
        self._findings[finding.finding_id] = finding
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def list_findings(self, requirement_id: str | None = None) -> list[Finding]:
        return [item for item in self._findings.values() if requirement_id is None or item.requirement_id == requirement_id]

    def save_run(self, run: EvaluationRun) -> EvaluationRun:
        self._runs[run.run_id] = run
        return run

    def get_run(self, run_id: str) -> EvaluationRun | None:
        return self._runs.get(run_id)

    def save_mutation_run(self, run: MutationRun) -> MutationRun:
        self._mutation_runs[run.run_id] = run
        return run

    def get_mutation_run(self, run_id: str) -> MutationRun | None:
        return self._mutation_runs.get(run_id)

    def save_mutant(self, mutant: Mutant) -> Mutant:
        self._mutants[mutant.mutant_id] = mutant
        return mutant

    def get_mutant(self, mutant_id: str) -> Mutant | None:
        return self._mutants.get(mutant_id)

    def list_mutants(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Mutant]:
        return [item for item in self._mutants.values() if (run_id is None or item.run_id == run_id) and (requirement_id is None or item.requirement_id == requirement_id)]

    def save_gap(self, gap: VerificationGap) -> VerificationGap:
        self._gaps[gap.gap_id] = gap
        return gap

    def get_gap(self, gap_id: str) -> VerificationGap | None:
        return self._gaps.get(gap_id)

    def list_gaps(self, run_id: str | None = None, requirement_id: str | None = None) -> list[VerificationGap]:
        return [item for item in self._gaps.values() if (run_id is None or item.run_id == run_id) and (requirement_id is None or item.requirement_id == requirement_id)]

    def save_candidate(self, candidate: TestCandidate) -> TestCandidate:
        self._candidates[candidate.candidate_id] = candidate
        return candidate

    def get_candidate(self, candidate_id: str) -> TestCandidate | None:
        return self._candidates.get(candidate_id)

    def list_candidates(self, run_id: str | None = None, requirement_id: str | None = None) -> list[TestCandidate]:
        return [item for item in self._candidates.values() if (run_id is None or item.run_id == run_id) and (requirement_id is None or item.requirement_id == requirement_id)]

    def save_validation(self, validation: CandidateValidation) -> CandidateValidation:
        self._validations[validation.validation_id] = validation
        return validation

    def get_validation(self, validation_id: str) -> CandidateValidation | None:
        return self._validations.get(validation_id)

    def list_validations(self, run_id: str | None = None, candidate_id: str | None = None) -> list[CandidateValidation]:
        return [item for item in self._validations.values() if (run_id is None or item.run_id == run_id) and (candidate_id is None or item.candidate_id == candidate_id)]

    def save_test_engineering_run(self, run: TestEngineeringRun) -> TestEngineeringRun:
        self._test_engineering_runs[run.run_id] = run
        return run

    def get_test_engineering_run(self, run_id: str) -> TestEngineeringRun | None:
        return self._test_engineering_runs.get(run_id)

    def save_snapshot(self, snapshot: ProjectSnapshot) -> ProjectSnapshot:
        self._snapshots[snapshot.snapshot_id] = snapshot
        return snapshot

    def get_snapshot(self, snapshot_id: str) -> ProjectSnapshot | None:
        return self._snapshots.get(snapshot_id)

    def list_snapshots(self, project_root: str | None = None) -> list[ProjectSnapshot]:
        return [item for item in self._snapshots.values() if project_root is None or item.project_root == project_root]

    def save_changeset(self, changeset: ChangeSet) -> ChangeSet:
        self._changesets[changeset.changeset_id] = changeset
        return changeset

    def get_changeset(self, changeset_id: str) -> ChangeSet | None:
        return self._changesets.get(changeset_id)

    def save_plan(self, plan: EvaluationPlan) -> EvaluationPlan:
        self._plans[plan.plan_id] = plan
        return plan

    def get_plan(self, plan_id: str) -> EvaluationPlan | None:
        return self._plans.get(plan_id)

    def save_comparison(self, comparison: RunComparison) -> RunComparison:
        self._comparisons[comparison.comparison_id] = comparison
        return comparison

    def get_comparison(self, comparison_id: str) -> RunComparison | None:
        return self._comparisons.get(comparison_id)

    def save_lifecycle_record(self, record: EvidenceLifecycleRecord) -> EvidenceLifecycleRecord:
        self._lifecycle[record.record_id] = record
        return record

    def get_lifecycle_record(self, evidence_id: str) -> EvidenceLifecycleRecord | None:
        records = [r for r in self._lifecycle.values() if r.evidence_id == evidence_id]
        if not records:
            return None
        return records[-1]

    def list_lifecycle_records(self, state: EvidenceLifecycleState | None = None, evidence_id: str | None = None) -> list[EvidenceLifecycleRecord]:
        return [item for item in self._lifecycle.values() if (state is None or item.state == state) and (evidence_id is None or item.evidence_id == evidence_id)]

    def save_monitoring_config(self, config: MonitoringConfiguration) -> MonitoringConfiguration:
        self._monitoring[config.config_id] = config
        return config

    def get_monitoring_config(self, config_id: str) -> MonitoringConfiguration | None:
        return self._monitoring.get(config_id)


class SQLiteEvidenceStore(EvidenceStore):
    def __init__(self, database_path: str):
        self._database_path = database_path
        self._lock = RLock()
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                requirement_id TEXT,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_requirement ON evidence(requirement_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                requirement_id TEXT,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_requirement ON findings(requirement_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_project ON runs(project_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS mutation_runs (
                run_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_mutation_runs_project ON mutation_runs(project_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS mutants (
                mutant_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                requirement_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_mutants_run ON mutants(run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_mutants_requirement ON mutants(requirement_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS verification_gaps (
                gap_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                requirement_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_gaps_run ON verification_gaps(run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_gaps_requirement ON verification_gaps(requirement_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS test_candidates (
                candidate_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                requirement_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_candidates_run ON test_candidates(run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_candidates_requirement ON test_candidates(requirement_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS candidate_validations (
                validation_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_validations_run ON candidate_validations(run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_validations_candidate ON candidate_validations(candidate_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS test_engineering_runs (
                run_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_test_engineering_runs_project ON test_engineering_runs(project_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                project_root TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_snapshots_root ON snapshots(project_root);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS changesets (
                changeset_id TEXT PRIMARY KEY,
                base_snapshot_id TEXT NOT NULL,
                target_snapshot_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_changesets_base ON changesets(base_snapshot_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_changesets_target ON changesets(target_snapshot_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_plans (
                plan_id TEXT PRIMARY KEY,
                impact_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_plans_impact ON evaluation_plans(impact_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS run_comparisons (
                comparison_id TEXT PRIMARY KEY,
                base_run_id TEXT NOT NULL,
                target_run_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_comparisons_base ON run_comparisons(base_run_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_comparisons_target ON run_comparisons(target_run_id);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence_lifecycle (
                record_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                state TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_lifecycle_evidence ON evidence_lifecycle(evidence_id);
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_lifecycle_state ON evidence_lifecycle(state);
            """)
            self._connection.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_configs (
                config_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """)
            self._connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_monitoring_proj ON monitoring_configs(project_id);
            """)
            self._connection.commit()

    def _save(self, table: str, key: str, payload: str, columns: tuple[str, ...], values: tuple[object, ...]) -> None:
        placeholders = ", ".join("?" for _ in values)
        column_names = ", ".join(columns)
        updates = ", ".join(f"{column}=excluded.{column}" for column in columns[1:])
        with self._lock:
            self._connection.execute(
                f"INSERT INTO {table} ({column_names}) VALUES ({placeholders}) "
                f"ON CONFLICT({columns[0]}) DO UPDATE SET {updates}",
                values,
            )
            self._connection.commit()

    def save_evidence(self, evidence: Evidence) -> Evidence:
        self._save("evidence", evidence.evidence_id, evidence.to_json(), ("evidence_id", "run_id", "requirement_id", "payload"), (evidence.evidence_id, evidence.run_id, evidence.requirement_id, evidence.to_json()))
        return evidence

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        row = self._connection.execute("SELECT payload FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        return Evidence.from_dict(json.loads(row[0])) if row else None

    def list_evidence(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Evidence]:
        query = "SELECT payload FROM evidence WHERE 1=1"
        values: list[object] = []
        if run_id is not None:
            query += " AND run_id=?"
            values.append(run_id)
        if requirement_id is not None:
            query += " AND requirement_id=?"
            values.append(requirement_id)
        return [Evidence.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_finding(self, finding: Finding) -> Finding:
        self._save("findings", finding.finding_id, finding.to_json(), ("finding_id", "requirement_id", "payload"), (finding.finding_id, finding.requirement_id, finding.to_json()))
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._connection.execute("SELECT payload FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return Finding.from_dict(json.loads(row[0])) if row else None

    def list_findings(self, requirement_id: str | None = None) -> list[Finding]:
        query = "SELECT payload FROM findings WHERE 1=1"
        values: list[object] = []
        if requirement_id is not None:
            query += " AND requirement_id=?"
            values.append(requirement_id)
        return [Finding.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_run(self, run: EvaluationRun) -> EvaluationRun:
        self._save("runs", run.run_id, run.to_json(), ("run_id", "project_id", "payload"), (run.run_id, run.project_id, run.to_json()))
        return run

    def get_run(self, run_id: str) -> EvaluationRun | None:
        row = self._connection.execute("SELECT payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return EvaluationRun.from_dict(json.loads(row[0])) if row else None

    def save_mutation_run(self, run: MutationRun) -> MutationRun:
        self._save("mutation_runs", run.run_id, run.to_json(), ("run_id", "project_id", "payload"), (run.run_id, run.project_id, run.to_json()))
        return run

    def get_mutation_run(self, run_id: str) -> MutationRun | None:
        row = self._connection.execute("SELECT payload FROM mutation_runs WHERE run_id=?", (run_id,)).fetchone()
        return MutationRun.from_dict(json.loads(row[0])) if row else None

    def save_mutant(self, mutant: Mutant) -> Mutant:
        self._save("mutants", mutant.mutant_id, mutant.to_json(), ("mutant_id", "run_id", "requirement_id", "payload"), (mutant.mutant_id, mutant.run_id, mutant.requirement_id, mutant.to_json()))
        return mutant

    def get_mutant(self, mutant_id: str) -> Mutant | None:
        row = self._connection.execute("SELECT payload FROM mutants WHERE mutant_id=?", (mutant_id,)).fetchone()
        return Mutant.from_dict(json.loads(row[0])) if row else None

    def list_mutants(self, run_id: str | None = None, requirement_id: str | None = None) -> list[Mutant]:
        query = "SELECT payload FROM mutants WHERE 1=1"
        values: list[object] = []
        if run_id is not None:
            query += " AND run_id=?"
            values.append(run_id)
        if requirement_id is not None:
            query += " AND requirement_id=?"
            values.append(requirement_id)
        return [Mutant.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_gap(self, gap: VerificationGap) -> VerificationGap:
        self._save("verification_gaps", gap.gap_id, gap.to_json(), ("gap_id", "run_id", "requirement_id", "payload"), (gap.gap_id, gap.run_id, gap.requirement_id, gap.to_json()))
        return gap

    def get_gap(self, gap_id: str) -> VerificationGap | None:
        row = self._connection.execute("SELECT payload FROM verification_gaps WHERE gap_id=?", (gap_id,)).fetchone()
        return VerificationGap.from_dict(json.loads(row[0])) if row else None

    def list_gaps(self, run_id: str | None = None, requirement_id: str | None = None) -> list[VerificationGap]:
        query = "SELECT payload FROM verification_gaps WHERE 1=1"
        values: list[object] = []
        if run_id is not None:
            query += " AND run_id=?"
            values.append(run_id)
        if requirement_id is not None:
            query += " AND requirement_id=?"
            values.append(requirement_id)
        return [VerificationGap.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_candidate(self, candidate: TestCandidate) -> TestCandidate:
        self._save("test_candidates", candidate.candidate_id, candidate.to_json(), ("candidate_id", "run_id", "requirement_id", "payload"), (candidate.candidate_id, candidate.run_id, candidate.requirement_id, candidate.to_json()))
        return candidate

    def get_candidate(self, candidate_id: str) -> TestCandidate | None:
        row = self._connection.execute("SELECT payload FROM test_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
        return TestCandidate.from_dict(json.loads(row[0])) if row else None

    def list_candidates(self, run_id: str | None = None, requirement_id: str | None = None) -> list[TestCandidate]:
        query = "SELECT payload FROM test_candidates WHERE 1=1"
        values: list[object] = []
        if run_id is not None:
            query += " AND run_id=?"
            values.append(run_id)
        if requirement_id is not None:
            query += " AND requirement_id=?"
            values.append(requirement_id)
        return [TestCandidate.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_validation(self, validation: CandidateValidation) -> CandidateValidation:
        self._save("candidate_validations", validation.validation_id, validation.to_json(), ("validation_id", "run_id", "candidate_id", "payload"), (validation.validation_id, validation.run_id, validation.candidate_id, validation.to_json()))
        return validation

    def get_validation(self, validation_id: str) -> CandidateValidation | None:
        row = self._connection.execute("SELECT payload FROM candidate_validations WHERE validation_id=?", (validation_id,)).fetchone()
        return CandidateValidation.from_dict(json.loads(row[0])) if row else None

    def list_validations(self, run_id: str | None = None, candidate_id: str | None = None) -> list[CandidateValidation]:
        query = "SELECT payload FROM candidate_validations WHERE 1=1"
        values: list[object] = []
        if run_id is not None:
            query += " AND run_id=?"
            values.append(run_id)
        if candidate_id is not None:
            query += " AND candidate_id=?"
            values.append(candidate_id)
        return [CandidateValidation.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_test_engineering_run(self, run: TestEngineeringRun) -> TestEngineeringRun:
        self._save("test_engineering_runs", run.run_id, run.to_json(), ("run_id", "project_id", "payload"), (run.run_id, run.project_id, run.to_json()))
        return run

    def get_test_engineering_run(self, run_id: str) -> TestEngineeringRun | None:
        row = self._connection.execute("SELECT payload FROM test_engineering_runs WHERE run_id=?", (run_id,)).fetchone()
        return TestEngineeringRun.from_dict(json.loads(row[0])) if row else None

    def save_snapshot(self, snapshot: ProjectSnapshot) -> ProjectSnapshot:
        self._save("snapshots", snapshot.snapshot_id, snapshot.to_json(), ("snapshot_id", "project_root", "payload"), (snapshot.snapshot_id, snapshot.project_root, snapshot.to_json()))
        return snapshot

    def get_snapshot(self, snapshot_id: str) -> ProjectSnapshot | None:
        row = self._connection.execute("SELECT payload FROM snapshots WHERE snapshot_id=?", (snapshot_id,)).fetchone()
        return ProjectSnapshot.from_dict(json.loads(row[0])) if row else None

    def list_snapshots(self, project_root: str | None = None) -> list[ProjectSnapshot]:
        query = "SELECT payload FROM snapshots WHERE 1=1"
        values: list[object] = []
        if project_root is not None:
            query += " AND project_root=?"
            values.append(project_root)
        return [ProjectSnapshot.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_changeset(self, changeset: ChangeSet) -> ChangeSet:
        self._save("changesets", changeset.changeset_id, changeset.to_json(), ("changeset_id", "base_snapshot_id", "target_snapshot_id", "payload"), (changeset.changeset_id, changeset.base_snapshot_id, changeset.target_snapshot_id, changeset.to_json()))
        return changeset

    def get_changeset(self, changeset_id: str) -> ChangeSet | None:
        row = self._connection.execute("SELECT payload FROM changesets WHERE changeset_id=?", (changeset_id,)).fetchone()
        return ChangeSet.from_dict(json.loads(row[0])) if row else None

    def save_plan(self, plan: EvaluationPlan) -> EvaluationPlan:
        self._save("evaluation_plans", plan.plan_id, plan.to_json(), ("plan_id", "impact_id", "payload"), (plan.plan_id, plan.impact_id, plan.to_json()))
        return plan

    def get_plan(self, plan_id: str) -> EvaluationPlan | None:
        row = self._connection.execute("SELECT payload FROM evaluation_plans WHERE plan_id=?", (plan_id,)).fetchone()
        return EvaluationPlan.from_dict(json.loads(row[0])) if row else None

    def save_comparison(self, comparison: RunComparison) -> RunComparison:
        self._save("run_comparisons", comparison.comparison_id, comparison.to_json(), ("comparison_id", "base_run_id", "target_run_id", "payload"), (comparison.comparison_id, comparison.base_run_id, comparison.target_run_id, comparison.to_json()))
        return comparison

    def get_comparison(self, comparison_id: str) -> RunComparison | None:
        row = self._connection.execute("SELECT payload FROM run_comparisons WHERE comparison_id=?", (comparison_id,)).fetchone()
        return RunComparison.from_dict(json.loads(row[0])) if row else None

    def save_lifecycle_record(self, record: EvidenceLifecycleRecord) -> EvidenceLifecycleRecord:
        self._save("evidence_lifecycle", record.record_id, record.to_json(), ("record_id", "evidence_id", "state", "payload"), (record.record_id, record.evidence_id, record.state.value if hasattr(record.state, "value") else str(record.state), record.to_json()))
        return record

    def get_lifecycle_record(self, evidence_id: str) -> EvidenceLifecycleRecord | None:
        row = self._connection.execute("SELECT payload FROM evidence_lifecycle WHERE evidence_id=? ORDER BY ROWID DESC LIMIT 1", (evidence_id,)).fetchone()
        return EvidenceLifecycleRecord.from_dict(json.loads(row[0])) if row else None

    def list_lifecycle_records(self, state: EvidenceLifecycleState | None = None, evidence_id: str | None = None) -> list[EvidenceLifecycleRecord]:
        query = "SELECT payload FROM evidence_lifecycle WHERE 1=1"
        values: list[object] = []
        if state is not None:
            query += " AND state=?"
            values.append(state.value if hasattr(state, "value") else str(state))
        if evidence_id is not None:
            query += " AND evidence_id=?"
            values.append(evidence_id)
        return [EvidenceLifecycleRecord.from_dict(json.loads(row[0])) for row in self._connection.execute(query, values).fetchall()]

    def save_monitoring_config(self, config: MonitoringConfiguration) -> MonitoringConfiguration:
        self._save("monitoring_configs", config.config_id, config.to_json(), ("config_id", "project_id", "payload"), (config.config_id, config.project_id, config.to_json()))
        return config

    def get_monitoring_config(self, config_id: str) -> MonitoringConfiguration | None:
        row = self._connection.execute("SELECT payload FROM monitoring_configs WHERE config_id=?", (config_id,)).fetchone()
        return MonitoringConfiguration.from_dict(json.loads(row[0])) if row else None

    def close(self) -> None:
        with self._lock:
            self._connection.close()
