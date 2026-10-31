from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, TypeVar

SCHEMA_VERSION = "2.0"
T = TypeVar("T")


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    VERIFIED = "verified"
    HYPOTHESIS = "hypothesis"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class VerificationMode(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    MUTATION = "mutation"
    GENERATED_TEST = "generated_test"
    MIXED = "mixed"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    VIOLATION = "violation"
    UNKNOWN = "unknown"
    INCONCLUSIVE = "inconclusive"


class TestEffectiveness(str, Enum):
    DETECTED = "detected"
    SURVIVED = "survived"
    NOT_EVALUATED = "not_evaluated"
    INCONCLUSIVE = "inconclusive"


TestEffectiveness.__test__ = False


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class BehavioralVerdict(str, Enum):
    PASSED = "passed"
    VIOLATION_OBSERVED = "violation_observed"
    FAILED_TEST = "failed_test"
    EXECUTION_ERROR = "execution_error"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"
    NOT_EVALUATED = "not_evaluated"


def _serialize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {item.name: _serialize(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]
    return value


@dataclass(frozen=True)
class VersionedSchema:
    schema_version: ClassVar[str] = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = _serialize(self)
        data["schema_version"] = self.schema_version
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class RequirementV2(VersionedSchema):
    requirement_id: str
    normalized_text: str
    source_text: str
    atomic: bool = True
    atomicity_reasons: tuple[str, ...] = ()
    ambiguous: bool = False
    ambiguity_reasons: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    source_hint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequirementV2":
        return cls(
            requirement_id=data["requirement_id"], normalized_text=data["normalized_text"],
            source_text=data.get("source_text", data["normalized_text"]),
            atomic=data.get("atomic", True), atomicity_reasons=tuple(data.get("atomicity_reasons", ())),
            ambiguous=data.get("ambiguous", False), ambiguity_reasons=tuple(data.get("ambiguity_reasons", ())),
            dependencies=tuple(data.get("dependencies", ())), source_hint=data.get("source_hint"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class CodeSymbol(VersionedSchema):
    symbol_id: str
    artifact_id: str
    language: str
    kind: str
    qualified_name: str
    span: dict[str, Any]
    parent_id: str | None = None
    calls: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    dependency_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodeSymbol":
        return cls(
            symbol_id=data["symbol_id"], artifact_id=data["artifact_id"], language=data["language"],
            kind=data["kind"], qualified_name=data["qualified_name"], span=dict(data.get("span", {})),
            parent_id=data.get("parent_id"), calls=tuple(data.get("calls", ())),
            imports=tuple(data.get("imports", ())), dependency_ids=tuple(data.get("dependency_ids", ())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class TraceabilityLink(VersionedSchema):
    link_id: str
    requirement_id: str
    target_id: str
    target_kind: str
    relation: str
    origin: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceabilityLink":
        return cls(data["link_id"], data["requirement_id"], data["target_id"], data["target_kind"], data["relation"], data["origin"], float(data["confidence"]), tuple(data.get("evidence_ids", ())))


@dataclass(frozen=True)
class ReproducibilityMetadata(VersionedSchema):
    input_hashes: dict[str, str] = field(default_factory=dict)
    parser_version: str = "specguard-v2-phase1"
    adapter_id: str | None = None
    adapter_version: str | None = None
    oracle_version: str | None = None
    provider: str | None = None
    provider_version: str | None = None
    seed: str | None = None
    execution_policy_id: str | None = None
    image_digest: str | None = None
    command: tuple[str, ...] = ()
    environment_fingerprint: str | None = None
    network_policy: str = "none"
    resource_policy: dict[str, Any] = field(default_factory=dict)
    retry_policy: str = "retry-once"
    parent_evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReproducibilityMetadata":
        values = dict(data)
        values["command"] = tuple(values.get("command", ()))
        values["parent_evidence_ids"] = tuple(values.get("parent_evidence_ids", ()))
        values["input_hashes"] = dict(values.get("input_hashes", {}))
        values["resource_policy"] = dict(values.get("resource_policy", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class Evidence(VersionedSchema):
    evidence_id: str
    run_id: str
    kind: str
    status: EvidenceStatus
    claim: str
    requirement_id: str | None = None
    artifact_ids: tuple[str, ...] = ()
    source_spans: tuple[dict[str, Any], ...] = ()
    input_hashes: dict[str, str] = field(default_factory=dict)
    output_hash: str | None = None
    execution_context: dict[str, Any] = field(default_factory=dict)
    reproducibility: ReproducibilityMetadata = field(default_factory=ReproducibilityMetadata)
    parent_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        values = dict(data)
        values["status"] = EvidenceStatus(values["status"])
        values["artifact_ids"] = tuple(values.get("artifact_ids", ()))
        values["source_spans"] = tuple(values.get("source_spans", ()))
        values["parent_ids"] = tuple(values.get("parent_ids", ()))
        values["reproducibility"] = ReproducibilityMetadata.from_dict(values.get("reproducibility", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class Finding(VersionedSchema):
    finding_id: str
    requirement_id: str | None
    category: str
    severity: str
    verdict: str
    compliance_status: ComplianceStatus
    test_effectiveness_status: TestEffectiveness
    verification_mode: VerificationMode
    message: str
    evidence_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        values = dict(data)
        values["compliance_status"] = ComplianceStatus(values["compliance_status"])
        values["test_effectiveness_status"] = TestEffectiveness(values["test_effectiveness_status"])
        values["verification_mode"] = VerificationMode(values["verification_mode"])
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        values["hypothesis_ids"] = tuple(values.get("hypothesis_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RunPolicy(VersionedSchema):
    policy_id: str
    provider: str = "offline"
    execution_mode: str = "docker"
    network_policy: str = "none"
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpu_count: float = 1.0
    pids_limit: int = 128
    image: str | None = None
    retry_limit: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunPolicy":
        return cls(**{item.name: data[item.name] for item in fields(cls) if item.name in data})


@dataclass(frozen=True)
class EvaluationRun(VersionedSchema):
    run_id: str
    project_id: str
    revision_id: str | None
    policy: RunPolicy
    status: RunStatus = RunStatus.QUEUED
    started_at: float | None = None
    finished_at: float | None = None
    engine_runs: tuple[dict[str, Any], ...] = ()
    finding_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    reproducibility: ReproducibilityMetadata = field(default_factory=ReproducibilityMetadata)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvaluationRun":
        values = dict(data)
        values["policy"] = RunPolicy.from_dict(values["policy"])
        values["status"] = RunStatus(values.get("status", RunStatus.QUEUED.value))
        values["engine_runs"] = tuple(values.get("engine_runs", ()))
        values["finding_ids"] = tuple(values.get("finding_ids", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        values["counts"] = dict(values.get("counts", {}))
        values["reproducibility"] = ReproducibilityMetadata.from_dict(values.get("reproducibility", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class ExpectedBehaviorContract(VersionedSchema):
    contract_id: str
    requirement_id: str
    preconditions: tuple[str, ...]
    actions: tuple[str, ...]
    postconditions: tuple[str, ...]
    uncertainty: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    oracle_version: str = "deterministic-v1"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExpectedBehaviorContract":
        return cls(
            contract_id=data["contract_id"], requirement_id=data["requirement_id"],
            preconditions=tuple(data.get("preconditions", ())), actions=tuple(data.get("actions", ())),
            postconditions=tuple(data.get("postconditions", ())), uncertainty=tuple(data.get("uncertainty", ())),
            evidence_ids=tuple(data.get("evidence_ids", ())), oracle_version=data.get("oracle_version", "deterministic-v1"),
        )


@dataclass(frozen=True)
class BehavioralObservation(VersionedSchema):
    observation_id: str
    run_id: str
    requirement_id: str
    verdict: BehavioralVerdict
    actual: str | None = None
    expected: str | None = None
    source: str = "isolated_execution"
    evidence_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehavioralObservation":
        return cls(
            observation_id=data["observation_id"], run_id=data["run_id"], requirement_id=data["requirement_id"],
            verdict=BehavioralVerdict(data["verdict"]), actual=data.get("actual"), expected=data.get("expected"),
            source=data.get("source", "isolated_execution"), evidence_ids=tuple(data.get("evidence_ids", ())),
            details=dict(data.get("details", {})),
        )


class MutationVerdict(str, Enum):
    KILLED = "killed"
    SURVIVED = "survived"
    EQUIVALENT = "equivalent"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"
    EXECUTION_ERROR = "execution_error"


class MutationOperatorKind(str, Enum):
    COMPARISON_BOUNDARY = "comparison_boundary"
    BOOLEAN_LOGIC = "boolean_logic"
    ARITHMETIC = "arithmetic"
    RETURN_VALUE = "return_value"
    INPUT_VALIDATION = "input_validation"
    EXCEPTION_HANDLING = "exception_handling"


@dataclass(frozen=True)
class MutationPatch(VersionedSchema):
    patch_id: str
    file_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    original_text: str
    replacement_text: str
    operator: MutationOperatorKind
    source_hash: str
    mutated_hash: str
    target_symbol_id: str | None = None
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MutationPatch":
        values = dict(data)
        values["operator"] = MutationOperatorKind(values["operator"])
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class Mutant(VersionedSchema):
    mutant_id: str
    run_id: str
    requirement_id: str
    patch: MutationPatch
    verdict: MutationVerdict = MutationVerdict.INCONCLUSIVE
    relevant: bool = True
    relevance_reason: str = ""
    attempt: int = 1
    evidence_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Mutant":
        values = dict(data)
        values["patch"] = MutationPatch.from_dict(values["patch"])
        values["verdict"] = MutationVerdict(values.get("verdict", MutationVerdict.INCONCLUSIVE.value))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RequirementMutationSummary(VersionedSchema):
    requirement_id: str
    targeting_status: str
    relevant: bool
    killed: int = 0
    survived: int = 0
    equivalent: int = 0
    invalid: int = 0
    inconclusive: int = 0
    execution_error: int = 0
    score: float | None = None
    complete: bool = False
    reason: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequirementMutationSummary":
        return cls(**{item.name: data[item.name] for item in fields(cls) if item.name in data})


@dataclass(frozen=True)
class MutationRun(VersionedSchema):
    run_id: str
    project_id: str
    baseline_status: str
    status: str
    mutant_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    summaries: tuple[RequirementMutationSummary, ...] = ()
    reproducibility: ReproducibilityMetadata = field(default_factory=ReproducibilityMetadata)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MutationRun":
        values = dict(data)
        values["mutant_ids"] = tuple(values.get("mutant_ids", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        values["counts"] = dict(values.get("counts", {}))
        values["summaries"] = tuple(RequirementMutationSummary.from_dict(item) for item in values.get("summaries", ()))
        values["reproducibility"] = ReproducibilityMetadata.from_dict(values.get("reproducibility", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


class TestCandidateStatus(str, Enum):
    PROPOSED = "proposed"
    BLOCKED = "blocked"
    VALIDATED = "validated"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


TestCandidateStatus.__test__ = False


@dataclass(frozen=True)
class VerificationGap(VersionedSchema):
    gap_id: str
    run_id: str
    requirement_id: str
    status: str
    valid_mutant_ids: tuple[str, ...] = ()
    killed: int = 0
    survived: int = 0
    reason: str = ""
    evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationGap":
        values = dict(data)
        values["valid_mutant_ids"] = tuple(values.get("valid_mutant_ids", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class TestCandidate(VersionedSchema):
    candidate_id: str
    run_id: str
    requirement_id: str
    status: TestCandidateStatus
    content: str
    content_hash: str
    targeted_mutant_ids: tuple[str, ...] = ()
    source_references: tuple[str, ...] = ()
    strategy: str = "deterministic_invocation_profile"
    expected_behavior: tuple[str, ...] = ()
    confidence: float = 0.0
    evidence_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestCandidate":
        values = dict(data)
        values["status"] = TestCandidateStatus(values.get("status", TestCandidateStatus.INCONCLUSIVE.value))
        values["targeted_mutant_ids"] = tuple(values.get("targeted_mutant_ids", ()))
        values["source_references"] = tuple(values.get("source_references", ()))
        values["expected_behavior"] = tuple(values.get("expected_behavior", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


TestCandidate.__test__ = False


@dataclass(frozen=True)
class CandidateValidation(VersionedSchema):
    validation_id: str
    run_id: str
    candidate_id: str
    status: TestCandidateStatus
    original_status: str
    mutant_status: str
    detected_mutant_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CandidateValidation":
        values = dict(data)
        values["status"] = TestCandidateStatus(values.get("status", TestCandidateStatus.INCONCLUSIVE.value))
        values["detected_mutant_ids"] = tuple(values.get("detected_mutant_ids", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class TestEngineeringRun(VersionedSchema):
    run_id: str
    project_id: str
    status: str
    gap_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    validation_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    reproducibility: ReproducibilityMetadata = field(default_factory=ReproducibilityMetadata)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestEngineeringRun":
        values = dict(data)
        values["gap_ids"] = tuple(values.get("gap_ids", ()))
        values["candidate_ids"] = tuple(values.get("candidate_ids", ()))
        values["validation_ids"] = tuple(values.get("validation_ids", ()))
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        values["counts"] = dict(values.get("counts", {}))
        values["reproducibility"] = ReproducibilityMetadata.from_dict(values.get("reproducibility", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


TestEngineeringRun.__test__ = False


class FileChangeKind(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class RequirementChangeKind(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    UNCHANGED = "unchanged"


class EvidenceLifecycleState(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    SUPERSEDED = "superseded"
    INVALIDATED = "invalidated"
    REVALIDATED = "revalidated"


class PlanActionKind(str, Enum):
    RERUN = "rerun"
    REUSE = "reuse"
    INVALIDATE = "invalidate"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


class RegressionKind(str, Enum):
    COMPLIANCE_REGRESSION = "compliance_regression"
    EFFECTIVENESS_REGRESSION = "effectiveness_regression"
    COVERAGE_REGRESSION = "coverage_regression"
    EXECUTION_REGRESSION = "execution_regression"


@dataclass(frozen=True)
class ProjectSnapshot(VersionedSchema):
    snapshot_id: str
    project_root: str
    created_at: float = 0.0
    files: dict[str, str] = field(default_factory=dict)
    file_categories: dict[str, str] = field(default_factory=dict)
    requirement_hashes: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectSnapshot":
        values = dict(data)
        values["files"] = dict(values.get("files", {}))
        values["file_categories"] = dict(values.get("file_categories", {}))
        values["requirement_hashes"] = dict(values.get("requirement_hashes", {}))
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class ChangeRecord(VersionedSchema):
    path: str
    kind: FileChangeKind
    old_hash: str | None = None
    new_hash: str | None = None
    old_path: str | None = None
    category: str = "other"
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChangeRecord":
        values = dict(data)
        values["kind"] = FileChangeKind(values["kind"])
        values["details"] = dict(values.get("details", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RequirementChange(VersionedSchema):
    requirement_id: str
    kind: RequirementChangeKind
    old_text: str | None = None
    new_text: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequirementChange":
        values = dict(data)
        values["kind"] = RequirementChangeKind(values["kind"])
        values["details"] = dict(values.get("details", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class ChangeSet(VersionedSchema):
    changeset_id: str
    base_snapshot_id: str | None = None
    target_snapshot_id: str = ""
    file_changes: tuple[ChangeRecord, ...] = ()
    requirement_changes: tuple[RequirementChange, ...] = ()
    created_at: float = 0.0
    has_source_changes: bool = False
    has_test_changes: bool = False
    has_requirement_changes: bool = False
    has_dependency_changes: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChangeSet":
        values = dict(data)
        values["file_changes"] = tuple(ChangeRecord.from_dict(item) for item in values.get("file_changes", ()))
        values["requirement_changes"] = tuple(RequirementChange.from_dict(item) for item in values.get("requirement_changes", ()))
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class ImpactAnalysis(VersionedSchema):
    impact_id: str
    changeset_id: str
    impacted_requirement_ids: tuple[str, ...] = ()
    unaffected_requirement_ids: tuple[str, ...] = ()
    impacted_symbol_ids: tuple[str, ...] = ()
    impacted_test_ids: tuple[str, ...] = ()
    stale_evidence_ids: tuple[str, ...] = ()
    stale_finding_ids: tuple[str, ...] = ()
    reasons: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImpactAnalysis":
        values = dict(data)
        values["impacted_requirement_ids"] = tuple(values.get("impacted_requirement_ids", ()))
        values["unaffected_requirement_ids"] = tuple(values.get("unaffected_requirement_ids", ()))
        values["impacted_symbol_ids"] = tuple(values.get("impacted_symbol_ids", ()))
        values["impacted_test_ids"] = tuple(values.get("impacted_test_ids", ()))
        values["stale_evidence_ids"] = tuple(values.get("stale_evidence_ids", ()))
        values["stale_finding_ids"] = tuple(values.get("stale_finding_ids", ()))
        values["reasons"] = {key: list(items) for key, items in values.get("reasons", {}).items()}
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class EvaluationPlanItem(VersionedSchema):
    item_id: str
    requirement_id: str
    action: PlanActionKind
    engines: tuple[str, ...] = ()
    reason: str = ""
    reusable_finding_ids: tuple[str, ...] = ()
    reusable_evidence_ids: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvaluationPlanItem":
        values = dict(data)
        values["action"] = PlanActionKind(values["action"])
        values["engines"] = tuple(values.get("engines", ()))
        values["reusable_finding_ids"] = tuple(values.get("reusable_finding_ids", ()))
        values["reusable_evidence_ids"] = tuple(values.get("reusable_evidence_ids", ()))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class EvaluationPlan(VersionedSchema):
    plan_id: str
    impact_id: str
    base_run_id: str | None = None
    target_snapshot_id: str = ""
    items: tuple[EvaluationPlanItem, ...] = ()
    total_requirements: int = 0
    rerun_count: int = 0
    reuse_count: int = 0
    invalidate_count: int = 0
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvaluationPlan":
        values = dict(data)
        values["items"] = tuple(EvaluationPlanItem.from_dict(item) for item in values.get("items", ()))
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class EvidenceLifecycleRecord(VersionedSchema):
    record_id: str
    evidence_id: str
    state: EvidenceLifecycleState
    reason: str
    updated_at: float = 0.0
    invalidated_by_change_id: str | None = None
    superseded_by_evidence_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceLifecycleRecord":
        values = dict(data)
        values["state"] = EvidenceLifecycleState(values["state"])
        values["details"] = dict(values.get("details", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RequirementComparison(VersionedSchema):
    requirement_id: str
    base_compliance: ComplianceStatus | None = None
    target_compliance: ComplianceStatus | None = None
    base_effectiveness: TestEffectiveness | None = None
    target_effectiveness: TestEffectiveness | None = None
    base_score: float | None = None
    target_score: float | None = None
    status_delta: str = "no_change"
    is_requirement_change: bool = False
    explanation: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RequirementComparison":
        values = dict(data)
        if values.get("base_compliance") is not None:
            values["base_compliance"] = ComplianceStatus(values["base_compliance"])
        if values.get("target_compliance") is not None:
            values["target_compliance"] = ComplianceStatus(values["target_compliance"])
        if values.get("base_effectiveness") is not None:
            values["base_effectiveness"] = TestEffectiveness(values["base_effectiveness"])
        if values.get("target_effectiveness") is not None:
            values["target_effectiveness"] = TestEffectiveness(values["target_effectiveness"])
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RegressionFinding(VersionedSchema):
    regression_id: str
    requirement_id: str
    kind: RegressionKind
    severity: str = "medium"
    message: str = ""
    base_verdict: str = ""
    target_verdict: str = ""
    evidence_ids: tuple[str, ...] = ()
    is_requirement_change: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegressionFinding":
        values = dict(data)
        values["kind"] = RegressionKind(values["kind"])
        values["evidence_ids"] = tuple(values.get("evidence_ids", ()))
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class RunComparison(VersionedSchema):
    comparison_id: str
    base_run_id: str
    target_run_id: str
    timestamp: float = 0.0
    requirement_comparisons: tuple[RequirementComparison, ...] = ()
    regressions: tuple[RegressionFinding, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    summary: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunComparison":
        values = dict(data)
        values["requirement_comparisons"] = tuple(RequirementComparison.from_dict(item) for item in values.get("requirement_comparisons", ()))
        values["regressions"] = tuple(RegressionFinding.from_dict(item) for item in values.get("regressions", ()))
        values["counts"] = dict(values.get("counts", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})


@dataclass(frozen=True)
class MonitoringConfiguration(VersionedSchema):
    config_id: str
    project_id: str
    root_path: str
    watch_paths: tuple[str, ...] = ()
    ignore_patterns: tuple[str, ...] = (".git", ".venv", "__pycache__", ".pytest_cache")
    enabled: bool = True
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MonitoringConfiguration":
        values = dict(data)
        values["watch_paths"] = tuple(values.get("watch_paths", ()))
        values["ignore_patterns"] = tuple(values.get("ignore_patterns", ()))
        values["metadata"] = dict(values.get("metadata", {}))
        return cls(**{item.name: values[item.name] for item in fields(cls) if item.name in values})

