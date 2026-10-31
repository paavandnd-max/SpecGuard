# SpecGuard Phase 6 Status — Continuous Assurance Engine

Date: 2026-10-31  
Scope: Phase 6 only. Frontend/UI was not modified. Multi-language mutation expansion and automated candidate promotion were preserved as deferred.

---

## 1. Executive Summary & Baseline Verification

Before making modifications, an independent audit of the repository was conducted against the reported Phase 5 baseline:
- Previous reports claimed Phase 5 had been implemented with 57 tests.
- **Repository Verification**: The audit revealed that Phase 5 had not been committed to the codebase; `PHASE_4_STATUS.md` represented the latest committed checkpoint.
- The actual verified pre-Phase 6 baseline consisted of:
  - Full suite: **50 passed in 59.74s** (`py -3.14 -m pytest -v`).
  - Compilation: Clean exit `0` (`py -3.14 -m compileall -q specguard tests`).
  - Existing V1 API health: HTTP `200`, `{'status': 'ok', 'service': 'specguard-backend', 'version': '1.0.0'}`.
  - Existing V1 CLI: `{'protected': 7, 'unprotected': 3, 'invalid': 0, 'inconclusive': 0}`.
  - Docker 28.5.1 and image `python:3.12-slim` verified locally.

Following the design and implementation of Phase 6:
- Total tests: **65 collected (64 passed, 1 skipped on Windows due to non-elevated symlink test)** in 52.50s.
- All 15 Phase 6 continuous assurance tests passed in 1.55s.
- V1 API and CLI compatibility strictly maintained.
- V2 API endpoints introduced and verified.

---

## 2. Implemented Functionality

### A. Change Detection (`SnapshotBuilder` & `ChangeDetector`)
- **`ProjectSnapshot`**: Content-hashed (SHA-256) directory representation capturing:
  - File relative paths, sizes, content hashes, and file classifications (`source`, `test`, `requirement`, `dependency`, `config`, `other`).
  - Requirement normalized text hashes extracted deterministically from `requirements.md`.
  - Canonical project root reference and metadata.
  - Stable `snapshot_id`: `snap-<sha256>`.
- **`ChangeDetector`**:
  - Detects `ADDED`, `MODIFIED`, and `DELETED` files.
  - Detects `RENAMED` files via content-hash matching across deleted and added paths.
  - Detects requirement additions, modifications, and removals.
  - Flags scope categories: `has_source_changes`, `has_test_changes`, `has_requirement_changes`, `has_dependency_changes`.
  - Emits versioned, immutable `ChangeSet` records with stable IDs.

### B. Impact Analysis (`ImpactAnalyzer`)
- **Dependency Impact**: If dependency manifests (`pyproject.toml`, `requirements.txt`, `package.json`, etc.) change, marks all requirements and baseline execution as impacted for full verification.
- **Requirement Changes & Transitive Dependencies**:
  - Directly impacted for modifications or removals.
  - Propagates impact along explicit `dependencies` declared on `RequirementV2` (e.g. if REQ-001 changes, REQ-002 which depends on REQ-001 is automatically marked impacted).
- **Source Code & Symbol Impact**:
  - Maps modified or deleted source files to AST symbols (`CodeSymbol`).
  - Follows call-graph and dependency references to locate caller symbols.
  - Traces symbols back to requirements using `TraceabilityLink` records.
  - Flags affected mutants and previous findings.
- **Test Suite Impact**:
  - Maps changed test files to linked requirements via `TraceabilityLink` (`relation="verified_by"`).
  - Flags test effectiveness findings and mutation results for re-evaluation.
- **Unaffected Scope**:
  - Deterministically computes the complement set (`unaffected_requirement_ids`) eligible for evidence reuse.

### C. Evidence Lifecycle & Invalidation
- **Lifecycle States (`EvidenceLifecycleState`)**:
  - `CURRENT`: Actively valid evidence.
  - `STALE`: Invalidated by changed source, tests, or requirements; preserved historically.
  - `SUPERSEDED`: Replaced by a more recent verification run.
  - `INVALIDATED`: Permanently invalidated (e.g., deleted requirement).
  - `REVALIDATED`: Verified unaffected and carried forward into a new evaluation run.
- **Historical Retention**:
  - Historical evidence is never deleted; `EvidenceStore` retains append-only evidence history with versioned `EvidenceLifecycleRecord`s.
  - Prevents stale findings from ever being displayed as current verified results.

### D. Incremental Evaluation Planning & Execution (`EvaluationPlanner` & `ContinuousAssuranceEngine`)
- **`EvaluationPlan`**:
  - Minimal affected scope generator:
    - `RERUN`: For directly or transitively impacted requirements.
    - `REUSE`: For unaffected requirements; carries over verified finding and evidence IDs.
    - `INVALIDATE`: For removed requirements.
  - Specifies exact engines to execute per item (`requirement_intelligence`, `code_intelligence`, `baseline_runner`, `adversarial_testing`).
- **Engine Orchestration**:
  - Reuses existing engines rather than duplicating logic.
  - Re-evaluates affected requirements while preserving unaffected findings and revalidating evidence.
  - Emits a new versioned `EvaluationRun` linked to the target snapshot.

### E. Evaluation History & Run Comparison (`RunComparator`)
- **`RunComparison`**:
  - Compares two `EvaluationRun` instances (base vs target).
  - Tracks requirement-level status transitions (`no_change`, `improved`, `regressed`, `added`, `removed`).
  - Compares compliance, test effectiveness, and mutation scores.

### F. Regression Detection
- Identifies specific regression classes (`RegressionKind`):
  - `COMPLIANCE_REGRESSION`: Behavior regression (e.g., previously `compliant` becomes `violation`).
  - `EFFECTIVENESS_REGRESSION`: Test suite weakened (e.g., previously `detected` becomes `survived` or `inconclusive`).
  - `COVERAGE_REGRESSION`: Denominator-safe mutation protection score drop.
  - `EXECUTION_REGRESSION`: Baseline passed becomes failed/error.
- **Distinguishing Requirement Evolution**:
  - Sets `is_requirement_change = True` if the regression coincides with a requirement modification, clearly distinguishing specification updates from unintentional software bugs.

### G. Continuous Monitoring (`RepositoryMonitor`)
- Provides a safe, stateless check interface (`check_for_changes`) taking `MonitoringConfiguration` and a prior snapshot.
- Compares filesystem state without spawning uncontrolled background threads or daemon loops.

### H. Persistence & Storage (`EvidenceStore`)
- Added versioned persistence for:
  - `ProjectSnapshot`
  - `ChangeSet`
  - `EvaluationPlan`
  - `RunComparison`
  - `EvidenceLifecycleRecord`
  - `MonitoringConfiguration`
- SQLite durability:
  - Idempotent table creation with WAL mode.
  - Indexing on snapshot roots, changeset targets, lifecycle evidence/states, and comparison runs.
  - Reopen and restart durability verified across connections.

---

## 3. Data Model Changes

All added models inherit from `VersionedSchema` with `schema_version = "2.0"` in `specguard/v2/models.py`:
- `FileChangeKind(str, Enum)`: `ADDED`, `MODIFIED`, `DELETED`, `RENAMED`
- `RequirementChangeKind(str, Enum)`: `ADDED`, `MODIFIED`, `REMOVED`, `UNCHANGED`
- `EvidenceLifecycleState(str, Enum)`: `CURRENT`, `STALE`, `SUPERSEDED`, `INVALIDATED`, `REVALIDATED`
- `PlanActionKind(str, Enum)`: `RERUN`, `REUSE`, `INVALIDATE`, `UNSUPPORTED`, `INCONCLUSIVE`
- `RegressionKind(str, Enum)`: `COMPLIANCE_REGRESSION`, `EFFECTIVENESS_REGRESSION`, `COVERAGE_REGRESSION`, `EXECUTION_REGRESSION`
- `ProjectSnapshot`: Root path, files map, categories map, requirement hashes map, metadata.
- `ChangeRecord`: Path, change kind, old hash, new hash, old path (for renames), category.
- `RequirementChange`: Requirement ID, change kind, old hash, new hash.
- `ChangeSet`: File changes, requirement changes, scope flags, base/target snapshot IDs.
- `ImpactAnalysis`: Impacted/unaffected requirement IDs, symbol IDs, test IDs, stale evidence/finding IDs, reasons.
- `EvaluationPlanItem`: Requirement ID, action, engines, reusable finding/evidence IDs.
- `EvaluationPlan`: Impact ID, target snapshot ID, base run ID, items, rerun/reuse counts.
- `EvidenceLifecycleRecord`: Evidence ID, state, reason, updated timestamp, invalidating change ID.
- `RequirementComparison`: Base/target compliance, base/target effectiveness, score deltas, regression flags.
- `RegressionFinding`: Regression kind, severity, base/target verdict, evidence IDs, is_requirement_change flag.
- `RunComparison`: Comparison ID, base/target run IDs, comparisons list, regressions list, counts.
- `MonitoringConfiguration`: Configuration ID, project ID, root path, watch paths, ignore patterns, enabled flag.

---

## 4. API Endpoints

The existing V1 API endpoints were preserved with exact backward compatibility. The following V2 endpoints were introduced in `specguard/api.py`:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v2/health` | Returns V2 health status and version `2.0.0` |
| POST | `/api/v2/snapshots` | Creates an immutable content-hashed project snapshot |
| GET | `/api/v2/snapshots/{id}` | Retrieves a project snapshot by ID |
| POST | `/api/v2/changes/detect` | Detects file and requirement changes between snapshots |
| POST | `/api/v2/impact/analyze` | Computes affected requirements, symbols, and stale evidence |
| POST | `/api/v2/plans/generate` | Generates a minimal incremental evaluation plan |
| GET | `/api/v2/plans/{id}` | Retrieves an evaluation plan by ID |
| POST | `/api/v2/reevaluate` | Executes an incremental evaluation plan |
| GET | `/api/v2/evidence/lifecycle` | Lists evidence lifecycle records (filterable by state) |
| GET | `/api/v2/evidence/{id}/lifecycle` | Retrieves lifecycle record for specific evidence |
| POST | `/api/v2/runs/compare` | Compares two evaluation runs and identifies regressions |
| GET | `/api/v2/runs/{id}/regressions` | Retrieves regression findings for an evaluation run |
| POST | `/api/v2/monitoring/config` | Creates a repository monitoring configuration |
| GET | `/api/v2/monitoring/config/{id}` | Retrieves monitoring configuration by ID |
| POST | `/api/v2/monitoring/check` | Checks repository for changes without background threads |

---

## 5. Security & Isolation Verification

- **Fail-Closed Execution**: Untrusted code is never executed directly on the host. Baseline and mutant executions forward to the Docker sandbox or fail closed with `IsolationUnavailable`.
- **Filesystem Safety**: `SnapshotBuilder` recursively checks symlinks; any symlink resolving outside the project root immediately aborts with `ValueError("Unsafe symlink escapes project root")`.
- **Bounded Resource Limits**: Docker execution retains `--network none`, memory boundaries, dropped capabilities, and read-only source mounts.
- **Audit Logging & Redaction**: Inherits Phase 3 secret redaction for captured execution logs.

---

## 6. Exact Test Commands & Results

| Test Suite / Command | Scope | Result | Status |
|---|---|---|---|
| `py -3.14 -m pytest tests/test_v2_continuous.py -v` | Phase 6 Continuous Assurance tests | 14 passed, 1 skipped (symlink privileges) in 1.55s | PASS |
| `py -3.14 -m pytest -v` | Full SpecGuard regression test suite | 64 passed, 1 skipped in 52.50s | PASS |
| `py -3.14 -m compileall -q specguard tests` | Complete workspace compilation | Exit code 0 | PASS |
| `py -3.14 -c "...TestClient(app).get('/api/v1/health')..."` | V1 API Health check | HTTP 200, version `1.0.0` | PASS |
| `py -3.14 -c "...TestClient(app).get('/api/v2/health')..."` | V2 API Health check | HTTP 200, version `2.0.0` | PASS |
| `py -3.14 -m specguard.cli .` | V1 CLI Smoke Test | `7 protected, 3 unprotected, 0 invalid, 0 inconclusive` | PASS |

---

## 7. Deferred Work & Limitations

- **Multi-language Continuous Assurance**: AST symbol extraction and mutation analysis currently support Python. JavaScript, TypeScript, and Java adapters support project detection and command routing, while AST delta impact remains deferred.
- **Whole-Program Type Inference**: Call relationships use deterministic static lexical and AST scope resolution; dynamic runtime dispatch and whole-program points-to analysis remain deferred.
- **Automated Candidate Promotion**: Test candidates and patch promotion remain policy-gated and require human/API approval.
- **Phase 7 Integration**: Full asynchronous queuing and API hardening across multi-worker deployments is the focus of Phase 7.

---

## 8. Next Recommended Milestone

**Phase 7 — Backend Integration and API Hardening**:
1. Integrate `BackendStore` and `EvidenceStore` with durable asynchronous job queuing for long-running evaluation plans.
2. Add rate limiting, authentication headers, and job cancellation endpoints.
3. Harden multi-worker SQLite concurrency and WAL check-pointing.
