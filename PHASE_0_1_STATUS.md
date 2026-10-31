# SpecGuard Phase 0/1 status

Date: 2026-10-31

This is the historical Phase 0/1 checkpoint. Phase 2 Code Intelligence was
implemented afterward; see `PHASE_2_STATUS.md` for the current follow-on
status.

Scope was limited to the approved V2 architecture revision, Phase 0 contracts
and compatibility, and Phase 1 deterministic Requirement Intelligence. No
frontend/UI files were modified. Phase 2 Code Intelligence and all later
phases were not started.

## Exact files changed

Architecture:

- `SPECguard_V2_ARCHITECTURE.md` — added the shared Test Oracle & Expected
  Behavior service, behavioral contracts and uncertainty, control-flow/data-flow/
  call-path evidence, reproducibility manifests, durable EvidenceStore design,
  and revised Phase 0/1 exit criteria.

Phase 0 implementation:

- `specguard/v2/__init__.py`
- `specguard/v2/models.py`
- `specguard/v2/evidence_store.py`
- `specguard/v2/compat.py`
- `specguard/v2/oracle.py`

Phase 1 implementation:

- `specguard/v2/requirement_intelligence.py`

Tests:

- `tests/test_v2_phase0_1.py`

The existing v1 modules, v1 API, CLI, report format, and frontend/UI were not
modified. CLI smoke execution regenerated the existing report artifacts under
`outputs/`.

## Implemented and tested

### Versioned V2 schemas

Implemented dataclass schemas with `schema_version="2.0"`, JSON/dict
serialization, and round-trip reconstruction for:

- normalized requirements;
- traceability links;
- reproducibility metadata;
- evidence and evidence status;
- findings with separate compliance and test-effectiveness status;
- run policies and evaluation runs;
- expected-behavior contracts.

### Shared Test Oracle & Expected Behavior service

Implemented `ExpectedBehaviorService` as a deterministic shared service, not an
autonomous agent. It emits preconditions, actions, postconditions, evidence,
oracle version, and explicit uncertainty when normative behavior cannot be
reliably derived.

### EvidenceStore

Implemented and tested:

- `EvidenceStore` abstract persistence port;
- `InMemoryEvidenceStore` for unit tests/local use;
- `SQLiteEvidenceStore` with SQLite tables, indexes, JSON payloads, WAL mode,
  reopen persistence, and evidence/finding/run lookup.

### V1 compatibility

`legacy_report_to_v2` wraps existing `AnalysisReport` mutation results into V2
`EvaluationRun`, `Finding`, and `Evidence` records. The migration test compares
the v1 report projection before and after wrapping and confirms it is unchanged.
Mutation protection is represented as test effectiveness; implementation
compliance remains `unknown`, avoiding a false claim that a surviving or killed
mutant proves implementation correctness.

### Requirement Intelligence

Implemented deterministic Phase 1 analysis for:

- stable IDs through the existing parser and normalized text;
- Unicode/whitespace normalization;
- atomicity candidates from conjunctions;
- ambiguity candidates from vague language, missing normative terms, and short
  statements;
- conservative contradiction candidates for explicit opposing normative clauses;
- dependency candidates from explicit `REQ-*` references;
- source/test traceability candidates and traceability gaps using existing
  marker and text evidence;
- evidence-backed findings and deterministic reproducibility metadata;
- behavior contracts for every normalized requirement.

No LLM is used to assert any Phase 1 finding.

## Verification commands and actual results

| Command | Actual result | Status |
|---|---|---|
| `rtk python -m pytest tests/test_v2_phase0_1.py -q` | `5 passed` | PASS |
| `rtk python -m pytest` | `28 passed in 40.54s` | PASS |
| `rtk python -m compileall -q specguard demo tests` | Exit code `0`, no output | PASS |
| `rtk python -c "...TestClient(app)..."` | `200 {'status':'ok','service':'specguard-backend','version':'1.0.0'}` and 9 v1 routes | PASS |
| `rtk python -c "RequirementIntelligenceEngine().analyze(...)"` | `10 requirements, 129 evidence, 5 findings, 105 traceability links, 10 behavior contracts` | PASS |
| `rtk python -m specguard.cli .` | `{'protected': 7, 'unprotected': 3, 'invalid': 0, 'inconclusive': 0}` | PASS |

The full suite includes the pre-existing v1 tests and the new Phase 0/1 tests.

## Partial or deferred capabilities

- Requirement contradiction detection is deliberately conservative and rule
  based. It reports candidates only when explicit opposing normative language
  and overlapping subject terms are present.
- Dependency detection currently uses explicit requirement references. Semantic
  dependency inference is deferred.
- Traceability candidates reuse existing explicit markers and heuristic test
  text matching. Ranked semantic code mapping belongs to Phase 2.
- The oracle is deterministic and intentionally incomplete. It does not perform
  dynamic behavioral verification or claim formal correctness.
- The SQLite store is a local durable implementation. The current v1
  `BackendStore` has not been replaced with it; wiring durable persistence into
  the API is deferred until the V2 run contract is accepted.
- The V2 schemas are available as a package, but no V2 API endpoints were added
  in this phase. Existing v1 endpoints remain unchanged.
- Existing adversarial results can be wrapped through the compatibility
  function, but the v1 engine has not been refactored into a new orchestrator.
- Control-flow, data-flow, and call-path extraction are specified in the
  architecture and remain Phase 2 work.

## Explicitly not started

- Code Intelligence Engine implementation.
- Behavioral Verification Engine implementation.
- New Adversarial Testing Engine features beyond compatibility wrapping.
- Autonomous Test Engineering Engine.
- Continuous Assurance Engine, revisions, history, or CI/CD events.
- Frontend/UI changes.
- New AWS or Failproof SDK integrations.

## Known limitations

The current V2 package does not yet enforce append-only evidence at the
interface level, provide schema migrations for future SQLite versions, or
provide multi-process locking/retention policies for production workers.
Those are deliberate follow-up tasks after the Phase 0 contract review.
