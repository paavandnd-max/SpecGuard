# SpecGuard Phase 5 Status — Autonomous Test Engineering

Date: 2026-10-31  
Scope: Phase 5 only. Frontend/UI, Phase 6 continuous assurance, generated-test promotion, and non-Python engines were not started.

## Independently verified baseline

Before editing, the existing Phase 0–4 workspace passed:

- `rtk python -m pytest -ra` — `51 passed in 75.47s`.
- `rtk python -m compileall -q specguard tests` — exit code `0`.
- Existing V1 API health — HTTP `200`, `{'status': 'ok', 'service': 'specguard-backend', 'version': '1.0.0'}`.
- Existing V1 CLI — `{'protected': 7, 'unprotected': 3, 'invalid': 0, 'inconclusive': 0}`.

## Files changed

- `specguard/v2/models.py` — versioned verification-gap, test-candidate, candidate-validation, and test-engineering-run schemas.
- `specguard/v2/evidence_store.py` — in-memory/SQLite persistence for gaps, candidates, validations, and engineering runs.
- `specguard/v2/test_engineering.py` — deterministic gap analysis, invocation-profile candidate generation, isolated validation, export handling, and evidence/findings.
- `specguard/v2/__init__.py` — Phase 5 exports.
- `tests/test_v2_test_engineering.py` — focused tests for gap targeting, ambiguity blocking, original-pass/mutant-detection validation, rejection paths, stable IDs/deduplication, export integrity, SQLite restart, and sandbox fail-closed behavior.
- `SPECguard_V2_ARCHITECTURE.md` — Phase 5 implementation and limitation note.
- `PHASE_5_STATUS.md` — this report.

No frontend/UI files or V1 routes/report serializers were modified.

## Implemented behavior

### Verification-gap analysis

- Uses only relevant valid Phase 4 mutants with verdict `killed` or `survived`.
- Surviving mutants create test-effectiveness gaps; killed mutants provide protection evidence.
- Invalid, equivalent, unrelated, and inconclusive outcomes are excluded from the effectiveness denominator.
- Uncertain/missing oracle contracts are `blocked`; incomplete mutation runs are `inconclusive`.
- A surviving mutant is never reported as an implementation defect.

### Deterministic candidate generation

- Generates Python `unittest` candidates from an explicit invocation profile containing module/import/setup/action/assertion source.
- Requires a determinate oracle contract. Missing profiles or uncertain contracts produce blocked candidates without invented assertions.
- Candidate IDs are stable hashes of requirement, content, and targeted mutant IDs; content hashes and source references are recorded.
- Candidate artifacts are stored in separate temporary/export directories and never overwrite the user’s tests.

### Validation lifecycle

- Static AST parsing and test discovery happen before execution.
- Candidate execution runs against the original project first.
- Each intended mutant is applied in a separate temporary copy and executed through the existing Docker-only `BaselineRunner`.
- `validated` requires original success plus detection of every targeted mutant.
- Original failure is `rejected`; no detection is `rejected`; timeout/sandbox/toolchain failures are `inconclusive`.
- Export refuses to overwrite a different file at the same candidate path.

## Verification commands and actual results

| Command / exercise | Actual result | Pass/fail | Limitation |
|---|---|---|---|
| `rtk python -m pytest tests/test_v2_test_engineering.py -q` | `6 passed` | PASS | Fake runners cover deterministic failure and unavailable-sandbox branches. |
| `rtk python -m pytest -ra` | `57 passed in 64.76s` | PASS | Includes all V1 and Phase 0–4 tests. |
| `rtk python -m compileall -q specguard tests` | exit code `0` | PASS | Compile check is not semantic verification. |
| Real Docker candidate fixture with `python:3.12-slim`, `network=none` | `run_status=completed`, candidate `validated`, original `passed`, mutant `failed_test`, detected mutant `mutant-1`, temporary root cleaned | PASS | Explicit invocation profile supplied; no AI inference was used. |
| Ambiguous oracle candidate | candidate `blocked`, no validation run | PASS | Assertions are intentionally not invented. |
| Original implementation failure | candidate `rejected`, original status `failed_test` | PASS | Unrelated/original failures are not treated as mutant detection. |
| Candidate passes original but does not detect mutant | candidate `rejected`, detected mutant list empty | PASS | Passing the original alone is insufficient. |
| Docker image omitted | candidate `inconclusive`, original validation `inconclusive`, no host fallback | PASS | Docker remains required for execution. |
| SQLite close/reopen | validation payload restored identically | PASS | Local SQLite is durable but not a distributed store. |
| Export integrity | candidate exported separately; original user test file unchanged | PASS | Export is explicit; no automatic promotion is performed. |

## V1 compatibility

After Phase 5 changes:

- Full suite: `57 passed in 64.76s`.
- V1 API health remains HTTP `200` with the same payload.
- V1 CLI remains `7 protected, 3 unprotected, 0 invalid, 0 inconclusive`.
- No V1 route, report schema, frontend, or original test file was changed.

No new V2 API or CLI surface was added; the engine is available as a backend Python service and its orchestration surface remains deferred.

## Capability classification

Implemented: deterministic Python gap analysis; oracle-uncertainty blocking; explicit invocation-profile generation; stable provenance and hashes; candidate deduplication; syntax/discovery checks; original-pass and intended-mutant detection validation; rejected/inconclusive outcomes; explicit export; in-memory/SQLite persistence; Docker fail-closed behavior; V1 regression coverage.

Partial: invocation profiles must be supplied by a trusted caller; the engine does not infer safe function arguments, fixtures, imports, or assertions from arbitrary requirements. Candidate validation runs the project’s discovered suite together with the generated artifact, so framework/dependency availability is image-dependent. Flakiness detection is represented by inconclusive outcomes but does not yet perform repeated statistical trials.

Deferred: AI/LLM candidate generation, automatic invocation inference, candidate promotion into user tests, multi-language generation, V2 API/CLI orchestration, historical candidate comparison, CI/CD integration, and Phase 6 continuous assurance.

## Security guarantees and limitations

- Candidate and mutant project code execute only through the existing Docker sandbox with read-only mounts, no network, bounded timeout/memory/CPU/PIDs, dropped capabilities, and no-new-privileges.
- Candidate discovery and syntax checks do not import or execute project code.
- Original tests are copied, never silently edited; generated files live under `specguard_generated_tests` in temporary copies or an explicit export directory.
- Source/mutant paths must resolve inside the project root; symlinked project inputs are rejected by the shared copier.
- Commands remain argument arrays with `shell=False`; no package installation or host execution is introduced.
- Secret redaction and Docker isolation retain Phase 3’s pattern-based and host-daemon limitations.
- A validated candidate proves the candidate’s observed detection of the specified mutant; it does not prove formal requirement compliance.

## Next recommended milestone

Add a small V2 orchestration/API boundary for retrieving mutation runs, gaps, candidates, and validation evidence. Keep candidate promotion and Phase 6 continuous assurance out of scope until that evidence contract is accepted.
