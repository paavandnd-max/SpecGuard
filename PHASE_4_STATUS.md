# SpecGuard Phase 4 Status — Advanced Adversarial Testing

Date: 2026-10-31  
Scope: Phase 4 only. Frontend/UI, Phase 5 generated-test engineering, Phase 6 continuous assurance, and non-Python mutation engines were not started.

## Independently verified baseline

Before editing, the existing workspace passed:

- `rtk python -m pytest -ra` — `43 passed in 50.68s`.
- `rtk python -m compileall -q specguard tests` — exit code `0`.
- Existing V1 API health — HTTP `200`, `{'status': 'ok', 'service': 'specguard-backend', 'version': '1.0.0'}`.
- Existing V1 CLI — `{'protected': 7, 'unprotected': 3, 'invalid': 0, 'inconclusive': 0}`.

The workspace has no meaningful project-local Git root (the generated parent contains many unrelated untracked home-directory entries), so verification used the actual files, tests, API, and CLI rather than treating that noisy status as a project diff.

## Files changed

- `specguard/v2/models.py` — versioned mutation verdict/operator, patch, mutant, mutation-run, and requirement-summary schemas.
- `specguard/v2/evidence_store.py` — in-memory and SQLite persistence for mutation runs and mutants, including restart durability.
- `specguard/v2/adversarial.py` — requirement-aware targeting, deterministic Python AST mutation operators, isolated lifecycle, Docker execution, classification, scoring, and evidence.
- `specguard/v2/__init__.py` — Phase 4 exports.
- `tests/test_v2_adversarial.py` — eight focused tests covering operators, targeting uncertainty, baseline fail-closed behavior, Docker configuration absence, non-Python unsupported status, killed/survived scoring, cleanup, SQLite restart persistence, equivalent/invalid caution, and retry-once handling.
- `SPECguard_V2_ARCHITECTURE.md` — Phase 4 implementation and limitation note.
- `PHASE_4_STATUS.md` — this report.

No frontend/UI files or V1 route/output implementations were modified.

## Implemented behavior

### Requirement-aware targeting

- Requires a deterministic `ExpectedBehaviorContract` and explicit source/code traceability.
- Prefers source-marker line evidence, then code-symbol traceability, then an explicit requirement source hint.
- Produces `unsupported` for uncertain oracle contracts or non-Python projects.
- Produces `inconclusive` when traceability, symbols, source paths, or supported mutation locations are unavailable.
- Does not guess a target from requirement text alone.

### Deterministic Python operators

The AST-span-aware operator set currently supports:

- comparison boundaries: `<`/`<=`, `>`/`>=`, `==`/`!=` swaps;
- boolean logic: `and`/`or` swaps;
- arithmetic: `+`/`-`, `*`/`/` swaps;
- return values: replace a returned expression with `None`;
- input validation: disable an `if` guard containing a `raise`;
- exception handling: broaden a typed handler to `Exception` or suppress an explicit `raise`.

Mutations are generated from exact AST source spans, never broad text replacement. Stable IDs derive from requirement, source hash, location, operator, and replacement. Patch records preserve original/mutated hashes, source path, spans, operator, target symbol, and exact text.

### Lifecycle and classification

- Baseline tests run first through `BaselineRunner`; any non-passing baseline stops mutant execution.
- Each mutant is copied into a temporary symlink-rejecting workspace, statically parsed, executed only through Docker, and deleted in a `finally` block.
- `failed_test` maps to `killed`; `passed` maps to `survived`; static AST identity maps to `equivalent`; parse/span failures map to `invalid`; timeout/unavailable runs map to `inconclusive`; sandbox/toolchain failures map to `execution_error`.
- Equivalent mutants are only claimed when the normalized ASTs are identical or the patch is a no-op. Otherwise the result is not labeled equivalent.
- Killed mutants report test effectiveness only; they do not claim implementation compliance. Surviving mutants do not claim a bug.
- Requirement scores use only relevant killed/survived mutants. Scores remain `null` when the denominator is zero or execution is incomplete due to invalid, inconclusive, or execution-error outcomes.

### Persistence

Mutation runs, mutants, exact patches, evidence, and findings are stored through the existing `EvidenceStore`. SQLite tables are created idempotently and round-trip after closing and reopening the database.

## Verification commands and results

| Command / exercise | Actual result | Pass/fail | Limitation |
|---|---|---|---|
| `rtk python -m pytest tests/test_v2_adversarial.py -q` | `8 passed` | PASS | Fake runners are used for deterministic failure/cleanup branches. |
| `rtk python -m pytest -ra` | `51 passed in 52.09s` | PASS | Covers all prior V1/V2 tests plus Phase 4 tests. |
| `rtk python -m compileall -q specguard tests` | exit code `0` | PASS | Compilation is not semantic verification. |
| Real Docker Phase 4 fixture with `python:3.12-slim`, `network=none` | `status=completed`, `baseline=passed`, `killed=2`, `survived=0`, `invalid=0`, `inconclusive=0`, score `1.0`, `cleaned=True` | PASS | Fixture exercised two operators for one requirement; it is not a full RefundFlow run. |
| Real current RefundFlow project with `python:3.12-slim` | `status=inconclusive`, `baseline=execution_error`, `mutants=0`, error `Baseline did not pass` | PASS | The image does not contain the project's pytest dependency; fail-closed gating correctly prevents mutation execution. |
| Baseline failure fake runner | no mutants, mutation run `inconclusive` | PASS | Confirms baseline gating without relying on host execution. |
| Docker image omitted | baseline `inconclusive`, no mutants | PASS | Docker availability remains an environment prerequisite. |
| JavaScript fixture | baseline/targeting explicitly `unsupported`, no mutants | PASS | JavaScript adapter remains detection/command contract only. |
| Equivalent no-op and stale-span candidates | `equivalent` and `invalid`; score remains `null` | PASS | No equivalent claim is made from behavioral similarity alone. |
| SQLite close/reopen | mutation run and mutant payloads restored identically | PASS | Local SQLite is not a distributed store. |

## V1 compatibility

After Phase 4 changes:

- Full suite: `51 passed in 52.09s`.
- V1 API health remains HTTP `200` with the same payload.
- V1 CLI remains `7 protected, 3 unprotected, 0 invalid, 0 inconclusive`.
- No V1 API endpoint or report schema was changed.

## Capability classification

Implemented: Python requirement-aware targeting; six deterministic operator families; stable patches and IDs; baseline gating; Docker-only mutant execution; timeout/network/resource policy forwarding; cleanup; explicit outcome classification; cautious equivalent-mutant handling; denominator-safe effectiveness scoring; in-memory/SQLite persistence; V1 regression coverage.

Partial: target selection supports explicit source markers, code-symbol links, and source hints but does not perform whole-program relevance inference. Runtime reproducibility stores image references and policy fingerprints; immutable image digest resolution and dependency lockfile capture remain deferred. AST column offsets are interpreted using Python source spans and are not a language-independent patch format.

Deferred: automatic test/probe generation, behavioral observation extraction from arbitrary tests, mutation operators for JavaScript/TypeScript/Java, V2 API/CLI orchestration, historical mutation comparison, and Phase 5/6 workflows.

## Security boundaries and limitations

- Project and mutant code execute only through the existing Docker sandbox with read-only mounts, no network, bounded CPU/memory/PIDs, dropped capabilities, and no-new-privileges.
- No shell command interpolation is introduced; Docker commands remain argument arrays with `shell=False`.
- Symlinks are rejected before copying a mutant workspace, and source target paths must resolve inside the project root.
- A missing Docker image/configuration fails closed. There is no host fallback.
- Secret redaction and Docker isolation inherit Phase 3's pattern-based redaction and host-daemon trust limitations.
- A mutation score is not a compliance score and is intentionally absent for incomplete or zero-denominator runs.

## Next recommended milestone

Add a minimal V2 orchestration/API boundary that records `EvaluationRun` lifecycle, baseline gating, and mutation-run retrieval. Keep generated tests and new-language mutation engines deferred until that evidence contract is stable.
