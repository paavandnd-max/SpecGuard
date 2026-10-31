# SpecGuard Phase 3 Status — Behavioral Verification Engine

Date: 2026-10-31  
Scope: Phase 3 only. Frontend/UI, Phase 4 mutation expansion, Phase 5 test generation, Phase 6 continuous assurance, and new language analyzers were not started.

## Files changed

- `specguard/v2/models.py` — added versioned `BehavioralVerdict` and `BehavioralObservation` contracts.
- `specguard/v2/behavioral.py` — static test discovery, Docker-only baseline runner, evidence/reproducibility capture, secret redaction, and explicit oracle comparison.
- `specguard/v2/__init__.py` — exports Phase 3 contracts and services.
- `tests/test_v2_behavioral.py` — eleven focused tests for static discovery, unsupported/ambiguous frameworks, symlink rejection, fail-closed execution, redaction, timestamps, failed tests, missing-framework errors, timeout handling, oracle comparison, no-observation handling, and schema round-trip.
- `SPECguard_V2_ARCHITECTURE.md` — Phase 3 implementation and limitation note.
- `PHASE_3_STATUS.md` — this report.

No frontend files or V1 route/output implementations were modified.

## Implemented

### Static test discovery

- Parses Python test files with `ast` only; it never imports or runs project modules during discovery.
- Identifies `unittest` and `pytest` suites and test functions/classes.
- Reports `unsupported` for explicitly detected unsupported frameworks such as `nose`.
- Reports `inconclusive` for mixed frameworks, syntax/read errors, no tests, or ambiguous discovery.
- Rejects symlinked tests and paths resolving outside the project root.

### Isolated baseline execution

- Uses the existing `DockerSandbox` exclusively; there is no host-execution fallback.
- Fails closed when Docker or an approved image is unavailable.
- Preserves the existing read-only mount, `--network none`, timeout, memory, CPU, PID, capability-drop, and no-new-privileges policy.
- Captures command, return code, stdout, stderr, duration, UTC start/end timestamps, runtime/interpreter marker, project input hashes, environment marker, seed applicability, and resource/network policy.
- Redacts common secret-shaped values in captured logs before persistence.
- Classifies successful runs as `passed`, assertion/process failures as `failed_test`, infrastructure/image failures as `execution_error`, and unavailable/timeout runs as `inconclusive`.

### Oracle-backed behavioral comparison

- Compares only caller-supplied observations with explicit `ExpectedBehaviorContract` postconditions.
- Does not infer expected behavior from implementation output or a passing test suite.
- Uncertain contracts become `unsupported`/`inconclusive`; missing observations become `not_evaluated`/`inconclusive`.
- Matching deterministic observations produce `passed` or `violation_observed` verdicts with dynamic verification mode.
- Findings and comparison evidence are persisted through the existing `EvidenceStore`, including SQLite restart durability inherited from Phase 0.
- Compliance and test-effectiveness statuses remain separate; baseline success alone never proves requirement compliance.

## Verification commands and actual results

| Command | Result | Pass/fail | Limitation |
|---|---|---|---|
| `rtk python -m pytest tests/test_v2_behavioral.py -q` | `11 passed` | PASS | Focused Phase 3 tests use a fake sandbox for failure/timeout branches; one smoke uses real Docker below. |
| `rtk python -m pytest -ra` | `43 passed in 46.41s` | PASS | Test suite validates implemented behavior only. |
| `rtk python -m compileall -q specguard tests` | exit code `0` | PASS | Compile check is not semantic verification. |
| `rtk python -c "...TestClient(app).get('/api/v1/health')..."` | `200 {'status': 'ok', 'service': 'specguard-backend', 'version': '1.0.0'}` | PASS | V1 health smoke only; no new V2 API was added. |
| `rtk python -m specguard.cli .` | `{'protected': 7, 'unprotected': 3, 'invalid': 0, 'inconclusive': 0}` | PASS | Existing V1 CLI output preserved; this is mutation/test-effectiveness output, not Phase 3 compliance. |
| `rtk docker version --format '{{.Server.Version}}'` | `28.5.1` | PASS | Docker availability is environment-dependent. |
| `rtk docker image inspect python:3.12-slim --format '{{.Id}}'` | `sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159` | PASS | Runner currently records configured image reference; immutable digest resolution is deferred. |
| Real `BaselineRunner(ExecutionPolicy(docker_image='python:3.12-slim'))` unittest fixture | `status=passed`, `returncode=0`, `Ran 1 test`, `network=none`, `cleaned=True` | PASS | Fixture was created in a temporary directory and removed after execution. |
| Real Docker timeout fixture, 1-second policy and 5-second test | `status=inconclusive`, `stderr='Sandbox timed out after 1s'`, `returncode=None`, `cleaned=True` | PASS | Timeout is intentionally inconclusive; no partial result is treated as compliance. |
| Real Docker network fixture attempting outbound socket with `network='none'` | `status=passed`, `Ran 1 test`, `network='none'`, resource policy captured | PASS | This validates the configured Docker network boundary, not every possible kernel escape. |
| Real Docker invalid image `specguard/does-not-exist:invalid` | `status=execution_error`, `returncode=125`, Docker pull/access error, evidence `inconclusive` | PASS | Image lookup may contact Docker's configured registry only when an invalid image is requested; normal policy is network-isolated for project execution. |

## Capability classification

Implemented and tested: Python static discovery; explicit unsupported/ambiguous states; Docker-only baseline execution; timeout/resource/network policy forwarding; secret redaction; symlink/path filtering; baseline status classification; deterministic oracle comparison; V2 EvidenceStore persistence; V1 compatibility.

Partial: runtime/dependency reproducibility is represented by command, image reference, project hashes, adapter/parser versions, and policy metadata. The runner does not yet resolve and pin an immutable image digest, materialize dependency lockfile fingerprints separately, or record a test-framework seed when the framework does not expose one.

Deferred: automatic extraction of behavioral observations from arbitrary test output; focused requirement probes; static-to-dynamic hypothesis verification workflow; JavaScript/TypeScript/Java behavioral analyzers; V2 API/CLI surface; CI/CD orchestration.

## Security guarantees and limits

- Uploaded project code is executed only inside the existing Docker boundary with a read-only mount, no network, bounded resources, dropped capabilities, and no-new-privileges.
- Discovery and hashing do not import or execute project code, and symlinks are excluded from both paths.
- Commands are argument arrays (`shell=False`); no shell interpolation is used.
- Docker/image/configuration failures fail closed; the implementation never falls back to host execution.
- Logs are pattern-redacted, not a full secret-detection or declassification proof. A secret that does not match the current patterns could still appear in output.
- Docker isolation depends on the host Docker daemon/kernel configuration; this phase does not claim a formal sandbox or escape-proof guarantee.

## Next milestone

Before Phase 4, add a small V2 orchestration/API boundary that records `EvaluationRun` lifecycle and baseline gating, then implement only evidence-backed focused probes for determinate contracts. Mutation expansion and generated-test workflows remain subsequent phases.
