# SpecGuard backend acceptance audit

Audit date: 2026-10-31

This report records executed commands and HTTP requests. It does not treat
language detection or adapter-contract tests as language evaluation success.
No frontend files were modified.

## Results at a glance

| Area | Result | Evidence |
|---|---|---|
| Complete repository test suite | PASS | `23 passed in 34.36s` |
| FastAPI server and all routes | PASS | All requested routes returned expected responses |
| Python project through API and Docker | PASS | Analysis `7438391bcbf94dee8c1211cedca717f6` |
| Baseline failure abort | PASS | 10 inconclusive, zero mutation classifications |
| Valid mutant classification | PASS | 7 protected, 3 unprotected |
| ZIP traversal protection | PASS | `Unsafe archive path` |
| ZIP symlink protection | PASS | `Symbolic links are not accepted` |
| Timeout enforcement | PASS | `Sandbox timed out after 1s` |
| Memory limit | PASS | Docker return code `137` |
| Network isolation | PASS | `Network is unreachable` |
| Host execution check | PASS | Read-only write failed; host marker absent |
| JavaScript evaluation | NOT SUPPORTED | Baseline could not start: `npm` missing in configured image |
| TypeScript evaluation | NOT SUPPORTED | Baseline could not start: `npm` missing in configured image |
| Java evaluation | NOT SUPPORTED | Baseline could not start: `mvn` missing in configured image |

## 1. Complete test suite

Command:

```powershell
rtk python -m pytest
```

Actual output:

```text
...............                                                  [100%]
23 passed in 34.36s
```

Result: PASS.

Limitation: this validates the repository’s automated tests. It does not by
itself prove that arbitrary uploaded projects execute safely.

## 2. Server startup and API endpoint audit

Server command:

```powershell
rtk powershell -NoProfile -Command '$env:SPECGUARD_DOCKER_IMAGE="python:3.12-slim"; python -m uvicorn specguard.api:app --host 127.0.0.1 --port 8765'
```

The server reported `Application startup complete` and listened on
`http://127.0.0.1:8765`.

| Request | Actual output | Result | Limitation |
|---|---|---|---|
| `GET /api/v1/health` | `200`, `{"status":"ok","service":"specguard-backend","version":"1.0.0"}` | PASS | In-process server only |
| `POST /api/v1/projects` with `{"name":"acceptance-demo"}` | `201`, project `406cb4849f784bc4aa25c15e9fdcce23` | PASS | Project store is in memory |
| `POST /api/v1/projects/{id}/requirements` multipart `requirements.md` | `200`, `status: validated` | PASS | Markdown checklist format required |
| `POST /api/v1/projects/{id}/source` multipart `project.zip` | `200`, manifest with source and test files | PASS | Upload limits apply |
| `POST /api/v1/projects/{id}/tests` multipart `test_extra.py` | `200`, `status: validated` | PASS | Test stored under source/tests |
| `POST /api/v1/analysis` with `provider=offline, execution=docker` | `202`, analysis `7438391bcbf94dee8c1211cedca717f6` | PASS | Background job is in-process |
| `GET /api/v1/analysis/{id}` | `200`, `status: completed`, baseline passed | PASS | Polling required for completion |
| `GET /api/v1/analysis/{id}/results` | `200`, counts `{protected:7,unprotected:3,invalid:0,inconclusive:0}` | PASS | Results are JSON |
| `GET /api/v1/analysis/{id}/report?format=json` | `200`, keys include `baseline_output`, `counts`, `metadata`, `results` | PASS | JSON response is not persisted by API |
| `GET /api/v1/analysis/{id}/report?format=html` | `200`, `text/html; charset=utf-8`, contains `Metadata` | PASS | Generated on request |

## 3. Complete Python project submission and Docker evaluation

The project submitted through the API contained:

- `requirements.md`
- `refund_flow.py`
- `tests/__init__.py`
- `tests/test_refund_flow.py` with eight `unittest` tests
- an additional uploaded `tests/test_extra.py`

The first probe against the existing `demo:latest` image produced:

```text
3.14.3 ...
ModuleNotFoundError: No module named 'pytest'
```

That image was not used for the successful evaluation. The audit configured the
real sandbox with the pulled `python:3.12-slim` image and the command:

```text
docker run --rm --network none --read-only --cpus 1 --memory 512m --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges ...
```

Actual completed evaluation:

```text
status: completed
baseline_passed: true
counts: protected=7, unprotected=3, invalid=0, inconclusive=0
```

The seven protected requirements produced failing test output from inside the
container, including paths such as `/workspace/tests/test_refund_flow.py`. The
three intentionally unprotected requirements were REQ-004, REQ-008, and
REQ-010. Result: PASS.

## 4. Baseline failure and missing-test behavior

The audit submitted two additional projects through the same API and Docker
workflow.

Baseline-failure project:

```text
analysis: 927ddda601264e02b9c8dc4f0e8ebdaf
status: completed
baseline_passed: false
counts: protected=0, unprotected=0, invalid=0, inconclusive=10
```

The failing test was intentional. Mutation evaluation did not run. Result: PASS.

Missing-tests project:

```text
analysis: d4fe96ee72e64458b9f8e511ab345f09
status: completed
baseline_passed: false
counts: protected=0, unprotected=0, invalid=0, inconclusive=10
baseline output: Ran 0 tests ... NO TESTS RAN
```

Result: PASS. The engine refuses to treat an empty baseline as evidence.

## 5. Python, JavaScript, TypeScript, and Java independently

Each project was submitted through the API with its own source archive and
requirements file. These are evaluation attempts, not detection-only checks.

| Language | Analysis | Actual baseline output | Result | Limitation |
|---|---|---|---|---|
| Python | `7438391bcbf94dee8c1211cedca717f6` | `Ran 8 tests ... OK` | PASS | Evaluated in Docker |
| JavaScript | `c4001a8d70e24cfbab3340a7862a1266` | `exec: "npm": executable file not found in $PATH` | NOT SUPPORTED | Configured Python image has no Node/npm |
| TypeScript | `70abe06bb8124e4593019ea4deeed4dd` | `exec: "npm": executable file not found in $PATH` | NOT SUPPORTED | No Node/npm or TypeScript toolchain in image |
| Java | `3f660c74a0af428095c680d011036e9` | `exec: "mvn": executable file not found in $PATH` | NOT SUPPORTED | No Maven/JDK image configured |

All three non-Python jobs completed with `baseline_passed=false` and ten
inconclusive results. No language besides Python is claimed as successfully
evaluated by this audit.

## 6. ZIP traversal and symlink protection

The audit called `ingest_archive_bytes` with a ZIP member named `../escape.txt`.

Actual output:

```text
Unsafe archive path: ../escape.txt
```

Result: PASS.

A ZIP entry with Unix symlink mode bits produced:

```text
Symbolic links are not accepted: link
```

Result: PASS. No archive member was extracted outside its destination.

## 7. Timeout, memory, and network isolation

Timeout command:

```text
python -c "import time; time.sleep(5)"
```

Policy: `timeout_seconds=1`. Actual result:

```text
Sandbox timed out after 1s
```

Result: PASS.

Memory command:

```text
python -c "x=bytearray(512*1024*1024)"
```

Policy: `memory_mb=64`. Actual Docker return code: `137`. Result: PASS.

Network command:

```text
python -c "import socket; socket.create_connection(('1.1.1.1',80),2)"
```

Actual output:

```text
OSError: [Errno 101] Network is unreachable
```

Result: PASS.

## 8. Host-execution check

Command executed through the Docker sandbox:

```text
python -c "from pathlib import Path; Path('host_marker.txt').write_text('executed')"
```

Actual output:

```text
OSError: [Errno 30] Read-only file system: 'host_marker.txt'
marker_exists_on_host: false
```

Result: PASS. The attempted write ran against the read-only `/workspace`
mount and did not create a host file. The successful Python evaluation’s test
output also showed `/workspace/...` paths, confirming container execution.

## 9. Failure cases

Malformed requirements request:

```text
POST /api/v1/projects/{id}/requirements
status: 400
body: No checklist requirements found
```

Result: PASS.

Unsupported Go project:

```text
analysis: 888e76a1824f47f7b0fde086e8ffb2a5
status: failed
error: No adapter available for detected language: unknown
```

Result: PASS.

Invalid Docker image:

```text
docker image: registry.invalid/specguard/no-such-image:never
returncode: 125
error: failed to resolve reference ... no such host
```

Result: PASS. The sandbox returned the Docker failure; it did not classify a
mutant as protected.

Docker executable unavailable simulation:

```text
PATH=""
require_isolation(...)
Docker executable is unavailable
```

Result: PASS for fail-closed behavior. Docker Desktop itself remained running;
this was a controlled executable-lookup simulation rather than stopping the
host daemon.

## 10. Final limitations

- Python is the only language with a successful API-to-Docker mutation
  evaluation in this environment.
- JavaScript, TypeScript, and Java adapters were exercised through evaluation
  attempts and failed at missing runtime/toolchain prerequisites; they remain
  unsupported for acceptance purposes.
- Docker Desktop and the `python:3.12-slim` image were available during this
  audit. The API correctly fails closed when `SPECGUARD_DOCKER_IMAGE` is unset.
- The job/project store is in-process; this audit did not validate restart
  persistence or multi-worker durability.
- No AWS credentials, Bedrock calls, S3 uploads, or Failproof SDK calls were
  used.
