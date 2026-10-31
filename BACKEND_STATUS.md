# SpecGuard backend status

## Fully implemented

- Safe project directory and ZIP ingestion with path traversal, symlink, file
  count, per-file, total-size, and unsupported-file checks.
- Python requirements parsing, unique IDs, source-marker mapping, test mapping,
  ambiguity signals, and a serializable traceability graph.
- Deterministic offline mutations, Bedrock provider boundary, compilation and
  behavior validation, retry-once handling, equivalent-mutant detection, and
  protected/unprotected/invalid/inconclusive classifications.
- Adapter contracts and detection for Python, JavaScript, TypeScript, and Java.
  Python has verified syntax and test execution behavior in this repository.
- FastAPI project, upload, analysis, status, results, report, and health APIs.
- JSON and HTML report serialization and the existing local CLI.

## Partial or environment-dependent

- Secure execution is implemented as a Docker boundary with network disabled,
  read-only project mounts, CPU/memory/process limits, dropped capabilities,
  and a timeout. The API fails closed unless Docker and an approved image are
  configured via `SPECGUARD_DOCKER_IMAGE`. The current environment has no configured Docker image, so API
  analysis jobs report an explicit isolation failure.
- JavaScript, TypeScript, and Java adapters detect projects and expose commands;
  actual execution requires the corresponding external runtimes/toolchains and
  is covered by adapter contract tests rather than claimed as available here.
- The API job store is in-process and should be replaced by a durable queue and
  database for production workers.

## Unsupported or incomplete integrations

- C/C++, C#, Go, PHP, Ruby, and Rust adapters are not implemented.
- Failproof AI is an explicit boundary because no installed SDK or verified
  documentation was present; no invented calls are made.
- Bedrock and S3 classes are boundaries and do not use credentials in local mode.
- Lambda/CodeBuild files remain deployment integration points; no deployment was
  performed.

## Exact local commands and verification

```powershell
python -m pytest
python -m compileall -q specguard demo tests
python -m specguard.cli .
uvicorn specguard.api:app --reload
```

The local suite contains 23 passing tests. The demo report has seven protected,
three intentionally unprotected, and zero invalid or inconclusive requirements.
