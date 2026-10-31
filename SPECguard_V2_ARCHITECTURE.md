# SpecGuard V2 architecture

## Product direction

SpecGuard becomes an Autonomous Software Assurance Engineer: a backend system
that reads requirements, understands implementation structure and behavior,
actively challenges the implementation, proposes missing tests, and maintains
reproducible assurance evidence over time.

The product combines two responsibilities:

1. an autonomous assurance engineer that investigates and challenges software;
2. a requirements verification platform that maintains traceability and
   historical evidence.

The V2 architecture is a backend plan. It does not define or require changes
to the frontend/UI.

## Architectural principles

- Preserve the working SpecGuard backend and evolve it behind stable contracts.
- Keep the six engines independently testable and replaceable.
- Use one shared requirement, traceability, evidence, verdict, execution, and
  artifact model across all engines.
- Keep implementation compliance separate from test effectiveness. A correct
  implementation, a test that catches a violation, and a generated test that
  has merely been proposed are different facts.
- Label every AI-derived statement as a hypothesis until a deterministic check,
  static analysis, or isolated execution verifies it.
- Make every verdict reproducible from immutable input hashes, adapter versions,
  provider configuration, execution policy, and evidence references.
- Fail closed when untrusted code cannot run in genuine isolation.
- Avoid formal-verification language. SpecGuard provides evidence-backed
  confidence and identified gaps; it does not prove arbitrary software
  correct.

## Existing backend baseline

The current backend is a usable foundation:

| Existing module | Reuse in V2 | Current role and boundary |
|---|---|---|
| `specguard/ingestion.py` | Ingestion gateway | Bounded directory/ZIP ingestion, traversal and symlink checks, manifests and hashes |
| `specguard/adapters.py` | Code intelligence adapter registry | Python, JavaScript, TypeScript and Java detection/command contracts; Python execution is verified, other runtimes remain environment-dependent |
| `specguard/requirements.py` | Requirement intelligence parser | Markdown checklist parsing, normalization and unique IDs |
| `specguard/mapping.py` and `intelligence.py` | Traceability index | Source markers, test references, ambiguity signals and graph serialization |
| `specguard/providers.py` | Adversarial mutation provider port | Deterministic offline provider; Bedrock is an explicit boundary |
| `specguard/engine.py` | Adversarial verification kernel | Baseline check, one-requirement mutants, compilation, retry, equivalence and classifications |
| `specguard/sandbox.py` and `secure_execution.py` | Execution service | Temporary workspaces and Docker network/resource/read-only controls |
| `specguard/reporting.py` | Evidence projection | JSON and HTML reports |
| `specguard/backend.py` and `api.py` | API/job shell | Multipart project ingestion, in-process jobs, status/results/report/health endpoints |
| `specguard/models.py` | Compatibility layer | Current `Requirement`, `RequirementResult`, `AnalysisReport` and mutation records |

The current implementation is mutation-centered. V2 adds shared evidence and
engine orchestration around it; it does not discard the deterministic demo or
the existing API surface.

## Component architecture

```text
                         +-----------------------------+
                         | FastAPI compatibility/API   |
                         | project, evaluation, CI     |
                         +--------------+--------------+
                                        |
                         +--------------v--------------+
                         | Assurance Orchestrator      |
                         | run state, policies, gates  |
                         +--+------+------+------+-----+
                            |      |      |      |
       +--------------------+      |      |      +----------------------+
       |                           |      |                             |
+------v------+            +-------v------+ +-------v------+     +------v------+
| Requirement |            | Code         | | Behavioral   |     | Adversarial |
| Intelligence|            | Intelligence | | Verification|     | Testing     |
+------+------+            +-------+------+ +-------+------+     +------+------+
       |                           |              |                     |
       +---------------------------+--------------+---------------------+
                                   |
                          +--------v--------+
                          | Shared evidence |
                          | + traceability |
                          +---+---------+---+
                              |         |
                   +----------v--+   +--v----------------+
                   | Autonomous   |   | Continuous        |
                   | Test         |   | Assurance         |
                   | Engineering  |   | change/history    |
                   +-------------+   +-------------------+
                              |
                    +---------v----------+
                    | Isolated execution |
                    | adapters/providers |
                    +--------------------+
```

The orchestrator coordinates engines but does not own their domain logic. An
engine returns evidence and proposed next actions; the orchestrator applies
policy gates, persists state, and decides whether the next engine may run.

### Shared Test Oracle & Expected Behavior service

The Test Oracle & Expected Behavior service is a shared domain service, not a
seventh autonomous agent. It converts a normalized requirement into a typed
behavioral contract used by Behavioral Verification, Adversarial Testing, and
Autonomous Test Engineering.

Each contract contains:

- `preconditions`: required state, actors, inputs, and environmental assumptions;
- `actions`: the operation or interaction under evaluation;
- `postconditions`: observable outputs, state changes, errors, or invariants;
- `uncertainty`: missing, ambiguous, contradictory, or inferred clauses;
- `evidence_ids`: requirement text and deterministic extraction evidence;
- `oracle_version`: the rule set that produced the contract.

The service may return an incomplete contract. It must preserve uncertainty and
must not silently turn an inferred expected behavior into a verified fact. A
contract with unresolved uncertainty can drive candidate generation, but it
cannot by itself produce a verified compliance verdict.

### 1. Requirement Intelligence Engine

Responsibilities:

- Parse Markdown and future structured requirement formats.
- Normalize IDs, wording, actors, conditions, expected outcomes, constraints,
  and acceptance criteria.
- Split compound statements into atomic requirement candidates.
- Detect ambiguity, contradiction, missing actors/units, vague thresholds, and
  incompatible constraints.
- Identify explicit and inferred dependencies between requirements.
- Create requirement-to-source and requirement-to-test traceability candidates.

Inputs are `ProjectManifest`, requirement artifacts, and optional project
metadata. Outputs are normalized requirements, ambiguity/contradiction
findings, dependency edges, and traceability hypotheses. A parser finding is
static evidence until a reviewer or deterministic check confirms it.

### 2. Code Intelligence Engine

Responsibilities:

- Select a language adapter and record its version/toolchain evidence.
- Discover source, test, configuration, build, and generated files.
- Build a language-neutral symbol graph for modules, functions, classes,
  methods, imports, calls, inheritance, and dependency edges.
- Resolve explicit source markers and rank semantic mappings from requirements
  to symbols and execution paths.
- Track implementation traceability separately from test traceability.

The adapter contract remains the existing `LanguageAdapter` shape and expands
with `parse_symbols`, `dependency_graph`, `validate`, and normalized command
results. Language-specific parsing stays inside adapters; the shared graph and
evidence formats remain language-neutral. The roadmap explicitly adds:

- control-flow evidence: branches, guards, loops, exception paths, and
  reachable requirement-relevant paths;
- data-flow evidence: definitions, uses, taint/validation boundaries, and
  value transformations;
- call-path evidence: caller/callee chains, entry points, and the path used by
  a dynamic probe or test.

These are evidence records with source spans and tool versions, not claims of
formal program proof.

### 3. Behavioral Verification Engine

Responsibilities:

- Turn a normalized requirement into observable preconditions, action, and
  expected postconditions.
- Compare static implementation behavior with the requirement model.
- Run focused probes and contract examples in an isolated workspace.
- Report concrete observed inputs, outputs, exceptions, state transitions, and
  relevant source/test locations.
- Separate static findings from dynamically verified findings.

Static control-flow or data-flow analysis may produce a hypothesis such as
“the boundary check appears missing.” Only an isolated probe that reproduces
the violation may produce a dynamically verified behavioral finding.

### 4. Adversarial Testing Engine

Responsibilities:

- Preserve the current one-requirement-per-mutant workflow.
- Add boundary-value, negative-path, invalid-state, timeout, and failure
  scenario generation.
- Keep original and modified source, patch identity, provider provenance, and
  reproducibility seed in the evidence record.
- Validate syntax, build, behavior, timeout, and equivalent-mutant status
  before classification.
- Distinguish implementation compliance from whether the current tests detect
  the violation.

Existing `SpecGuard` becomes the first implementation of this engine behind a
new port. `PROTECTED` means a valid, requirement-specific mutant was caught by
relevant tests. `UNPROTECTED` means it survived. `INVALID` and `INCONCLUSIVE`
remain evidence states rather than compliance claims.

### 5. Autonomous Test Engineering Engine

Responsibilities:

- Use requirement gaps, traceability gaps, surviving mutants, and behavioral
  findings to propose candidate tests.
- Generate tests in a separate candidate artifact, never directly into the
  project by default.
- Run each candidate against the original implementation and the intended
  mutant.
- Verify that the candidate fails or passes for the expected reason and catches
  the targeted violation.
- Mark candidates as `hypothesis`, `validated_candidate`, `rejected`, or
  `inconclusive`; never treat generated tests as trusted solely because they
  execute.

This engine consumes adversarial evidence but does not silently change the
user’s test suite. Promotion to a project artifact is a separate policy-gated
operation for a future API.

### 6. Continuous Assurance Engine

Responsibilities:

- Accept a source/test/requirements revision and compute changed artifact,
  symbol, requirement, and dependency scopes.
- Re-evaluate affected requirements first, then expand to dependency-affected
  requirements according to policy.
- Compare current evidence with historical runs and identify regressions,
  recovered gaps, flaky results, and stale mappings.
- Maintain immutable run manifests and append-only evidence references.
- Expose future CI/CD triggers, commit status, and assurance deltas without
  coupling the core engines to a particular CI provider.

## Shared data and evidence model

V2 should add versioned records alongside the existing dataclasses rather than
breaking them immediately.

### Core records

```text
Project
  project_id, name, manifest_hash, created_at, adapter_id, adapter_version

Artifact
  artifact_id, project_id, kind, relative_path, sha256, size, revision_id

Requirement
  requirement_id, normalized_text, source_text, atomic, ambiguity,
  dependencies[], source_locations[], test_locations[]

CodeSymbol
  symbol_id, artifact_id, language, kind, qualified_name, span,
  parent_id, calls[], imports[], dependency_ids[]

TraceabilityLink
  link_id, requirement_id, target_id, target_kind, relation,
  origin, confidence, evidence_ids[]

Evidence
  evidence_id, run_id, kind, status, claim, requirement_id,
  artifact_ids[], source_spans[], input_hashes[], output_hash,
  execution_context, tool_versions, reproducibility, parent_ids[], created_at

Finding
  finding_id, requirement_id, category, severity, verdict,
  compliance_status, test_effectiveness_status, evidence_ids[],
  hypothesis_ids[], remediation_reference

TestCandidate
  candidate_id, requirement_id, source, intended_violation,
  original_result, mutant_result, validation_status, evidence_ids[]

EvaluationRun
  run_id, project_id, revision_id, policy_id, status, started_at,
  finished_at, engine_runs[], counts, error, reproducibility_manifest
```

### Evidence status and verdict separation

Evidence uses explicit statuses:

- `observed`: captured from a tool or isolated execution.
- `verified`: independently reproduced under a recorded policy.
- `hypothesis`: AI or static-analysis claim awaiting verification.
- `rejected`: attempted claim disproved by a check.
- `inconclusive`: timeout, infrastructure failure, flake, or insufficient data.

Findings carry separate dimensions:

- `implementation_compliance`: compliant, violation, unknown, or inconclusive;
- `test_effectiveness`: detected, survived, not_evaluated, or inconclusive;
- `verification_mode`: static, dynamic, mutation, generated_test, or mixed.

This prevents a surviving mutant from being reported as proof that the
implementation is wrong, and prevents a passing static check from being
reported as proof that tests are effective.

Every dynamic evidence record must include the isolated command, image digest,
resource policy, network policy, workspace/artifact hashes, stdout/stderr,
exit code, timeout state, and relevant test identifiers. Every AI hypothesis
must include provider/model configuration, prompt/input references, retry data,
and the later evidence that accepted or rejected it.

Every evaluation also carries a reproducibility manifest: schema versions,
source/requirements/test hashes, adapter and parser versions, oracle version,
provider/model configuration, random seed, mutation seed, execution image
digest, command vector, environment allowlist fingerprint, resource policy,
network policy, retry policy, and parent evidence IDs. A result is reusable
only when the relevant manifest fields match.

### Durable EvidenceStore

All engines write through an `EvidenceStore` port. The port supports immutable
evidence, findings, evaluation runs, lookup by requirement/run, and historical
queries. The Phase 0 local implementation uses SQLite with JSON payloads and
indexed IDs; an in-memory implementation remains available for unit tests and
the current local API. A future worker deployment can replace the store with a
server database without changing engine contracts.

## Data flow

1. Ingestion validates a directory or ZIP, creates a manifest, hashes artifacts,
   and rejects unsafe paths before any project code is executed.
2. Requirement Intelligence parses and normalizes criteria, emits ambiguity,
   contradiction, dependency, and requirement nodes.
3. Code Intelligence selects an adapter, builds the symbol/dependency graph,
   and emits implementation traceability candidates.
4. The orchestrator persists a run manifest and applies the execution policy.
5. Behavioral Verification performs static checks and, when permitted, isolated
   probes; each result references evidence rather than mutating a global state.
6. Adversarial Testing runs the baseline, creates validated requirement-specific
   mutants, and records test-effectiveness evidence.
7. Autonomous Test Engineering proposes and validates candidate tests against
   original and mutated workspaces.
8. Continuous Assurance computes revision impact, reuses unaffected evidence
   only when hashes and policy versions match, and schedules affected work.
9. Reporting projects the same evidence graph into API JSON, HTML, CLI output,
   and future CI status. Reports never invent progress or verdicts.

## API evolution

The existing FastAPI endpoints remain compatible:

- `POST /api/v1/projects`
- project requirements/source/tests upload endpoints
- `POST /api/v1/analysis`
- analysis status, results, report, and health endpoints

V2 should add versioned endpoints rather than overload existing response
shapes:

```text
POST /api/v2/evaluations
GET  /api/v2/evaluations/{run_id}
GET  /api/v2/evaluations/{run_id}/findings
GET  /api/v2/evaluations/{run_id}/evidence/{evidence_id}
GET  /api/v2/evaluations/{run_id}/traceability
GET  /api/v2/evaluations/{run_id}/test-candidates
POST /api/v2/evaluations/{run_id}/reverify
POST /api/v2/projects/{project_id}/revisions
GET  /api/v2/projects/{project_id}/history
POST /api/v2/ci/events
```

The v2 evaluation request selects engines and policies, for example:

```json
{
  "project_id": "...",
  "revision_id": "...",
  "engines": ["requirements", "code", "behavior", "adversarial", "tests", "continuous"],
  "provider": "offline",
  "execution_policy": "docker-python-3.12",
  "verification_mode": "static_and_dynamic"
}
```

Responses expose run state and evidence references. They do not expose an
engine’s internal chain-of-thought or fabricate percentage progress.

## Agent and orchestration responsibilities

The autonomous agent is a bounded planner, not an authority over evidence.

- The orchestrator selects the next engine from declared dependencies and
  policy gates.
- Each engine receives typed inputs and returns typed artifacts, findings,
  evidence, and suggested next actions.
- The agent may prioritize an ambiguity, choose a provider, or request a
  candidate test, but it cannot promote a hypothesis to a verified verdict.
- A verifier component checks schema, hashes, execution context, and required
  evidence before persistence.
- Retry budgets, tool allowlists, cost/time limits, and approval requirements
  are part of the run policy, not hidden agent behavior.

## Execution and security model

The current Docker boundary remains the default for uploaded code:

- no host-shell execution;
- separate temporary workspace per mutant/probe/candidate;
- read-only project mount;
- network disabled by default;
- CPU, memory, PID, and timeout limits;
- dropped capabilities and `no-new-privileges`;
- image identity recorded in the run manifest;
- cleanup after each run.

Static parsing and artifact hashing may run without executing project code. Any
operation that imports, builds, tests, or probes uploaded code must pass through
the execution worker. If Docker or an approved image is unavailable, the
orchestrator produces an explicit `inconclusive`/failed run and does not fall
back to the host.

The current backend uses an in-process job store and a Docker subprocess
boundary. A production worker should move execution to a dedicated worker
service, enforce cgroup quotas at the worker level, use immutable image digests,
store artifacts outside the worker filesystem, and scrub secrets from all
child environments and logs.

## Development phases and exit criteria

### Phase 0: contracts and compatibility

- Freeze v1 response shapes and add versioned model packages.
- Define evidence, finding, run-policy, traceability, reproducibility, and
  behavioral-contract schemas.
- Add the shared Test Oracle & Expected Behavior service as a deterministic
  contract builder with explicit uncertainty.
- Add the `EvidenceStore` port, in-memory implementation, and SQLite local
  implementation when round-trip and durability tests pass.
- Wrap existing adversarial results into v2 findings/evidence without changing
  v1 API/report output.
- Add serialization round-trip and migration tests.

Exit: existing 23-test suite remains green and v1 reports are unchanged.

### Phase 1: Requirement Intelligence Engine

- Extend parsing beyond checklist lines.
- Add deterministic normalized text, atomicity candidates, ambiguity,
  contradiction, dependency, and evidence-backed traceability records.
- Preserve current IDs/source hints and map old reports into the new model.

Exit: deterministic fixtures cover each finding type and every claim has
evidence status.

### Phase 2: Code Intelligence Engine

- Add symbol/dependency graph ports to language adapters.
- Implement Python symbol extraction first, then independently verified
  JavaScript/TypeScript/Java workers with their own images/toolchains.
- Replace marker-only mapping with ranked links that retain marker provenance.

Phase 2 implementation currently provides a bounded Python AST analyzer in
`specguard/v2/code_intelligence.py`. It emits module/class/function/method
symbols, statically resolvable local call edges, import/dependency facts,
branch/loop control-flow facts, local definition/use data-flow facts,
input-validation and exception-handling observations, and explicit-marker
requirement-to-symbol candidates. Each observation is stored as V2 evidence
with source spans, artifact hashes, adapter version, and a static execution
policy. JavaScript, TypeScript, and Java remain adapter-detection-only until
their parser/toolchain workers have isolated fixtures and verified evidence.

The analyzer does not claim whole-program semantic analysis, complete call
resolution, interprocedural data-flow, alias analysis, or formal verification.
Syntax failures are inconclusive; languages without a Phase 2 analyzer are
explicitly unsupported.

Exit: each claimed language has an actual isolated parse/build/test fixture;
unavailable toolchains remain explicitly unsupported.

### Phase 3: Behavioral Verification Engine

- Define requirement observables and probe artifacts.
- Add static finding versus dynamic verification status.
- Persist concrete inputs, outputs, exceptions, and execution context.

Exit: a fixture demonstrates a static hypothesis being verified, rejected, and
left inconclusive under separate runs.

Phase 3 implementation status (current): `specguard/v2/behavioral.py` provides
static Python test discovery, Docker-only baseline execution, reproducibility
metadata, redacted execution logs, and explicit comparison of supplied
observations with determinate Test Oracle contracts. Discovery never imports
test modules. Execution fails closed when Docker or an approved image is not
available and applies the existing read-only, no-network, timeout, memory,
CPU, and PID policy. Results are persisted as V2 Evidence and Findings through
the existing EvidenceStore. Passing a test suite is not treated as proof of
requirement compliance; no observation or an uncertain contract is
`inconclusive`/`not_evaluated`. Phase 3 currently supports Python
`unittest`/`pytest` discovery only. Dynamic requirement probes, automatic
observation extraction from arbitrary tests, immutable image-digest
resolution, and non-Python behavioral analyzers remain deferred.

### Phase 4: Adversarial Testing Engine

- Move current `SpecGuard` into the engine port.
- Add boundary, negative, and failure scenario generators.
- Add provenance, reproducibility seeds, and relevant-test attribution.

Exit: current RefundFlow classification remains 7 protected/3 unprotected and
all invalid/equivalent/timeout paths have evidence.

Phase 4 implementation status (current): `specguard/v2/adversarial.py` adds a
Python-first, requirement-aware adversarial engine. It requires a determinate
oracle contract plus explicit source/code traceability before selecting a
target; unsupported languages, uncertain contracts, and missing traceability
remain explicit unsupported/inconclusive outcomes. The operator set is
deterministic and AST-span-aware for comparison boundaries, boolean logic,
arithmetic, return values, input-validation guards, and exception handling.
Each mutant has stable IDs, source/mutated hashes, an exact patch, operator,
target, provenance, and Docker execution evidence. Mutant workspaces reject
symlinks, are temporary, and execute only through the existing read-only,
network-isolated Docker sandbox. Outcomes are `killed`, `survived`,
`equivalent`, `invalid`, `inconclusive`, or `execution_error`; only complete
killed/survived denominators receive a requirement score, and a killed mutant
does not assert implementation compliance. Mutation runs and mutants are
durably stored in the existing in-memory/SQLite EvidenceStore. Phase 4 is
Python-only; automatic probe generation, non-Python mutation engines, V2 API
orchestration, and generated tests remain deferred.

### Phase 5: Autonomous Test Engineering Engine

- Generate candidate tests into isolated artifacts.
- Run each candidate against original and intended mutant.
- Require verification before a candidate can be proposed for promotion.

Exit: surviving RefundFlow requirements produce candidates that are shown to
kill the intended mutant, with rejected and inconclusive examples.

Phase 5 implementation status (current): `specguard/v2/test_engineering.py`
performs deterministic gap analysis over valid, relevant Phase 4 outcomes and
keeps implementation compliance separate from test effectiveness. Surviving
mutants create test-effectiveness gaps; invalid, equivalent, unrelated, and
inconclusive outcomes do not enter the denominator. Candidate generation uses
an explicit invocation/assertion profile plus a determinate Test Oracle
contract. Missing profiles or uncertain contracts are blocked rather than
inventing assertions. Generated candidates are separate artifacts with stable
IDs, content hashes, requirement/source/mutant provenance, and reproducibility
metadata. Validation first checks static syntax/discovery, then runs the
candidate against the original and intended mutant in the existing Docker-only
sandbox; only original-pass plus intended-mutant-detection is `validated`.
SQLite and in-memory EvidenceStore persistence covers gaps, candidates,
validation records, findings, and test-engineering runs. AI generation,
automatic invocation inference, non-Python support, and Phase 6 history/CI
orchestration remain deferred.


### Phase 6: Continuous Assurance Engine

- Add revision manifests and changed-scope calculation.
- Add historical evidence storage and regression comparison.
- Add CI event adapter without coupling engines to one vendor.

Exit: a source revision re-evaluates only affected requirements and reports a
reproducible evidence delta.

Phase 6 implementation status (current): `specguard/v2/continuous.py` implements
the Continuous Assurance Engine:
1. `SnapshotBuilder`: Deterministic, content-hashed project snapshots (`ProjectSnapshot`)
   capturing file paths, SHA-256 hashes, file classifications (`source`, `test`,
   `requirement`, `dependency`, `config`), requirement normalized hashes, and path
   safety validation that rejects symlinks escaping project boundaries.
2. `ChangeDetector`: Detects added, modified, deleted, and renamed files (via content-hash
   matching), alongside requirement additions, modifications, and removals in `ChangeSet`.
3. `ImpactAnalyzer`: Propagates impacts across code symbols, call relationships,
   requirement-to-code traceability, test files, and transitive requirement dependencies,
   distinguishing affected from unaffected requirements, symbols, and tests.
4. `EvidenceLifecycleRecord`: Explicit evidence lifecycle tracking (`current`, `stale`,
   `superseded`, `invalidated`, `revalidated`) ensuring historical evidence is never
   deleted, while preventing stale findings from posing as verified current results.
5. `EvaluationPlanner`: Generates deterministic `EvaluationPlan` instances specifying
   minimal affected rerun scope vs reuse of verified evidence and findings.
6. `ContinuousAssuranceEngine`: Selective incremental re-evaluation orchestrating
   prior engines (`RequirementIntelligenceEngine`, `CodeIntelligenceEngine`,
   `BaselineRunner`, `BehavioralVerificationEngine`, `AdversarialTestingEngine`),
   preserving unaffected findings and emitting versioned `EvaluationRun` records.
7. `RunComparator`: Compares runs and identifies `compliance_regression`,
   `effectiveness_regression`, `coverage_regression`, and `execution_regression`,
   distinguishing genuine code regressions from intentional requirement updates.
8. `RepositoryMonitor`: Safe, stateless monitoring check for repository and filesystem
   changes without uncontrolled background threads.
9. `EvidenceStore`: In-memory and durable SQLite storage for snapshots, changesets,
   plans, comparisons, lifecycle records, and monitoring configurations with restart durability.
10. V2 API: Added REST endpoints under `/api/v2/...` for snapshots, changesets, impact
    analysis, plans, incremental re-evaluation, lifecycle, comparisons, and monitoring,
    preserving all existing V1 endpoints.

## Dependencies and risks

| Dependency/risk | Impact | Mitigation |
|---|---|---|
| Language parsers and toolchains | False mappings or blocked evaluations | Adapter-specific images, pinned versions, fixture-based verification |
| LLM/provider variability | Non-reproducible hypotheses or unsafe patches | Structured outputs, schema validation, deterministic offline provider, evidence gates |
| Docker availability | No dynamic verification | Fail closed; expose inconclusive status; require approved image digest |
| In-process job store | Lost history and poor multi-worker behavior | Introduce durable run/evidence store and queue in Continuous Assurance phase |
| Requirement ambiguity | Incorrect test generation | Preserve ambiguity findings and require evidence before verdicts |
| Equivalent mutants/flaky tests | Misleading protection results | Equivalent checks, repeated runs, stability evidence, explicit inconclusive state |
| Generated test trust | False confidence | Run against original and mutant; never auto-promote unverified candidates |
| Artifact and secret leakage | Security or privacy incident | Bounded ingestion, scrubbed environment, read-only mounts, isolated workers, retention policy |
| AWS/Failproof availability | Optional integrations may be absent | Keep provider ports; never invent SDK calls; offline path remains functional |

## Migration plan from the existing backend

1. Add a `specguard/v2` model namespace that wraps current `Requirement`,
   `RequirementResult`, `MutationProposal`, and `AnalysisReport` records.
2. Introduce an `EvidenceStore` interface with an in-memory implementation so
   current tests and local API behavior remain usable.
3. Put the current `SpecGuard.analyze` behind `AdversarialTestingEngine` and
   translate its results into `Finding` plus `Evidence` records.
4. Keep `ingestion.py`, `adapters.py`, `secure_execution.py`, and existing v1
   routes unchanged while adding typed ports and adapters around them.
5. Add the Requirement and Code Intelligence engines as independent pre-run
   stages. Their mappings are additive; existing explicit source markers remain
   authoritative evidence when present.
6. Add v2 evaluation endpoints and a compatibility projection that emits the
   current v1 report shape from the new evidence graph.
7. Move background jobs from `BackendStore` to a durable queue only after the
   shared run/evidence model is stable.
8. Add autonomous test candidates and continuous revision history behind new
   endpoints; do not change the existing dashboard contract.
9. Deprecate v1 only after consumers can read v2 evidence and migration tests
   prove equivalent results for the current RefundFlow demo.

## Definition of readiness for the next phase

The next implementation phase may begin after this architecture is accepted.
It should start with Phase 0 schema/compatibility work, not with new UI work or
an LLM integration. A phase is complete only when its evidence model, isolated
fixtures, negative cases, and regression tests pass; unsupported languages,
providers, and execution environments remain visibly unsupported.
