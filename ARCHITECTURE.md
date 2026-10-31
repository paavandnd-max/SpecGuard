# Architecture

`requirements.py` parses checklist criteria into stable IDs. `mapping.py`
finds explicit `# specguard: REQ-*` markers, keeping traceability reviewable.
`providers.py` separates mutation generation from execution: the deterministic
provider supports repeatable offline runs, while the Bedrock and Failproof
adapters are explicit integration boundaries.

`engine.py` performs a baseline sanity check, creates a fresh candidate for
each requirement, compiles every Python file, executes the safe test runner,
and retries one time after an invalid proposal. AST comparison detects
equivalent mutants. `reporting.py` serializes the result to JSON and HTML.

The runner uses argument vectors, no shell, a timeout, a reduced environment,
and a temporary copied workspace. Cloud files under `specguard/integrations`
are deployment placeholders and are not invoked by local analysis.

The backend layer adds `ingestion.py` for bounded, path-safe project uploads,
`adapters.py` for language/framework detection and command contracts,
`intelligence.py` for requirement/test traceability, and `api.py` for the
frontend-facing FastAPI surface. `secure_execution.py` is a Docker boundary;
the API refuses to execute uploaded projects when Docker or an approved image
is unavailable.
