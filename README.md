# SpecGuard

SpecGuard is a Python-first, requirement-aware mutation-testing MVP. It parses
acceptance criteria, maps each criterion to an explicit source marker, creates
one deterministic mutant per requirement, validates compilation, runs tests in
an isolated temporary workspace, and classifies the result as protected,
unprotected, invalid, or inconclusive.

## Quick start

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m specguard.cli .
```

The demo baseline deliberately covers seven of ten requirements. The analysis
should report REQ-004, REQ-008, and REQ-010 as unprotected while the other seven
are protected. Reports are written to `outputs/specguard-report.json` and
`outputs/specguard-report.html`; the optional dashboard runs with
`streamlit run specguard/dashboard.py`.

The deterministic provider is offline and safe for local demos. Bedrock,
Failproof AI, Lambda, CodeBuild, and S3 integration files remain explicit
boundaries until their real SDK or deployment contract is configured.

The backend API is available with `python -m pip install -e ".[backend]"` and
`uvicorn specguard.api:app --reload`. See [API.md](API.md) and
[BACKEND_STATUS.md](BACKEND_STATUS.md) for endpoint schemas and security
limitations. Uploaded projects are executed only through the Docker boundary;
the API fails closed when Docker or an approved execution image is unavailable.
