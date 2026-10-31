# SpecGuard backend API

Run the local backend with:

```powershell
uvicorn specguard.api:app --reload
```

The API is intentionally backend-only. A frontend can use the following stable
JSON and multipart endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Service health and version |
| POST | `/api/v1/projects` | Create a project (`name`, optional `metadata`) |
| POST | `/api/v1/projects/{id}/requirements` | Upload and validate `requirements.md` |
| POST | `/api/v1/projects/{id}/source` | Upload a source file or ZIP; ZIPs are safely extracted |
| POST | `/api/v1/projects/{id}/tests` | Upload an additional test file |
| POST | `/api/v1/analysis` | Queue an analysis (`project_id`, `provider`, `execution`) |
| GET | `/api/v1/analysis/{id}` | Job status and summary |
| GET | `/api/v1/analysis/{id}/results` | Structured requirement results |
| GET | `/api/v1/analysis/{id}/report?format=json\|html` | Full report |
| GET | `/api/v2/health` | V2 Service health and version (`2.0.0`) |
| POST | `/api/v2/snapshots` | Create an immutable content-hashed project snapshot |
| GET | `/api/v2/snapshots/{id}` | Retrieve a project snapshot |
| POST | `/api/v2/changes/detect` | Compute added, modified, deleted, renamed files and req changes |
| POST | `/api/v2/impact/analyze` | Perform impact analysis linking changes to requirements and symbols |
| POST | `/api/v2/plans/generate` | Generate minimal incremental evaluation plan |
| GET | `/api/v2/plans/{id}` | Retrieve an evaluation plan |
| POST | `/api/v2/reevaluate` | Trigger selective incremental evaluation execution |
| GET | `/api/v2/evidence/lifecycle` | List evidence lifecycle records (filterable by state) |
| GET | `/api/v2/evidence/{id}/lifecycle` | Retrieve evidence lifecycle state |
| POST | `/api/v2/runs/compare` | Compare two evaluation runs and detect regressions |
| GET | `/api/v2/runs/{id}/regressions` | Retrieve regression summary for an evaluation run |
| POST | `/api/v2/monitoring/config` | Create a repository monitoring configuration |
| GET | `/api/v2/monitoring/config/{id}` | Retrieve monitoring configuration |
| POST | `/api/v2/monitoring/check` | Perform safe repository change check |

Uploaded projects are never executed directly on the host by the API. Analysis
requires `execution="docker"`, an approved Docker image, and a Docker runtime;
set `SPECGUARD_DOCKER_IMAGE` to the approved image name. When those are unavailable the job fails closed with an explicit error. The
current in-process job store is suitable for local development and should be
replaced with durable storage and a worker queue for multi-worker deployment.
