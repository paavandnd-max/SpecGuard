from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .backend import BackendError, BackendStore
from .ingestion import IngestionError
from .reporting import report_dict, write_html
from .v2 import (
    ChangeDetector,
    ContinuousAssuranceEngine,
    EvaluationPlanner,
    EvidenceLifecycleState,
    EvidenceStore,
    ImpactAnalyzer,
    InMemoryEvidenceStore,
    MonitoringConfiguration,
    RepositoryMonitor,
    SnapshotBuilder,
)
import sys
from .secure_execution import DockerSandbox, ExecutionPolicy
from .v2.adversarial import AdversarialTestingEngine
from .v2.code_intelligence import CodeIntelligenceEngine
from .v2.requirement_intelligence import RequirementIntelligenceEngine
from .v2.test_engineering import AutonomousTestEngineeringEngine


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    metadata: dict = Field(default_factory=dict)


class AnalysisCreate(BaseModel):
    project_id: str
    provider: str = Field(default="offline", pattern="^(offline|bedrock)$")
    execution: str = Field(default="docker", pattern="^(docker)$")


class SnapshotCreateRequest(BaseModel):
    project_path: str
    metadata: dict = Field(default_factory=dict)


class ChangeDetectRequest(BaseModel):
    target_snapshot_id: str
    base_snapshot_id: str | None = None


class ImpactAnalyzeRequest(BaseModel):
    changeset_id: str
    project_path: str


class PlanGenerateRequest(BaseModel):
    impact_id: str
    target_snapshot_id: str
    base_run_id: str | None = None


class ReevaluateRequest(BaseModel):
    plan_id: str
    project_path: str
    base_run_id: str | None = None


class RunCompareRequest(BaseModel):
    base_run_id: str
    target_run_id: str


class MonitoringConfigCreate(BaseModel):
    project_id: str
    root_path: str
    watch_paths: list[str] = Field(default_factory=list)
    enabled: bool = True


class MonitoringCheckRequest(BaseModel):
    config_id: str
    last_snapshot_id: str | None = None


class RequirementAnalyzeRequest(BaseModel):
    text: str | None = None
    project_path: str | None = None
    run_id: str = "requirements-intelligence"


class RequirementsTextRequest(BaseModel):
    text: str


def _error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail={"code": exc.__class__.__name__, "message": str(exc)})


def create_app(store: BackendStore | None = None, evidence_store: EvidenceStore | None = None) -> FastAPI:
    app = FastAPI(title="SpecGuard Backend", version="1.0.0", description="Requirements evaluation API")
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.store = store or BackendStore()
    app.state.evidence_store = evidence_store or InMemoryEvidenceStore()
    app.state.continuous = ContinuousAssuranceEngine(store=app.state.evidence_store)

    @app.get("/api/v1/health")
    def health() -> dict:
        return {"status": "ok", "service": "specguard-backend", "version": app.version}

    @app.post("/api/v1/projects", status_code=201)
    def create_project(request: ProjectCreate) -> dict:
        record = app.state.store.create_project(request.name, request.metadata)
        return {"id": record.id, "name": request.name, "metadata": record.metadata, "status": "created"}

    @app.get("/api/v1/projects")
    def list_projects() -> list[dict]:
        with app.state.store.lock:
            results = []
            for p in app.state.store.projects.values():
                req_file = p.root / "requirements.md"
                source_dir = p.root / "source"
                results.append({
                    "id": p.id,
                    "name": p.metadata.get("name", p.id),
                    "created_at": p.created_at,
                    "metadata": p.metadata,
                    "has_requirements": req_file.exists(),
                    "has_source": source_dir.exists(),
                    "requirements_path": str(req_file) if req_file.exists() else None,
                    "source_path": str(source_dir) if source_dir.exists() else None,
                })
            return sorted(results, key=lambda x: x["created_at"], reverse=True)

    @app.get("/api/v1/projects/{project_id}")
    def get_project(project_id: str) -> dict:
        try:
            p = app.state.store.project(project_id)
            req_file = p.root / "requirements.md"
            source_dir = p.root / "source"
            return {
                "id": p.id,
                "name": p.metadata.get("name", p.id),
                "created_at": p.created_at,
                "metadata": p.metadata,
                "has_requirements": req_file.exists(),
                "has_source": source_dir.exists(),
                "requirements_path": str(req_file) if req_file.exists() else None,
                "source_path": str(source_dir) if source_dir.exists() else None,
            }
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.post("/api/v1/projects/{project_id}/requirements-text")
    def upload_requirements_text(project_id: str, req: RequirementsTextRequest) -> dict:
        import re
        try:
            formatted_lines = []
            for line in req.text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith(("- [ ]", "- [x]", "- [X]", "* [ ]", "* [x]", "* [X]")) or re.match(r"^\d+[.)]", stripped):
                    formatted_lines.append(stripped)
                else:
                    formatted_lines.append(f"- [ ] {stripped}")
            content = "\n".join(formatted_lines) if formatted_lines else "- [ ] REQ-001: Default requirement placeholder."
            path = app.state.store.save_requirements(project_id, "requirements.md", content.encode("utf-8"))
            return {"project_id": project_id, "path": str(path.name), "status": "validated"}
        except (BackendError, IngestionError, ValueError) as exc:
            raise _error(exc)

    @app.post("/api/v1/projects/{project_id}/requirements")
    async def upload_requirements(project_id: str, file: UploadFile = File(...)) -> dict:
        try:
            data = await file.read(app.state.store.limits.max_file_size + 1)
            path = app.state.store.save_requirements(project_id, file.filename or "requirements.md", data)
            return {"project_id": project_id, "path": str(path.name), "status": "validated"}
        except (BackendError, IngestionError, ValueError) as exc:
            raise _error(exc)

    @app.post("/api/v1/projects/{project_id}/source")
    async def upload_source(project_id: str, file: UploadFile = File(...)) -> dict:
        try:
            data = await file.read(app.state.store.limits.max_total_size + 1)
            manifest = app.state.store.save_source(project_id, file.filename or "source.zip", data)
            return {"project_id": project_id, "status": "validated", "manifest": manifest.to_dict()}
        except (BackendError, IngestionError, ValueError) as exc:
            raise _error(exc)

    @app.post("/api/v1/projects/{project_id}/tests")
    async def upload_tests(project_id: str, file: UploadFile = File(...)) -> dict:
        try:
            data = await file.read(app.state.store.limits.max_file_size + 1)
            path = app.state.store.save_tests(project_id, file.filename or "test_file", data)
            return {"project_id": project_id, "path": str(path.relative_to(app.state.store.project(project_id).root)), "status": "validated"}
        except (BackendError, IngestionError, ValueError) as exc:
            raise _error(exc)

    @app.post("/api/v1/analysis", status_code=202)
    def start_analysis(request: AnalysisCreate) -> dict:
        try:
            analysis = app.state.store.submit_analysis(request.project_id, request.provider, request.execution)
            return app.state.store.analysis_payload(analysis)
        except BackendError as exc:
            raise _error(exc)

    @app.get("/api/v1/analysis/{analysis_id}")
    def get_analysis(analysis_id: str) -> dict:
        try:
            return app.state.store.analysis_payload(app.state.store.analysis(analysis_id))
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.get("/api/v1/analysis/{analysis_id}/results")
    def get_results(analysis_id: str) -> dict:
        try:
            analysis = app.state.store.analysis(analysis_id)
            if not analysis.report:
                return {"analysis_id": analysis_id, "status": analysis.status, "results": []}
            return {"analysis_id": analysis_id, "status": analysis.status, "results": report_dict(analysis.report)["results"], "counts": analysis.report.counts()}
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.get("/api/v1/analysis/{analysis_id}/report")
    def get_report(analysis_id: str, format: str = Query(default="json", pattern="^(json|html)$")):
        try:
            analysis = app.state.store.analysis(analysis_id)
            if not analysis.report:
                return JSONResponse({"analysis_id": analysis_id, "status": analysis.status, "error": analysis.error})
            if format == "html":
                temporary = Path(app.state.store.root) / f"{analysis_id}.html"
                write_html(analysis.report, temporary)
                return HTMLResponse(temporary.read_text(encoding="utf-8"))
            return JSONResponse(report_dict(analysis.report))
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    # --- SpecGuard V2 Continuous Assurance Endpoints ---

    @app.get("/api/v2/health")
    def health_v2() -> dict:
        return {"status": "ok", "service": "specguard-backend", "version": "2.0.0"}

    @app.post("/api/v2/snapshots", status_code=201)
    def create_snapshot(request: SnapshotCreateRequest) -> dict:
        try:
            snapshot = app.state.continuous.create_snapshot(request.project_path, request.metadata)
            return snapshot.to_dict()
        except Exception as exc:
            raise _error(exc)

    @app.get("/api/v2/snapshots/{snapshot_id}")
    def get_snapshot(snapshot_id: str) -> dict:
        snapshot = app.state.evidence_store.get_snapshot(snapshot_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return snapshot.to_dict()

    @app.post("/api/v2/changes/detect")
    def detect_changes(request: ChangeDetectRequest) -> dict:
        try:
            target = app.state.evidence_store.get_snapshot(request.target_snapshot_id)
            if not target:
                raise HTTPException(status_code=404, detail="Target snapshot not found")
            base = None
            if request.base_snapshot_id:
                base = app.state.evidence_store.get_snapshot(request.base_snapshot_id)
                if not base:
                    raise HTTPException(status_code=404, detail="Base snapshot not found")
            changeset = app.state.continuous.detect_changes(base, target)
            return changeset.to_dict()
        except HTTPException:
            raise
        except Exception as exc:
            raise _error(exc)

    @app.post("/api/v2/impact/analyze")
    def analyze_impact(request: ImpactAnalyzeRequest) -> dict:
        try:
            changeset = app.state.evidence_store.get_changeset(request.changeset_id)
            if not changeset:
                raise HTTPException(status_code=404, detail="Changeset not found")
            root = Path(request.project_path).resolve()
            req_file = root / "requirements.md"
            requirements = []
            symbols = ()
            traceability = ()
            if req_file.exists():
                r_int = RequirementIntelligenceEngine().analyze(req_file, root)
                requirements = list(r_int.requirements)
                c_int = CodeIntelligenceEngine(store=app.state.evidence_store).analyze(root, req_file)
                symbols = c_int.symbols
                traceability = c_int.traceability
            evidence = app.state.evidence_store.list_evidence()
            findings = app.state.evidence_store.list_findings()
            impact = app.state.continuous.analyze_impact(
                changeset,
                requirements,
                symbols=symbols,
                traceability=traceability,
                evidence=evidence,
                findings=findings,
            )
            return impact.to_dict()
        except HTTPException:
            raise
        except Exception as exc:
            raise _error(exc)

    @app.post("/api/v2/plans/generate", status_code=201)
    def generate_plan(request: PlanGenerateRequest) -> dict:
        try:
            target_snap = app.state.evidence_store.get_snapshot(request.target_snapshot_id)
            if not target_snap:
                raise HTTPException(status_code=404, detail="Target snapshot not found")
            base_run = None
            if request.base_run_id:
                base_run = app.state.evidence_store.get_run(request.base_run_id)
            findings = app.state.evidence_store.list_findings()
            evidence = app.state.evidence_store.list_evidence()
            from .v2.models import ImpactAnalysis
            impact = ImpactAnalysis(
                impact_id=request.impact_id,
                changeset_id="change-plan",
                impacted_requirement_ids=(),
                unaffected_requirement_ids=tuple(target_snap.requirement_hashes.keys()),
            )
            plan = app.state.continuous.generate_plan(
                impact,
                target_snap,
                base_run=base_run,
                all_findings=findings,
                all_evidence=evidence,
            )
            return plan.to_dict()
        except HTTPException:
            raise
        except Exception as exc:
            raise _error(exc)

    @app.get("/api/v2/plans/{plan_id}")
    def get_plan(plan_id: str) -> dict:
        plan = app.state.evidence_store.get_plan(plan_id)
        if not plan:
            raise HTTPException(status_code=404, detail="Evaluation plan not found")
        return plan.to_dict()

    @app.post("/api/v2/reevaluate")
    def trigger_reevaluate(request: ReevaluateRequest) -> dict:
        try:
            plan = app.state.evidence_store.get_plan(request.plan_id)
            if not plan:
                raise HTTPException(status_code=404, detail="Evaluation plan not found")
            base_run = app.state.evidence_store.get_run(request.base_run_id) if request.base_run_id else None
            run = app.state.continuous.execute_plan(plan, request.project_path, base_run=base_run)
            return run.to_dict()
        except HTTPException:
            raise
        except Exception as exc:
            raise _error(exc)

    @app.get("/api/v2/evidence/{evidence_id}/lifecycle")
    def get_evidence_lifecycle(evidence_id: str) -> dict:
        record = app.state.evidence_store.get_lifecycle_record(evidence_id)
        if not record:
            raise HTTPException(status_code=404, detail="Lifecycle record not found")
        return record.to_dict()

    @app.get("/api/v2/evidence/lifecycle")
    def list_evidence_lifecycle(state: str | None = None) -> dict:
        st = EvidenceLifecycleState(state) if state else None
        records = app.state.evidence_store.list_lifecycle_records(state=st)
        return {"records": [r.to_dict() for r in records]}

    @app.post("/api/v2/runs/compare")
    def compare_runs(request: RunCompareRequest) -> dict:
        try:
            comparison = app.state.continuous.compare_runs(request.base_run_id, request.target_run_id)
            return comparison.to_dict()
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:
            raise _error(exc)

    @app.get("/api/v2/runs/{run_id}/regressions")
    def get_run_regressions(run_id: str) -> dict:
        run = app.state.evidence_store.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return {"run_id": run_id, "counts": run.counts, "status": run.status.value}

    @app.post("/api/v2/monitoring/config", status_code=201)
    def create_monitoring_config(request: MonitoringConfigCreate) -> dict:
        config_id = f"mon-{request.project_id}"
        config = MonitoringConfiguration(
            config_id=config_id,
            project_id=request.project_id,
            root_path=str(Path(request.root_path).resolve()),
            watch_paths=tuple(request.watch_paths),
            enabled=request.enabled,
            created_at=time.time(),
        )
        app.state.evidence_store.save_monitoring_config(config)
        return config.to_dict()

    @app.get("/api/v2/monitoring/config/{config_id}")
    def get_monitoring_config(config_id: str) -> dict:
        config = app.state.evidence_store.get_monitoring_config(config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Monitoring configuration not found")
        return config.to_dict()

    @app.post("/api/v2/monitoring/check")
    def check_monitoring(request: MonitoringCheckRequest) -> dict:
        config = app.state.evidence_store.get_monitoring_config(request.config_id)
        if not config:
            raise HTTPException(status_code=404, detail="Monitoring configuration not found")
        last_snap = app.state.evidence_store.get_snapshot(request.last_snapshot_id) if request.last_snapshot_id else None
        monitor = RepositoryMonitor(builder=app.state.continuous.snapshot_builder, detector=app.state.continuous.change_detector)
        has_changes, changeset, new_snap = monitor.check_for_changes(config, last_snap)
        app.state.evidence_store.save_snapshot(new_snap)
        if changeset:
            app.state.evidence_store.save_changeset(changeset)
        return {
            "has_changes": has_changes,
            "changeset": changeset.to_dict() if changeset else None,
            "snapshot": new_snap.to_dict(),
        }

    # --- SpecGuard V2 Requirement Intelligence & UI Serving ---

    @app.get("/api/v2/requirements")
    def get_requirements() -> dict:
        default_path = Path(__file__).resolve().parent.parent / "requirements.md"
        if not default_path.exists():
            return {"status": "ok", "requirements": [], "findings": [], "contracts": [], "links": [], "evidence": [], "counts": {"total": 0}}
        engine = RequirementIntelligenceEngine()
        run_id = "requirements-default"
        result = engine.analyze(default_path, run_id=run_id)
        return {
            "status": "ok",
            "run_id": run_id,
            "requirements": [r.to_dict() for r in result.requirements],
            "findings": [f.to_dict() for f in result.findings],
            "contracts": [c.to_dict() for c in result.behavior_contracts],
            "links": [l.to_dict() for l in result.traceability],
            "evidence": [e.to_dict() for e in result.evidence],
            "counts": {
                "total": len(result.requirements),
                "atomic": sum(1 for r in result.requirements if getattr(r, "atomic", True)),
                "ambiguous": sum(1 for r in result.requirements if getattr(r, "ambiguous", False)),
                "findings": len(result.findings),
                "contracts": len(result.behavior_contracts),
            },
        }

    @app.post("/api/v2/requirements/analyze")
    def analyze_requirements(request: RequirementAnalyzeRequest) -> dict:
        import os
        import re
        import tempfile
        engine = RequirementIntelligenceEngine()
        temp_file = None
        try:
            if request.text:
                formatted_lines = []
                for line in request.text.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.startswith(("- [ ]", "- [x]", "- [X]", "* [ ]", "* [x]", "* [X]")) or re.match(r"^\d+[.)]", stripped):
                        formatted_lines.append(stripped)
                    else:
                        formatted_lines.append(f"- [ ] {stripped}")
                content_to_write = "\n".join(formatted_lines) if formatted_lines else "- [ ] REQ-001: Default requirement placeholder."

                with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
                    f.write(content_to_write)
                    temp_file = f.name
                req_path = temp_file
            elif request.project_path:
                p = Path(request.project_path)
                req_path = str(p / "requirements.md" if (p / "requirements.md").exists() else p)
            else:
                default_path = Path(__file__).resolve().parent.parent / "requirements.md"
                req_path = str(default_path)

            result = engine.analyze(req_path, run_id=request.run_id)
            for f in result.findings:
                app.state.evidence_store.save_finding(f)
            for e in result.evidence:
                app.state.evidence_store.save_evidence(e)

            return {
                "status": "ok",
                "run_id": request.run_id,
                "requirements": [r.to_dict() for r in result.requirements],
                "findings": [f.to_dict() for f in result.findings],
                "contracts": [c.to_dict() for c in result.behavior_contracts],
                "links": [l.to_dict() for l in result.traceability],
                "evidence": [e.to_dict() for e in result.evidence],
                "counts": {
                    "total": len(result.requirements),
                    "atomic": sum(1 for r in result.requirements if getattr(r, "atomic", True)),
                    "ambiguous": sum(1 for r in result.requirements if getattr(r, "ambiguous", False)),
                    "findings": len(result.findings),
                    "contracts": len(result.behavior_contracts),
                },
            }
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass

    @app.post("/api/v2/projects/{project_id}/analyze")
    def analyze_project(project_id: str) -> dict:
        try:
            record = app.state.store.project(project_id)
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        req_path = record.root / "requirements.md"
        if not req_path.exists():
            raise HTTPException(status_code=400, detail="Project does not have requirements.md uploaded yet")

        source_root = record.root / "source"
        if not source_root.exists():
            source_root = record.root

        req_engine = RequirementIntelligenceEngine()
        req_res = req_engine.analyze(req_path, project_root=source_root, run_id=f"req-intel-{project_id[:8]}")

        for f in req_res.findings:
            app.state.evidence_store.save_finding(f)
        for e in req_res.evidence:
            app.state.evidence_store.save_evidence(e)

        code_data = None
        links = list(req_res.traceability)
        has_py = any(source_root.glob("**/*.py"))
        if has_py:
            try:
                code_engine = CodeIntelligenceEngine(store=app.state.evidence_store)
                code_res = code_engine.analyze(source_root, req_path, run_id=f"code-intel-{project_id[:8]}")
                code_data = {
                    "language": code_res.language,
                    "framework": code_res.framework,
                    "status": code_res.status,
                    "symbols_count": len(code_res.symbols),
                    "symbols": [
                        {
                            "symbol_id": s.symbol_id,
                            "qualified_name": s.qualified_name,
                            "kind": s.kind,
                            "language": s.language,
                            "file_path": (s.span.get("path") or s.span.get("file_path", "")) if isinstance(s.span, dict) else (getattr(s.span, "path", None) or getattr(s.span, "file_path", "")) if s.span else "",
                            "span": f"L{s.span.get('start_line', 1)}-L{s.span.get('end_line', 1)}" if isinstance(s.span, dict) else (f"L{s.span.start_line}-L{s.span.end_line}" if s.span else ""),
                        }
                        for s in code_res.symbols[:100]
                    ],
                    "traceability_count": len(code_res.traceability),
                    "evidence_count": len(code_res.evidence),
                }
                links.extend(code_res.traceability)
            except Exception as code_err:
                code_data = {"status": "error", "message": str(code_err)}

        return {
            "status": "ok",
            "project_id": project_id,
            "project_name": record.metadata.get("name", project_id),
            "requirements": [r.to_dict() for r in req_res.requirements],
            "findings": [f.to_dict() for f in req_res.findings],
            "contracts": [c.to_dict() for c in req_res.behavior_contracts],
            "links": [l.to_dict() for l in links],
            "code_intelligence": code_data,
            "counts": {
                "total": len(req_res.requirements),
                "atomic": sum(1 for r in req_res.requirements if getattr(r, "atomic", True)),
                "ambiguous": sum(1 for r in req_res.requirements if getattr(r, "ambiguous", False)),
                "findings": len(req_res.findings),
                "contracts": len(req_res.behavior_contracts),
                "symbols": code_data.get("symbols_count", 0) if code_data else 0,
                "links": len(links),
            },
        }

    @app.get("/api/v2/projects/{project_id}/code-intelligence")
    def get_project_code_intelligence(project_id: str) -> dict:
        try:
            record = app.state.store.project(project_id)
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        source_root = record.root / "source"
        if not source_root.exists():
            return {"status": "empty", "message": "No repository source code uploaded yet", "symbols": [], "traceability": []}

        req_path = record.root / "requirements.md"
        engine = CodeIntelligenceEngine(store=app.state.evidence_store)
        res = engine.analyze(source_root, req_path if req_path.exists() else None, run_id=f"code-intel-{project_id[:8]}")
        return {
            "status": res.status,
            "language": res.language,
            "framework": res.framework,
            "symbols_count": len(res.symbols),
            "symbols": [
                {
                    "symbol_id": s.symbol_id,
                    "qualified_name": s.qualified_name,
                    "kind": s.kind,
                    "language": s.language,
                    "file_path": (s.span.get("path") or s.span.get("file_path", "")) if isinstance(s.span, dict) else (getattr(s.span, "path", None) or getattr(s.span, "file_path", "")) if s.span else "",
                    "span": f"L{s.span.get('start_line', 1)}-L{s.span.get('end_line', 1)}" if isinstance(s.span, dict) else (f"L{s.span.start_line}-L{s.span.end_line}" if s.span else ""),
                }
                for s in res.symbols
            ],
            "traceability": [t.to_dict() for t in res.traceability],
            "evidence_count": len(res.evidence),
        }

    @app.get("/api/v2/environment")
    def get_environment() -> dict:
        sandbox = DockerSandbox(ExecutionPolicy())
        docker_available = sandbox.available()
        docker_reason = None if docker_available else sandbox.explain_unavailable()
        evidence_records = app.state.evidence_store.list_lifecycle_records()
        findings = app.state.evidence_store.list_findings()
        return {
            "status": "ok",
            "service": "specguard-backend",
            "version": "2.0.0",
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
            "docker_available": docker_available,
            "docker_status": "active" if docker_available else "offline",
            "docker_message": "Docker rootless sandbox active" if docker_available else f"Sandbox offline: {docker_reason} (Fail-closed execution boundary)",
            "limits": {
                "max_file_size": app.state.store.limits.max_file_size,
                "max_total_size": app.state.store.limits.max_total_size,
                "max_files": app.state.store.limits.max_files,
            },
            "evidence_count": len(evidence_records),
            "findings_count": len(findings),
            "engines": [
                {"name": "Requirement Intelligence", "status": "active", "version": "v2.0"},
                {"name": "Python Code Intelligence", "status": "active", "version": "v2.0"},
                {"name": "Behavioral Verification", "status": "active", "version": "v2.0"},
                {"name": "Advanced Adversarial Testing", "status": "active", "version": "v2.0"},
                {"name": "Autonomous Test Engineering", "status": "active", "version": "v2.0"},
                {"name": "Continuous Assurance", "status": "active", "version": "v2.0"},
            ],
        }

    @app.get("/api/v2/projects/{project_id}/overview")
    def get_project_overview(project_id: str) -> dict:
        try:
            record = app.state.store.project(project_id)
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        req_path = record.root / "requirements.md"
        source_root = record.root / "source" if (record.root / "source").exists() else record.root

        req_count = 0
        amb_count = 0
        contracts_count = 0
        findings_count = 0
        if req_path.exists():
            req_engine = RequirementIntelligenceEngine()
            req_res = req_engine.analyze(req_path, project_root=source_root, run_id=f"overview-{project_id[:8]}")
            req_count = len(req_res.requirements)
            amb_count = sum(1 for r in req_res.requirements if getattr(r, "ambiguous", False))
            contracts_count = len(req_res.behavior_contracts)
            findings_count = len(req_res.findings)

        code_symbols_count = 0
        has_py = any(source_root.glob("**/*.py"))
        if has_py and req_path.exists():
            try:
                code_engine = CodeIntelligenceEngine(store=app.state.evidence_store)
                code_res = code_engine.analyze(source_root, req_path, run_id=f"overview-code-{project_id[:8]}")
                code_symbols_count = len(code_res.symbols)
            except Exception:
                code_symbols_count = 0

        sandbox = DockerSandbox(ExecutionPolicy())
        docker_available = sandbox.available()
        docker_reason = None if docker_available else sandbox.explain_unavailable()
        project_evidence = [e.to_dict() for e in app.state.evidence_store.list_lifecycle_records()[:20]]

        return {
            "status": "ok",
            "project_id": project_id,
            "project_name": record.metadata.get("name", project_id),
            "has_requirements": req_path.exists(),
            "has_source": has_py,
            "docker_available": docker_available,
            "docker_status": "active" if docker_available else "offline",
            "docker_message": "Docker rootless sandbox active" if docker_available else f"Sandbox offline: {docker_reason}",
            "metrics": {
                "total_requirements": req_count,
                "ambiguous_requirements": amb_count,
                "behavior_contracts": contracts_count,
                "ast_symbols": code_symbols_count,
                "findings": findings_count,
                "evidence_records": len(project_evidence),
            },
            "recent_evidence": project_evidence,
        }

    @app.post("/api/v2/projects/{project_id}/adversarial")
    def run_adversarial_testing(project_id: str) -> dict:
        try:
            record = app.state.store.project(project_id)
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        req_path = record.root / "requirements.md"
        source_root = record.root / "source" if (record.root / "source").exists() else record.root
        if not req_path.exists():
            raise HTTPException(status_code=400, detail="Project does not have requirements.md uploaded yet")

        req_engine = RequirementIntelligenceEngine()
        req_res = req_engine.analyze(req_path, project_root=source_root, run_id=f"adv-{project_id[:8]}")
        code_engine = CodeIntelligenceEngine(store=app.state.evidence_store)
        code_res = code_engine.analyze(source_root, req_path, run_id=f"adv-code-{project_id[:8]}")

        adv_engine = AdversarialTestingEngine(store=app.state.evidence_store)
        res = adv_engine.run(
            source_root,
            req_res.requirements,
            contracts=req_res.behavior_contracts,
            traceability=code_res.traceability,
            symbols=code_res.symbols,
            run_id=f"adv-run-{project_id[:8]}"
        )
        sandbox = DockerSandbox(ExecutionPolicy())
        return {
            "status": "ok",
            "run_id": res.run.run_id,
            "run_status": res.run.status,
            "targets_count": len(res.targeting.targets),
            "targets": [
                {
                    "target_id": f"target-{t.requirement_id}",
                    "target_line": t.target_line,
                    "target_symbol_id": t.target_symbol_id,
                    "requirement_id": t.requirement_id,
                    "status": t.status,
                    "reason": t.reason,
                    "source_path": str(t.source_path) if t.source_path else None,
                }
                for t in res.targeting.targets
            ],
            "mutants_count": len(res.mutants),
            "mutants": [m.to_dict() for m in res.mutants[:50]],
            "findings_count": len(res.findings),
            "findings": [f.to_dict() for f in res.findings[:50]],
            "evidence_count": len(res.evidence),
            "docker_available": sandbox.available(),
            "docker_notice": "Dynamic test execution against mutants is inconclusive when Docker is unconfigured (fail-closed execution enforced)." if not sandbox.available() else "Dynamic test execution performed in Docker sandbox."
        }

    @app.post("/api/v2/projects/{project_id}/test-engineering")
    def run_test_engineering(project_id: str) -> dict:
        try:
            record = app.state.store.project(project_id)
        except BackendError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        req_path = record.root / "requirements.md"
        source_root = record.root / "source" if (record.root / "source").exists() else record.root
        if not req_path.exists():
            raise HTTPException(status_code=400, detail="Project does not have requirements.md uploaded yet")

        req_engine = RequirementIntelligenceEngine()
        req_res = req_engine.analyze(req_path, project_root=source_root, run_id=f"te-{project_id[:8]}")
        code_engine = CodeIntelligenceEngine(store=app.state.evidence_store)
        code_res = code_engine.analyze(source_root, req_path, run_id=f"te-code-{project_id[:8]}")

        adv_engine = AdversarialTestingEngine(store=app.state.evidence_store)
        adv_res = adv_engine.run(
            source_root,
            req_res.requirements,
            contracts=req_res.behavior_contracts,
            traceability=code_res.traceability,
            symbols=code_res.symbols,
            run_id=f"te-mut-{project_id[:8]}"
        )

        eng_engine = AutonomousTestEngineeringEngine(store=app.state.evidence_store)
        res = eng_engine.run(
            source_root,
            req_res.requirements,
            contracts=req_res.behavior_contracts,
            mutation_run=adv_res.run,
            mutants=adv_res.mutants,
            run_id=f"te-eng-{project_id[:8]}"
        )
        return {
            "status": "ok",
            "run_id": res.run.run_id,
            "run_status": res.run.status,
            "gaps_count": len(res.gaps),
            "gaps": [g.to_dict() for g in res.gaps],
            "candidates_count": len(res.candidates),
            "candidates": [c.to_dict() for c in res.candidates],
            "validations_count": len(res.validations),
            "validations": [v.to_dict() for v in res.validations],
            "evidence_count": len(res.evidence),
        }

    @app.get("/api/v2/projects/{project_id}/evidence")
    def get_project_evidence(project_id: str) -> dict:
        records = app.state.evidence_store.list_lifecycle_records()
        findings = app.state.evidence_store.list_findings()
        return {
            "status": "ok",
            "project_id": project_id,
            "evidence": [r.to_dict() for r in records],
            "findings": [f.to_dict() for f in findings],
            "counts": {"evidence": len(records), "findings": len(findings)}
        }

    # Initialize default demo project if empty
    import shutil
    with app.state.store.lock:
        if not app.state.store.projects:
            demo_record = app.state.store.create_project("RefundFlow Payment Core", {"description": "Standard RefundFlow core with 10 formal requirements and Python AST symbols"})
            ws_req = Path(__file__).resolve().parent.parent / "requirements.md"
            if ws_req.exists():
                (demo_record.root / "requirements.md").write_bytes(ws_req.read_bytes())
            ws_demo = Path(__file__).resolve().parent.parent / "demo"
            if ws_demo.exists():
                shutil.copytree(ws_demo, demo_record.root / "source" / "demo", dirs_exist_ok=True)
            ws_tests = Path(__file__).resolve().parent.parent / "tests"
            if ws_tests.exists():
                shutil.copytree(ws_tests, demo_record.root / "source" / "tests", dirs_exist_ok=True)

    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
    if frontend_dir.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        def _serve_file(filename: str):
            p = frontend_dir / filename
            if p.exists():
                return HTMLResponse(p.read_text(encoding="utf-8"))
            return HTMLResponse(f"<h1>SpecGuard View {filename} not found</h1>", status_code=404)

        @app.get("/")
        @app.get("/requirements")
        def serve_requirements():
            return _serve_file("index.html")

        @app.get("/overview")
        def serve_overview():
            return _serve_file("assurance_overview.html")

        @app.get("/code-intelligence")
        def serve_code_intelligence():
            return _serve_file("code_intelligence.html")

        @app.get("/adversarial-testing")
        def serve_adversarial_testing():
            return _serve_file("adversarial_testing.html")

        @app.get("/autonomous-test-engineering")
        def serve_autonomous_test_engineering():
            return _serve_file("autonomous_test_engineering.html")

        @app.get("/continuous-assurance")
        def serve_continuous_assurance():
            return _serve_file("continuous_assurance.html")

    return app


app = create_app()
