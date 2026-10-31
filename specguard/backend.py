from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .adapters import AdapterDetection, adapter_for, detect_project
from .engine import SpecGuard
from .ingestion import IngestionError, IngestionLimits, ProjectManifest, extract_zip_safely, validate_project_directory
from .intelligence import TraceabilityGraph, build_traceability
from .models import AnalysisReport, Classification, RequirementResult
from .providers import BedrockMutationProvider, DeterministicOfflineProvider
from .reporting import report_dict, write_html, write_json
from .requirements import parse_requirements
from .secure_execution import DockerSandbox, ExecutionPolicy, IsolationUnavailable
from .sandbox import TestRun


class BackendError(ValueError):
    pass


@dataclass
class ProjectRecord:
    id: str
    root: Path
    created_at: float
    metadata: dict = field(default_factory=dict)
    manifest: ProjectManifest | None = None


@dataclass
class AnalysisRecord:
    id: str
    project_id: str
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    report: AnalysisReport | None = None
    error: str | None = None


class DockerTestRunner:
    def __init__(self, sandbox: DockerSandbox, command: tuple[str, ...], timeout: int = 60):
        self.sandbox = sandbox
        self.command = tuple("python" if item == sys.executable else item for item in command)
        self.timeout = timeout

    def run(self, workspace: str | Path) -> TestRun:
        try:
            completed = self.sandbox.run(workspace, self.command)
            return TestRun(completed.returncode, completed.stdout + completed.stderr)
        except IsolationUnavailable as exc:
            return TestRun(-1, str(exc), timed_out=False)


class BackendStore:
    """In-process project and job store; replace with a durable store for multi-worker deployments."""

    def __init__(self, root: str | Path | None = None, limits: IngestionLimits | None = None):
        self.root = Path(root or tempfile.mkdtemp(prefix="specguard-backend-"))
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or IngestionLimits()
        self.projects: dict[str, ProjectRecord] = {}
        self.analyses: dict[str, AnalysisRecord] = {}
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="specguard-analysis")

    def create_project(self, name: str, metadata: dict | None = None) -> ProjectRecord:
        project_id = uuid.uuid4().hex
        root = self.root / project_id
        root.mkdir()
        record = ProjectRecord(project_id, root, time.time(), {"name": name, **(metadata or {})})
        with self.lock:
            self.projects[project_id] = record
        return record

    def project(self, project_id: str) -> ProjectRecord:
        try:
            return self.projects[project_id]
        except KeyError as exc:
            raise BackendError("Project not found") from exc

    def analysis(self, analysis_id: str) -> AnalysisRecord:
        try:
            return self.analyses[analysis_id]
        except KeyError as exc:
            raise BackendError("Analysis not found") from exc

    def save_requirements(self, project_id: str, filename: str, data: bytes) -> Path:
        record = self.project(project_id)
        if len(data) > self.limits.max_file_size:
            raise IngestionError("Requirements file exceeds size limit")
        if not (filename.lower().endswith(".md") or filename.lower().endswith(".txt")):
            raise IngestionError("Requirements must be a Markdown (.md) or text (.txt) file")
        target = record.root / "requirements.md"
        target.write_bytes(data)
        parse_requirements(target)
        return target

    def save_source(self, project_id: str, filename: str, data: bytes) -> ProjectManifest:
        record = self.project(project_id)
        source_root = record.root / "source"
        if source_root.exists():
            shutil.rmtree(source_root)
        source_root.mkdir()
        if filename.lower().endswith(".zip"):
            archive = record.root / "upload.zip"
            archive.write_bytes(data)
            manifest = extract_zip_safely(archive, source_root, self.limits)
        else:
            if len(data) > self.limits.max_file_size:
                raise IngestionError("Source file exceeds size limit")
            safe_name = Path(filename).name
            target = source_root / safe_name
            target.write_bytes(data)
            manifest = validate_project_directory(source_root, self.limits)
        record.manifest = manifest
        return manifest

    def save_tests(self, project_id: str, filename: str, data: bytes) -> Path:
        record = self.project(project_id)
        test_root = record.root / "source" / "tests"
        test_root.mkdir(exist_ok=True)
        if len(data) > self.limits.max_file_size:
            raise IngestionError("Test file exceeds size limit")
        target = test_root / Path(filename).name
        target.write_bytes(data)
        return target

    def submit_analysis(self, project_id: str, provider_name: str = "offline", execution: str = "docker") -> AnalysisRecord:
        record = self.project(project_id)
        analysis = AnalysisRecord(uuid.uuid4().hex, project_id)
        with self.lock:
            self.analyses[analysis.id] = analysis
        self.executor.submit(self._run_analysis, analysis, record, provider_name, execution)
        return analysis

    def _run_analysis(self, analysis: AnalysisRecord, project: ProjectRecord, provider_name: str, execution: str) -> None:
        analysis.status = "running"
        analysis.started_at = time.time()
        try:
            source_root = project.root / "source"
            requirements_path = project.root / "requirements.md"
            if not source_root.exists() or not requirements_path.exists():
                raise BackendError("Requirements and source must be uploaded before analysis")
            detection = detect_project(source_root)
            adapter = adapter_for(detection.language)
            if adapter is None:
                raise BackendError(f"No adapter available for detected language: {detection.language}")
            requirements = parse_requirements(requirements_path)
            traceability = build_traceability(requirements_path, source_root)
            if execution != "docker":
                raise IsolationUnavailable("Untrusted project execution requires execution='docker'")
            policy = ExecutionPolicy(docker_image=os.environ.get("SPECGUARD_DOCKER_IMAGE"))
            sandbox = DockerSandbox(policy)
            if not sandbox.available():
                raise IsolationUnavailable(sandbox.explain_unavailable())
            provider = DeterministicOfflineProvider() if provider_name == "offline" else BedrockMutationProvider()
            runner = DockerTestRunner(sandbox, adapter.test_command(source_root) or ("python", "-m", "pytest", "-q"))
            report = SpecGuard(source_root, requirements, provider, runner).analyze()
            report.metadata = {"project": project.metadata, "detection": detection.__dict__, "traceability": traceability.to_dict()}
            analysis.report = report
            analysis.status = "completed"
        except Exception as exc:
            analysis.error = str(exc)
            analysis.status = "failed"
            fallback_requirements = []
            requirements_path = project.root / "requirements.md"
            if requirements_path.exists():
                try:
                    fallback_requirements = parse_requirements(requirements_path)
                except Exception:
                    fallback_requirements = []
            analysis.report = AnalysisReport(False, "", [RequirementResult(item, Classification.INCONCLUSIVE, reason=str(exc)) for item in fallback_requirements], str(project.root), {"error": str(exc)})
        finally:
            analysis.finished_at = time.time()

    def analysis_payload(self, analysis: AnalysisRecord) -> dict:
        payload = {"id": analysis.id, "project_id": analysis.project_id, "status": analysis.status, "created_at": analysis.created_at, "started_at": analysis.started_at, "finished_at": analysis.finished_at, "error": analysis.error}
        if analysis.report:
            payload["counts"] = analysis.report.counts()
            payload["baseline_passed"] = analysis.report.baseline_passed
        return payload
