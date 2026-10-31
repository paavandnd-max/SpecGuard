from __future__ import annotations

import io
import os
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from specguard.adapters import JavaAdapter, NodeAdapter, TypeScriptAdapter, detect_project
from specguard.api import create_app
from specguard.ingestion import IngestionError, IngestionLimits, ingest_archive_bytes
from specguard.intelligence import build_traceability
from specguard.requirements import parse_requirements
from specguard.secure_execution import DockerSandbox, ExecutionPolicy, IsolationUnavailable
from specguard.backend import BackendStore


ROOT = Path(__file__).parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("SPECGUARD_CHILD_RUN") == "1", reason="backend integration tests are not part of child project runs")


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, data in entries.items():
            bundle.writestr(name, data)
    return buffer.getvalue()


def test_zip_traversal_is_rejected(tmp_path):
    with pytest.raises(IngestionError, match="Unsafe archive path"):
        ingest_archive_bytes(zip_bytes({"../escape.py": b"print('bad')"}), tmp_path / "project")


def test_zip_limits_and_manifest(tmp_path):
    data = zip_bytes({"src/main.py": b"print('ok')", "tests/test_main.py": b"def test_ok(): pass"})
    manifest = ingest_archive_bytes(data, tmp_path / "project", IngestionLimits(max_files=3))
    assert manifest.metadata["file_count"] == 2
    assert manifest.metadata["has_tests"]
    with pytest.raises(IngestionError):
        ingest_archive_bytes(data, tmp_path / "too-small", IngestionLimits(max_total_size=5))


def test_language_detection_contracts(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"jest"},"devDependencies":{"jest":"1"}}')
    (tmp_path / "sample.js").write_text("module.exports = 1")
    assert isinstance(NodeAdapter().detect(tmp_path), object)
    assert detect_project(tmp_path).language == "javascript"
    (tmp_path / "sample.ts").write_text("const x: number = 1")
    assert TypeScriptAdapter().detect(tmp_path).language == "typescript"
    java_root = tmp_path / "java"
    java_root.mkdir()
    (java_root / "App.java").write_text("class App {}")
    assert JavaAdapter().detect(java_root).language == "java"


def test_traceability_graph_maps_source_and_tests():
    graph = build_traceability(ROOT / "requirements.md", ROOT)
    assert len(graph.requirements) == 10
    assert all(item.source_locations for item in graph.requirements)
    assert any(edge["type"] == "verified_by" for edge in graph.edges)


def test_requirement_ids_are_normalized(tmp_path):
    path = tmp_path / "requirements.md"
    path.write_text("- [ ] req-7: Must accept a valid value\n- [ ] Must reject an invalid value\n")
    parsed = parse_requirements(path)
    assert [item.id for item in parsed] == ["REQ-7", "REQ-002"]


def test_secure_boundary_fails_closed_without_image():
    sandbox = DockerSandbox(ExecutionPolicy(docker_image=None))
    assert not sandbox.available()
    with pytest.raises(IsolationUnavailable):
        from specguard.secure_execution import require_isolation
        require_isolation(ExecutionPolicy(docker_image=None))


def test_api_ingestion_health_and_fail_closed_analysis(tmp_path):
    store = BackendStore(tmp_path / "store")
    client = TestClient(create_app(store))
    assert client.get("/api/v1/health").status_code == 200
    project = client.post("/api/v1/projects", json={"name": "api-demo"})
    assert project.status_code == 201
    project_id = project.json()["id"]
    requirements = (ROOT / "requirements.md").read_bytes()
    assert client.post(f"/api/v1/projects/{project_id}/requirements", files={"file": ("requirements.md", requirements, "text/markdown")}).status_code == 200
    source = zip_bytes({"refund_flow.py": (ROOT / "demo" / "refund_flow.py").read_bytes()})
    source_response = client.post(f"/api/v1/projects/{project_id}/source", files={"file": ("source.zip", source, "application/zip")})
    assert source_response.status_code == 200
    analysis = client.post("/api/v1/analysis", json={"project_id": project_id})
    assert analysis.status_code == 202
    analysis_id = analysis.json()["id"]
    for _ in range(20):
        status = client.get(f"/api/v1/analysis/{analysis_id}").json()
        if status["status"] in {"failed", "completed"}:
            break
        time.sleep(0.01)
    assert status["status"] == "failed"
    assert "Docker" in status["error"] or "image" in status["error"]
    report = client.get(f"/api/v1/analysis/{analysis_id}/report?format=json")
    assert report.status_code == 200
