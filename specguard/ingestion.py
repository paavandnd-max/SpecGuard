from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath
from typing import Iterable


class IngestionError(ValueError):
    """A user-controlled project could not be safely ingested."""


@dataclass(frozen=True)
class IngestionLimits:
    max_files: int = 2_000
    max_file_size: int = 5 * 1024 * 1024
    max_total_size: int = 50 * 1024 * 1024


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    category: str


@dataclass
class ProjectManifest:
    root: str
    files: list[FileRecord]
    unsupported_files: list[str]
    metadata: dict

    def to_dict(self) -> dict:
        return asdict(self)


SUPPORTED_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".md", ".json", ".toml", ".yaml", ".yml", ".ini",
    ".cfg", ".txt", ".xml", ".gradle", ".properties", ".lock",
}
IGNORED_NAMES = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}


def _category(path: Path) -> str:
    if "test" in path.name.lower() or any(part.lower() in {"tests", "test", "__tests__"} for part in path.parts):
        return "tests"
    if path.suffix.lower() in {".md", ".txt"} or path.name.lower().startswith("readme"):
        return "documentation"
    if path.suffix.lower() in {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java"}:
        return "source"
    return "configuration"


def _validate_relative_zip_name(name: str) -> PurePosixPath:
    if "\\" in name:
        name = name.replace("\\", "/")
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise IngestionError(f"Unsafe archive path: {name}")
    if len(str(candidate)) > 240:
        raise IngestionError(f"Archive path is too long: {name}")
    return candidate


def _record_files(root: Path, limits: IngestionLimits) -> ProjectManifest:
    records: list[FileRecord] = []
    unsupported: list[str] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in IGNORED_NAMES for part in path.relative_to(root).parts):
            continue
        relative = path.relative_to(root)
        size = path.stat().st_size
        if size > limits.max_file_size:
            raise IngestionError(f"File exceeds size limit: {relative}")
        total += size
        if total > limits.max_total_size:
            raise IngestionError("Project exceeds total size limit")
        if len(records) >= limits.max_files:
            raise IngestionError("Project exceeds file-count limit")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        suffix = path.suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS and path.name.lower() not in {"makefile", "dockerfile", "package.json", "package-lock.json", "poetry.lock", "pom.xml", "build.gradle"}:
            unsupported.append(str(relative))
        records.append(FileRecord(str(relative), size, digest, _category(relative)))
    metadata = {
        "file_count": len(records),
        "total_size": total,
        "has_requirements": (root / "requirements.md").exists(),
        "has_tests": any(item.category == "tests" for item in records),
    }
    return ProjectManifest(str(root), records, unsupported, metadata)


def validate_project_directory(root: str | Path, limits: IngestionLimits | None = None) -> ProjectManifest:
    root = Path(root).resolve()
    if not root.is_dir():
        raise IngestionError(f"Project directory does not exist: {root}")
    return _record_files(root, limits or IngestionLimits())


def extract_zip_safely(archive: str | Path, destination: str | Path, limits: IngestionLimits | None = None) -> ProjectManifest:
    archive = Path(archive)
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    limits = limits or IngestionLimits()
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = [info for info in bundle.infolist() if not info.is_dir()]
            if len(infos) > limits.max_files:
                raise IngestionError("Archive exceeds file-count limit")
            total = 0
            for info in infos:
                relative = _validate_relative_zip_name(info.filename)
                if info.is_dir() or info.filename.endswith("/"):
                    continue
                if info.external_attr >> 16 & 0o170000 == 0o120000:
                    raise IngestionError(f"Symbolic links are not accepted: {info.filename}")
                if info.file_size > limits.max_file_size:
                    raise IngestionError(f"Archive member exceeds size limit: {info.filename}")
                total += info.file_size
                if total > limits.max_total_size:
                    raise IngestionError("Archive exceeds total size limit")
                target = (destination / Path(*relative.parts)).resolve()
                if destination not in target.parents:
                    raise IngestionError(f"Archive path escapes destination: {info.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, target.open("wb") as out:
                    shutil.copyfileobj(source, out, length=1024 * 1024)
    except zipfile.BadZipFile as exc:
        raise IngestionError("Uploaded file is not a valid ZIP archive") from exc
    return validate_project_directory(destination, limits)


def ingest_archive_bytes(data: bytes, destination: str | Path, filename: str = "project.zip", limits: IngestionLimits | None = None) -> ProjectManifest:
    if isinstance(filename, IngestionLimits) and limits is None:
        limits = filename
        filename = "project.zip"
    limits = limits or IngestionLimits()
    if len(data) > limits.max_total_size:
        raise IngestionError("Uploaded archive exceeds total size limit")
    destination = Path(destination)
    with tempfile.NamedTemporaryFile(prefix="specguard-upload-", suffix=".zip", delete=False) as handle:
        handle.write(data)
        temp_name = handle.name
    try:
        return extract_zip_safely(temp_name, destination, limits)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_manifest(manifest: ProjectManifest, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    return path
