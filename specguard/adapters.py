from __future__ import annotations

import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AdapterDetection:
    language: str
    framework: str | None
    package_manager: str | None
    build_system: str | None
    confidence: float
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    available: bool
    returncode: int | None = None
    output: str = ""


class LanguageAdapter(ABC):
    language: str

    @abstractmethod
    def detect(self, root: Path) -> AdapterDetection | None: ...

    @abstractmethod
    def source_files(self, root: Path) -> list[Path]: ...

    @abstractmethod
    def test_files(self, root: Path) -> list[Path]: ...

    @abstractmethod
    def test_command(self, root: Path) -> tuple[str, ...] | None: ...

    def build_command(self, root: Path) -> tuple[str, ...] | None:
        return None

    def validate(self, root: Path) -> CommandResult:
        return CommandResult((), True, 0, "No adapter-specific validation configured")

    def run_tests(self, root: Path, timeout: int = 30) -> CommandResult:
        command = self.test_command(root)
        if not command:
            return CommandResult((), False, None, "No test command detected")
        if shutil.which(command[0]) is None and command[0] != sys.executable:
            return CommandResult(command, False, None, f"Executable not found: {command[0]}")
        try:
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=timeout, shell=False)
            return CommandResult(command, True, completed.returncode, completed.stdout + completed.stderr)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(command, True, -1, str(exc))


class PythonAdapter(LanguageAdapter):
    language = "python"

    def detect(self, root: Path) -> AdapterDetection | None:
        files = list(root.rglob("*.py"))
        if not files:
            return None
        framework = "pytest" if any("pytest" in p.read_text(encoding="utf-8", errors="ignore") for p in root.rglob("*.py")) or (root / "pytest.ini").exists() or (root / "pyproject.toml").exists() else "unittest"
        manager = "poetry" if (root / "pyproject.toml").exists() and (root / "poetry.lock").exists() else "pip" if (root / "requirements.txt").exists() else None
        return AdapterDetection(self.language, framework, manager, None, 0.98, tuple(str(p.relative_to(root)) for p in files[:3]))

    def source_files(self, root: Path) -> list[Path]:
        return sorted(p for p in root.rglob("*.py") if "test" not in p.name.lower() and "tests" not in p.parts)

    def test_files(self, root: Path) -> list[Path]:
        return sorted(p for p in root.rglob("*.py") if "test" in p.name.lower() or "tests" in p.parts)

    def test_command(self, root: Path) -> tuple[str, ...] | None:
        if self.detect(root) and self.detect(root).framework == "pytest":
            return (sys.executable, "-m", "pytest", "-q")
        return (sys.executable, "-m", "unittest", "discover")

    def validate(self, root: Path) -> CommandResult:
        import py_compile
        try:
            for path in self.source_files(root) + self.test_files(root):
                py_compile.compile(str(path), doraise=True)
            return CommandResult((sys.executable, "-m", "py_compile"), True, 0, "Python syntax valid")
        except py_compile.PyCompileError as exc:
            return CommandResult((sys.executable, "-m", "py_compile"), True, 1, str(exc))


class NodeAdapter(LanguageAdapter):
    extensions: tuple[str, ...] = (".js", ".jsx", ".mjs", ".cjs")
    language = "javascript"

    def detect(self, root: Path) -> AdapterDetection | None:
        files = [p for ext in self.extensions for p in root.rglob(f"*{ext}")]
        if not files:
            return None
        package = root / "package.json"
        framework = None
        package_manager = "npm" if package.exists() or (root / "package-lock.json").exists() else None
        if package.exists():
            text = package.read_text(encoding="utf-8", errors="ignore")
            framework = "jest" if "jest" in text else "vitest" if "vitest" in text else "mocha" if "mocha" in text else None
        return AdapterDetection(self.language, framework, package_manager, "npm" if package_manager else None, 0.9, tuple(str(p.relative_to(root)) for p in files[:3]))

    def source_files(self, root: Path) -> list[Path]:
        return sorted(p for ext in self.extensions for p in root.rglob(f"*{ext}"))

    def test_files(self, root: Path) -> list[Path]:
        return sorted(p for p in self.source_files(root) if "test" in p.name.lower() or "spec" in p.name.lower() or "__tests__" in p.parts)

    def test_command(self, root: Path) -> tuple[str, ...] | None:
        detection = self.detect(root)
        if not detection:
            return None
        return ("npm", "test", "--", "--runInBand")


class TypeScriptAdapter(NodeAdapter):
    language = "typescript"
    extensions = (".ts", ".tsx")

    def detect(self, root: Path) -> AdapterDetection | None:
        detection = super().detect(root)
        if detection:
            return AdapterDetection("typescript", detection.framework, detection.package_manager, detection.build_system, detection.confidence, detection.evidence)
        return None

    def validate(self, root: Path) -> CommandResult:
        command = ("tsc", "--noEmit")
        if shutil.which("tsc") is None:
            return CommandResult(command, False, None, "TypeScript compiler not installed")
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True, shell=False)
        return CommandResult(command, True, completed.returncode, completed.stdout + completed.stderr)


class JavaAdapter(LanguageAdapter):
    language = "java"

    def detect(self, root: Path) -> AdapterDetection | None:
        files = list(root.rglob("*.java"))
        if not files:
            return None
        build = "maven" if (root / "pom.xml").exists() else "gradle" if (root / "build.gradle").exists() or (root / "gradlew").exists() else None
        framework = "junit" if any("junit" in p.read_text(encoding="utf-8", errors="ignore").lower() for p in files[:20]) else None
        return AdapterDetection(self.language, framework, None, build, 0.9, tuple(str(p.relative_to(root)) for p in files[:3]))

    def source_files(self, root: Path) -> list[Path]:
        return sorted(root.rglob("*.java"))

    def test_files(self, root: Path) -> list[Path]:
        return sorted(p for p in self.source_files(root) if "test" in p.name.lower() or "test" in p.parts)

    def build_command(self, root: Path) -> tuple[str, ...] | None:
        return ("mvn", "test", "-q") if (root / "pom.xml").exists() else ("gradle", "test") if (root / "build.gradle").exists() else None

    def test_command(self, root: Path) -> tuple[str, ...] | None:
        return self.build_command(root)

    def validate(self, root: Path) -> CommandResult:
        command = ("javac", "-version")
        if shutil.which("javac") is None:
            return CommandResult(command, False, None, "Java compiler not installed")
        return CommandResult(command, True, 0, "Java compiler available")


ADAPTERS: tuple[LanguageAdapter, ...] = (PythonAdapter(), TypeScriptAdapter(), NodeAdapter(), JavaAdapter())


def detect_project(root: str | Path) -> AdapterDetection:
    root = Path(root).resolve()
    detections = [item for adapter in ADAPTERS if (item := adapter.detect(root)) is not None]
    if not detections:
        return AdapterDetection("unknown", None, None, None, 0.0, ())
    return max(detections, key=lambda item: item.confidence)


def adapter_for(language: str) -> LanguageAdapter | None:
    return next((adapter for adapter in ADAPTERS if adapter.language == language), None)
