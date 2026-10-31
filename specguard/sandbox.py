from __future__ import annotations

import os
import site
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TestRun:
    returncode: int
    output: str
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class IsolatedWorkspace:
    def __init__(self, source: str | Path):
        self.source = Path(source).resolve()
        self._temp: tempfile.TemporaryDirectory[str] | None = None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self._temp = tempfile.TemporaryDirectory(prefix="specguard-")
        self.path = Path(self._temp.name) / self.source.name
        shutil.copytree(
            self.source,
            self.path,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
        )
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._temp:
            self._temp.cleanup()
        self.path = None


class SafeTestRunner:
    def __init__(self, test_args: tuple[str, ...] = ("-m", "pytest", "tests", "-q"), timeout: int = 30):
        self.test_args = test_args
        self.timeout = timeout

    def run(self, workspace: str | Path) -> TestRun:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["SPECGUARD_CHILD_RUN"] = "1"
        # Keep the interpreter's installed test dependencies available. The
        # subprocess is still constrained by an isolated cwd, no shell, and a
        # timeout; callers can pass a separately sanitized environment in a
        # future runner implementation.
        environment["PYTHONPATH"] = site.getusersitepackages()
        try:
            completed = subprocess.run(
                [sys.executable, *self.test_args],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
            return TestRun(completed.returncode, completed.stdout + completed.stderr)
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return TestRun(-1, output, timed_out=True)
