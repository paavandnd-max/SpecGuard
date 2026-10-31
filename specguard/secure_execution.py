from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class IsolationUnavailable(RuntimeError):
    """Raised when an untrusted project cannot be run in a real sandbox."""


@dataclass(frozen=True)
class ExecutionPolicy:
    timeout_seconds: int = 60
    memory_mb: int = 512
    cpu_count: float = 1.0
    pids_limit: int = 128
    network: str = "none"
    docker_image: str | None = None


class DockerSandbox:
    """Docker execution boundary with network, resource, and filesystem limits."""

    def __init__(self, policy: ExecutionPolicy | None = None):
        self.policy = policy or ExecutionPolicy()

    def available(self) -> bool:
        return bool(shutil.which("docker") and self.policy.docker_image)

    def explain_unavailable(self) -> str:
        if not shutil.which("docker"):
            return "Docker executable is unavailable"
        if not self.policy.docker_image:
            return "No approved execution image is configured"
        return "Sandbox unavailable"

    def run(self, project: str | Path, command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        if not self.available():
            raise IsolationUnavailable(self.explain_unavailable())
        project = Path(project).resolve()
        docker_command = [
            "docker", "run", "--rm", "--network", self.policy.network,
            "--read-only", "--cpus", str(self.policy.cpu_count),
            "--memory", f"{self.policy.memory_mb}m", "--pids-limit", str(self.policy.pids_limit),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{project}:/workspace:ro", "-w", "/workspace",
            self.policy.docker_image, *command,
        ]
        try:
            return subprocess.run(docker_command, capture_output=True, text=True, timeout=self.policy.timeout_seconds, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise IsolationUnavailable(f"Sandbox timed out after {self.policy.timeout_seconds}s") from exc


def require_isolation(policy: ExecutionPolicy | None = None) -> DockerSandbox:
    sandbox = DockerSandbox(policy)
    if not sandbox.available():
        raise IsolationUnavailable(sandbox.explain_unavailable())
    return sandbox
