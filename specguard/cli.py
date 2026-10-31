from __future__ import annotations

import argparse
import time
from pathlib import Path

from .adapters import detect_project
from .engine import SpecGuard
from .intelligence import build_traceability
from .providers import DeterministicOfflineProvider
from .reporting import write_html, write_json
from .requirements import parse_requirements


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SpecGuard mutation analysis")
    parser.add_argument("project", nargs="?", default=".")
    parser.add_argument("--requirements", default="requirements.md")
    parser.add_argument("--json", default="outputs/specguard-report.json")
    parser.add_argument("--html", default="outputs/specguard-report.html")
    args = parser.parse_args()
    project = Path(args.project).resolve()
    requirements_path = project / args.requirements
    started = time.perf_counter()
    report = SpecGuard(project, parse_requirements(requirements_path), DeterministicOfflineProvider()).analyze()
    report.metadata = {
        "project": str(project),
        "detection": detect_project(project).__dict__,
        "traceability": build_traceability(requirements_path, project).to_dict(),
        "duration_seconds": round(time.perf_counter() - started, 3),
    }
    json_path = project / args.json
    html_path = project / args.html
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, json_path)
    write_html(report, html_path)
    print(report.counts())
    return 0 if report.baseline_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
