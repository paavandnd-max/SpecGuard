from __future__ import annotations

import html
import json
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisReport


def report_dict(report: AnalysisReport) -> dict:
    data = asdict(report)
    for item in data["results"]:
        if item.get("source"):
            item["source"]["path"] = str(item["source"]["path"])
    data["counts"] = report.counts()
    return data


def write_json(report: AnalysisReport, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(report_dict(report), indent=2), encoding="utf-8")
    return path


def write_html(report: AnalysisReport, path: str | Path) -> Path:
    path = Path(path)
    rows = "".join(
        f"<tr><td>{html.escape(item.requirement.id)}</td><td>{html.escape(item.classification.value)}</td>"
        f"<td>{html.escape(item.description)}</td><td>{html.escape(item.reason)}</td></tr>"
        for item in report.results
    )
    metadata = html.escape(json.dumps(report.metadata, indent=2, default=str))
    document = f"""<!doctype html><html><head><meta charset='utf-8'><title>SpecGuard report</title>
<style>body{{font-family:system-ui;margin:2rem}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:.5rem}} th{{background:#f2f2f2}}</style>
</head><body><h1>SpecGuard report</h1><p>Baseline passed: {report.baseline_passed}</p>
<p>{html.escape(str(report.counts()))}</p><table><thead><tr><th>Requirement</th><th>Classification</th><th>Mutant</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Metadata</h2><pre>{metadata}</pre></body></html>"""
    path.write_text(document, encoding="utf-8")
    return path
