"""Small optional Streamlit dashboard for a JSON report."""

import json
from pathlib import Path


def render(report_path: str = "outputs/specguard-report.json") -> None:
    import streamlit as st

    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    st.title("SpecGuard")
    st.json(report.get("counts", {}))
    st.dataframe(report.get("results", []), use_container_width=True)


if __name__ == "__main__":
    render()
