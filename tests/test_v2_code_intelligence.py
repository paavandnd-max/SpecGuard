from __future__ import annotations

from pathlib import Path

from specguard.v2.code_intelligence import CodeIntelligenceEngine
from specguard.v2.evidence_store import InMemoryEvidenceStore
from specguard.v2.models import EvidenceStatus


def write_python_project(root: Path) -> Path:
    (root / "app.py").write_text(
        """
def validate_amount(amount):
    if amount <= 0:
        raise ValueError('amount must be positive')
    return amount

class RefundService:
    def run(self, amount):
        try:
            return validate_amount(amount)
        except ValueError:
            return None
"""
    )
    return root


def test_python_symbols_calls_control_flow_data_flow_and_exceptions(tmp_path):
    root = write_python_project(tmp_path)
    store = InMemoryEvidenceStore()
    result = CodeIntelligenceEngine(store).analyze(root, run_id="code-run")
    assert result.status == "observed"
    names = {symbol.qualified_name for symbol in result.symbols}
    assert {"app", "app.validate_amount", "app.RefundService", "app.RefundService.run"} <= names
    kinds = {item.kind for item in result.evidence}
    assert {"module_inventory", "control_flow_fact", "data_flow_fact", "exception_handling_fact", "input_validation_fact", "call_relationship"} <= kinds
    run_evidence = store.list_evidence(run_id="code-run")
    assert len(run_evidence) == len(result.evidence)
    call_symbol = next(symbol for symbol in result.symbols if symbol.qualified_name == "app.RefundService.run")
    validate_symbol = next(symbol for symbol in result.symbols if symbol.qualified_name == "app.validate_amount")
    assert validate_symbol.symbol_id in call_symbol.calls


def test_requirement_to_code_traceability_is_evidence_backed(tmp_path):
    root = write_python_project(tmp_path)
    requirements = tmp_path / "requirements.md"
    requirements.write_text("- [ ] REQ-001: Amount must be positive.\n")
    app = root / "app.py"
    app.write_text("# specguard: REQ-001\n" + app.read_text())
    result = CodeIntelligenceEngine().analyze(root, requirements, run_id="trace-run")
    links = [item for item in result.traceability if item.target_kind == "code_symbol"]
    assert links
    assert links[0].origin == "explicit_marker"
    evidence_ids = set(links[0].evidence_ids)
    assert evidence_ids <= {item.evidence_id for item in result.evidence}


def test_non_python_is_explicitly_unsupported(tmp_path):
    (tmp_path / "index.js").write_text("module.exports = 1")
    result = CodeIntelligenceEngine().analyze(tmp_path, run_id="js-run")
    assert result.status == "unsupported"
    assert result.symbols == ()
    assert result.evidence[0].status == EvidenceStatus.INCONCLUSIVE
    assert "Python AST" in result.unsupported_reasons[0]


def test_python_parse_failure_is_inconclusive(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    result = CodeIntelligenceEngine().analyze(tmp_path, run_id="broken-run")
    assert result.status == "inconclusive"
    assert result.evidence[0].status == EvidenceStatus.INCONCLUSIVE
    assert result.unsupported_reasons
