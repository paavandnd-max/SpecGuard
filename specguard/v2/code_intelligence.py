from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..adapters import adapter_for, detect_project
from .evidence_store import EvidenceStore, InMemoryEvidenceStore
from .models import (
    CodeSymbol,
    ComplianceStatus,
    Evidence,
    EvidenceStatus,
    Finding,
    ReproducibilityMetadata,
    RequirementV2,
    TestEffectiveness,
    TraceabilityLink,
    VerificationMode,
)
from .requirement_intelligence import RequirementIntelligenceEngine


@dataclass
class _MutableSymbol:
    symbol_id: str
    artifact_id: str
    language: str
    kind: str
    qualified_name: str
    span: dict[str, Any]
    parent_id: str | None = None
    raw_calls: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    dependency_ids: list[str] = field(default_factory=list)
    definitions: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def freeze(self, resolved_calls: tuple[str, ...] = ()) -> CodeSymbol:
        return CodeSymbol(
            symbol_id=self.symbol_id,
            artifact_id=self.artifact_id,
            language=self.language,
            kind=self.kind,
            qualified_name=self.qualified_name,
            span=self.span,
            parent_id=self.parent_id,
            calls=resolved_calls,
            imports=tuple(sorted(set(self.imports))),
            dependency_ids=tuple(sorted(set(self.dependency_ids))),
            metadata={**self.metadata, "definitions": sorted(self.definitions), "uses": sorted(self.uses), "raw_calls": list(self.raw_calls)},
        )


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, artifact_id: str, run_id: str, evidence_factory):
        self.path = path
        self.artifact_id = artifact_id
        self.run_id = run_id
        self.evidence_factory = evidence_factory
        self.symbols: list[_MutableSymbol] = []
        self.stack: list[_MutableSymbol] = []
        self.evidence: list[Evidence] = []
        self._qualified_stack: list[str] = []
        module_name = path.stem
        module = self._add_symbol("module", module_name, None, 1, 1, 1, 1)
        self.stack.append(module)
        self._qualified_stack.append(module_name)

    @property
    def current(self) -> _MutableSymbol:
        return self.stack[-1]

    def _add_symbol(self, kind: str, name: str, parent: _MutableSymbol | None, start: int, end: int, col: int, end_col: int) -> _MutableSymbol:
        qualified = f"{parent.qualified_name}.{name}" if parent else name
        symbol_id = "symbol-" + hashlib.sha256(f"{self.artifact_id}:{kind}:{qualified}:{start}".encode()).hexdigest()[:20]
        symbol = _MutableSymbol(symbol_id, self.artifact_id, "python", kind, qualified, {"path": str(self.path), "start_line": start, "end_line": end, "start_col": col, "end_col": end_col}, parent.symbol_id if parent else None)
        self.symbols.append(symbol)
        return symbol

    def _record(self, kind: str, claim: str, details: dict[str, Any], requirement_id: str | None = None) -> None:
        self.evidence.append(self.evidence_factory(kind, claim, details, requirement_id, self.artifact_id))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        symbol = self._add_symbol("method" if self.current.kind == "class" else "function", node.name, self.current, node.lineno, getattr(node, "end_lineno", node.lineno), node.col_offset, getattr(node, "end_col_offset", node.col_offset))
        arguments = [argument.arg for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
        symbol.metadata["arguments"] = arguments
        if node.returns:
            symbol.metadata["return_annotation"] = ast.unparse(node.returns)
        self.stack.append(symbol)
        self._qualified_stack.append(symbol.qualified_name)
        self.generic_visit(node)
        self._qualified_stack.pop()
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        symbol = self._add_symbol("class", node.name, self.current, node.lineno, getattr(node, "end_lineno", node.lineno), node.col_offset, getattr(node, "end_col_offset", node.col_offset))
        symbol.metadata["bases"] = [ast.unparse(base) for base in node.bases]
        self.stack.append(symbol)
        self._qualified_stack.append(symbol.qualified_name)
        self.generic_visit(node)
        self._qualified_stack.pop()
        self.stack.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            imported = alias.name
            self.current.imports.append(imported)
            self.current.dependency_ids.append("dependency-" + hashlib.sha256(imported.encode()).hexdigest()[:20])
            self._record("dependency_observation", "Python import observed", {"module": imported, "line": node.lineno, "kind": "import"})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        imported = "." * node.level + (node.module or "")
        names = [alias.name for alias in node.names]
        label = f"{imported}:{','.join(names)}"
        self.current.imports.append(label)
        self.current.dependency_ids.append("dependency-" + hashlib.sha256(label.encode()).hexdigest()[:20])
        self._record("dependency_observation", "Python from-import observed", {"module": imported, "names": names, "line": node.lineno, "kind": "from_import"})

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._call_name(node.func)
        if callee:
            self.current.raw_calls.append(callee)
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            current: ast.AST | None = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.current.definitions.add(node.id)
        elif isinstance(node.ctx, ast.Load):
            self.current.uses.add(node.id)

    def visit_If(self, node: ast.If) -> None:
        condition = ast.unparse(node.test)
        self._record("control_flow_fact", "Conditional branch observed", {"construct": "if", "condition": condition, "line": node.lineno, "symbol_id": self.current.symbol_id})
        if any(isinstance(child, ast.Raise) for child in ast.walk(ast.Module(body=node.body, type_ignores=[]))):
            self._record("input_validation_fact", "Input-related branch raises an exception", {"condition": condition, "line": node.lineno, "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._record("control_flow_fact", "For loop observed", {"construct": "for", "line": node.lineno, "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._record("control_flow_fact", "While loop observed", {"construct": "while", "condition": ast.unparse(node.test), "line": node.lineno, "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._record("exception_handling_fact", "Try/except handling observed", {"construct": "try", "line": node.lineno, "handlers": [ast.unparse(handler.type) if handler.type else "bare" for handler in node.handlers], "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        self._record("exception_handling_fact", "Explicit raise observed", {"construct": "raise", "line": node.lineno, "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self._record("data_flow_fact", "Return value observed", {"construct": "return", "line": node.lineno, "value": ast.unparse(node.value) if node.value else None, "symbol_id": self.current.symbol_id})
        self.generic_visit(node)

    def finish(self) -> tuple[list[_MutableSymbol], list[Evidence]]:
        for symbol in self.symbols:
            if symbol.definitions or symbol.uses:
                self._record("data_flow_fact", "Definitions and uses observed", {"symbol_id": symbol.symbol_id, "definitions": sorted(symbol.definitions), "uses": sorted(symbol.uses)})
        return self.symbols, self.evidence


@dataclass(frozen=True)
class CodeIntelligenceResult:
    language: str
    framework: str | None
    status: str
    symbols: tuple[CodeSymbol, ...]
    evidence: tuple[Evidence, ...]
    traceability: tuple[TraceabilityLink, ...]
    findings: tuple[Finding, ...] = ()
    unsupported_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "framework": self.framework,
            "status": self.status,
            "symbols": [item.to_dict() for item in self.symbols],
            "evidence": [item.to_dict() for item in self.evidence],
            "traceability": [item.to_dict() for item in self.traceability],
            "findings": [item.to_dict() for item in self.findings],
            "unsupported_reasons": list(self.unsupported_reasons),
        }


class CodeIntelligenceEngine:
    """Phase 2 static code intelligence with explicit bounded support."""

    version = "python-ast-v2-phase2"

    def __init__(self, store: EvidenceStore | None = None):
        self.store = store or InMemoryEvidenceStore()

    @staticmethod
    def _hash_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def analyze(self, project_root: str | Path, requirements_path: str | Path | None = None, run_id: str = "code-intelligence") -> CodeIntelligenceResult:
        root = Path(project_root).resolve()
        detection = detect_project(root)
        adapter = adapter_for(detection.language)
        if adapter is None:
            evidence = self._unsupported_evidence(run_id, detection.language, "No registered adapter for detected language")
            return CodeIntelligenceResult(detection.language, detection.framework, "unsupported", (), (evidence,), (), unsupported_reasons=("No registered adapter",))
        if detection.language != "python":
            evidence = self._unsupported_evidence(run_id, detection.language, "Static symbol extraction is implemented only for Python in Phase 2")
            return CodeIntelligenceResult(detection.language, detection.framework, "unsupported", (), (evidence,), (), unsupported_reasons=("Python AST analyzer is the only Phase 2 implementation",))

        source_files = adapter.source_files(root)
        if not source_files:
            evidence = self._unsupported_evidence(run_id, detection.language, "No source files were discovered")
            return CodeIntelligenceResult(detection.language, detection.framework, "inconclusive", (), (evidence,), (), unsupported_reasons=("No source files",))
        input_hashes = {str(path.relative_to(root)): self._hash_file(path) for path in source_files}
        evidence: list[Evidence] = []
        mutable_symbols: list[_MutableSymbol] = []
        parse_failures: list[str] = []
        for path in source_files:
            artifact_id = "artifact-" + self._hash_file(path)[:20]
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError) as exc:
                parse_failures.append(str(path))
                evidence.append(self._make_evidence(run_id, "syntax_analysis", "Python source could not be parsed", {"path": str(path), "error": str(exc)}, None, input_hashes))
                continue
            visitor = _PythonVisitor(path, artifact_id, run_id, lambda kind, claim, details, req, artifact: self._make_evidence(run_id, kind, claim, details, req, input_hashes, artifact))
            visitor.visit(tree)
            symbols, facts = visitor.finish()
            mutable_symbols.extend(symbols)
            evidence.extend(facts)
            evidence.append(self._make_evidence(run_id, "module_inventory", "Python module parsed", {"path": str(path), "symbol_count": len(symbols)}, None, input_hashes, artifact_id))

        symbol_names: dict[str, str] = {}
        for symbol in mutable_symbols:
            symbol_names.setdefault(symbol.qualified_name.rsplit(".", 1)[-1], symbol.symbol_id)
            symbol_names[symbol.qualified_name] = symbol.symbol_id
        frozen_symbols: list[CodeSymbol] = []
        for symbol in mutable_symbols:
            resolved: list[str] = []
            unresolved: list[str] = []
            for raw_call in symbol.raw_calls:
                target = symbol_names.get(raw_call) or symbol_names.get(raw_call.rsplit(".", 1)[-1])
                if target and target != symbol.symbol_id:
                    resolved.append(target)
                    evidence.append(self._make_evidence(run_id, "call_relationship", "Statically resolvable call relationship observed", {"caller": symbol.symbol_id, "callee": target, "expression": raw_call}, None, input_hashes, symbol.artifact_id))
                else:
                    unresolved.append(raw_call)
            frozen = symbol.freeze(tuple(sorted(set(resolved))))
            if unresolved:
                frozen = replace(frozen, metadata={**frozen.metadata, "unresolved_calls": sorted(set(unresolved))})
            frozen_symbols.append(frozen)

        traceability: list[TraceabilityLink] = []
        findings: list[Finding] = []
        if requirements_path is not None:
            intelligence = RequirementIntelligenceEngine().analyze(requirements_path, root, run_id)
            evidence.extend(intelligence.evidence)
            traceability.extend(intelligence.traceability)
            for link in intelligence.traceability:
                if link.target_kind != "source":
                    continue
                path_text = link.target_id.split(":", 1)[1].rsplit(":", 1)[0]
                matching = [symbol for symbol in frozen_symbols if symbol.span.get("path") == path_text]
                target = next((symbol for symbol in matching if symbol.kind in {"function", "method", "class"}), matching[0] if matching else None)
                if target:
                    mapping_evidence = self._make_evidence(run_id, "requirement_to_code_traceability", "Requirement source marker mapped to a parsed symbol", {"requirement_id": link.requirement_id, "symbol_id": target.symbol_id, "origin": link.origin}, link.requirement_id, input_hashes, target.artifact_id)
                    evidence.append(mapping_evidence)
                    traceability.append(TraceabilityLink(self._stable("link", link.requirement_id, target.symbol_id), link.requirement_id, target.symbol_id, "code_symbol", "implemented_by", "explicit_marker", 1.0, (mapping_evidence.evidence_id,)))
        for item in evidence:
            self.store.save_evidence(item)
        status = "inconclusive" if parse_failures and not frozen_symbols else "observed"
        return CodeIntelligenceResult(detection.language, detection.framework, status, tuple(frozen_symbols), tuple(evidence), tuple(traceability), tuple(findings), tuple(f"Could not parse: {path}" for path in parse_failures))

    def _unsupported_evidence(self, run_id: str, language: str, claim: str) -> Evidence:
        return self._make_evidence(run_id, "unsupported_analysis", claim, {"language": language}, None, {})

    @staticmethod
    def _stable(prefix: str, *parts: str) -> str:
        return f"{prefix}-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:20]

    def _make_evidence(self, run_id: str, kind: str, claim: str, details: dict[str, Any], requirement_id: str | None, input_hashes: dict[str, str], artifact_id: str | None = None) -> Evidence:
        evidence_id = self._stable("evidence", run_id, kind, requirement_id or "project", jsonish(details))
        return Evidence(
            evidence_id=evidence_id,
            run_id=run_id,
            kind=kind,
            status=EvidenceStatus.INCONCLUSIVE if kind in {"unsupported_analysis", "syntax_analysis"} else EvidenceStatus.OBSERVED,
            claim=claim,
            requirement_id=requirement_id,
            artifact_ids=(artifact_id,) if artifact_id else (),
            input_hashes=input_hashes,
            reproducibility=ReproducibilityMetadata(input_hashes=input_hashes, adapter_id="python-ast", adapter_version=self.version, execution_policy_id="static-no-execution"),
            details=details,
        )


def jsonish(value: Any) -> str:
    if isinstance(value, dict):
        return "{" + ",".join(f"{key}:{jsonish(value[key])}" for key in sorted(value)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jsonish(item) for item in value) + "]"
    return str(value)
