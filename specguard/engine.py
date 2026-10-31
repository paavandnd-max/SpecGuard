from __future__ import annotations

import ast
import py_compile
import shutil
import tempfile
from pathlib import Path

from .mapping import map_requirements
from .models import AnalysisReport, Classification, Requirement, RequirementResult, SourceLocation
from .providers import MutationProvider
from .sandbox import SafeTestRunner


def _compile_tree(root: Path) -> tuple[bool, str]:
    try:
        for path in root.rglob("*.py"):
            if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
                continue
            py_compile.compile(str(path), doraise=True)
        return True, ""
    except py_compile.PyCompileError as exc:
        return False, str(exc)


def _equivalent(original: str, mutated: str) -> bool:
    try:
        left = ast.dump(ast.parse(original), annotate_fields=False, include_attributes=False)
        right = ast.dump(ast.parse(mutated), annotate_fields=False, include_attributes=False)
        return left == right
    except SyntaxError:
        return False


class SpecGuard:
    def __init__(self, project: str | Path, requirements: list[Requirement], provider: MutationProvider, runner: SafeTestRunner | None = None):
        self.project = Path(project).resolve()
        self.requirements = requirements
        self.provider = provider
        self.runner = runner or SafeTestRunner()

    def analyze(self) -> AnalysisReport:
        baseline = self.runner.run(self.project)
        if not baseline.passed:
            return AnalysisReport(False, baseline.output, [
                RequirementResult(item, Classification.INCONCLUSIVE, reason="Baseline tests failed; mutation analysis was not run.")
                for item in self.requirements
            ], str(self.project))

        locations = map_requirements(self.requirements, self.project)
        results: list[RequirementResult] = []
        with tempfile.TemporaryDirectory(prefix="specguard-analysis-") as temp_name:
            temp_root = Path(temp_name)
            for requirement in self.requirements:
                source_location = (locations.get(requirement.id) or [None])[0]
                if source_location is None:
                    results.append(RequirementResult(requirement, Classification.INCONCLUSIVE, reason="No source mapping found."))
                    continue
                source_path = source_location.path
                original_source = source_path.read_text(encoding="utf-8")
                results.append(self._analyze_one(requirement, source_location, original_source, temp_root))
        return AnalysisReport(True, baseline.output, results, str(self.project))

    def _analyze_one(self, requirement: Requirement, location: SourceLocation, original_source: str, temp_root: Path) -> RequirementResult:
        last_reason = ""
        proposal = None
        for attempt in (1, 2):
            try:
                proposal = self.provider.propose(requirement, original_source)
                mutated_source = original_source.replace(proposal.original, proposal.replacement, 1)
                if mutated_source == original_source:
                    raise ValueError("Mutation produced no source change")
                if _equivalent(original_source, mutated_source):
                    return RequirementResult(requirement, Classification.INCONCLUSIVE, proposal.description, location, attempt, reason="Equivalent mutant.", equivalent=True)
                candidate = temp_root / f"{requirement.id.lower()}-attempt-{attempt}"
                shutil.copytree(self.project, candidate)
                relative = location.path.relative_to(self.project)
                candidate_file = candidate / relative
                candidate_file.write_text(mutated_source, encoding="utf-8")
                compiled, compile_output = _compile_tree(candidate)
                if not compiled:
                    last_reason = compile_output
                    continue
                test_run = self.runner.run(candidate)
                if test_run.timed_out:
                    return RequirementResult(requirement, Classification.INCONCLUSIVE, proposal.description, location, attempt, test_run.returncode, test_run.output, "Mutation test timed out.")
                classification = Classification.PROTECTED if not test_run.passed else Classification.UNPROTECTED
                return RequirementResult(requirement, classification, proposal.description, location, attempt, test_run.returncode, test_run.output, "Tests killed the mutant." if classification == Classification.PROTECTED else "Tests did not kill the mutant.", metadata={"rationale": proposal.rationale})
            except (ValueError, OSError, SyntaxError) as exc:
                last_reason = str(exc)
        return RequirementResult(requirement, Classification.INVALID, reason=f"Mutant invalid after retry: {last_reason}", attempt=2, source=location)
