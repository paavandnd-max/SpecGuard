import os
from pathlib import Path

import pytest

from specguard.engine import SpecGuard
from specguard.mapping import map_requirements
from specguard.models import Classification, MutationProposal
from specguard.providers import BedrockMutationProvider, DeterministicOfflineProvider, MutationProvider
from specguard.requirements import parse_requirements
from specguard.sandbox import IsolatedWorkspace, TestRun as RunnerResult


ROOT = Path(__file__).parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("SPECGUARD_CHILD_RUN") == "1", reason="component tests are not part of child project runs")


def test_requirements_parse_and_map():
    requirements = parse_requirements(ROOT / "requirements.md")
    assert len(requirements) == 10
    mapped = map_requirements(requirements, ROOT)
    assert all(mapped[item.id] for item in requirements)


def test_offline_analysis_has_three_unprotected_requirements():
    requirements = parse_requirements(ROOT / "requirements.md")
    report = SpecGuard(ROOT, requirements, DeterministicOfflineProvider()).analyze()
    assert report.baseline_passed
    assert report.counts() == {"protected": 7, "unprotected": 3, "invalid": 0, "inconclusive": 0}
    assert {item.requirement.id for item in report.results if item.classification == Classification.UNPROTECTED} == {"REQ-004", "REQ-008", "REQ-010"}


def test_bedrock_adapter_is_explicit_scaffold():
    try:
        BedrockMutationProvider().propose(parse_requirements(ROOT / "requirements.md")[0], "source")
    except RuntimeError as exc:
        assert "scaffold" in str(exc).lower()
    else:
        raise AssertionError("scaffold must not make an invented remote call")


class MissingProvider(MutationProvider):
    def propose(self, requirement, source):
        raise ValueError("no proposal")


class EquivalentProvider(MutationProvider):
    def propose(self, requirement, source):
        return MutationProposal(requirement.id, "whitespace only", "if amount <= 0:", "if amount <= 0: ", "equivalent")


class InvalidProvider(MutationProvider):
    def propose(self, requirement, source):
        return MutationProposal(requirement.id, "missing colon", "if amount <= 0:", "if amount <= 0", "invalid syntax")


def one_requirement():
    return [parse_requirements(ROOT / "requirements.md")[0]]


def test_retry_and_invalid_classification():
    result = SpecGuard(ROOT, one_requirement(), MissingProvider()).analyze().results[0]
    assert result.classification == Classification.INVALID
    assert result.attempt == 2


def test_equivalent_mutant_is_inconclusive():
    result = SpecGuard(ROOT, one_requirement(), EquivalentProvider()).analyze().results[0]
    assert result.classification == Classification.INCONCLUSIVE
    assert result.equivalent


def test_compile_failure_is_invalid_after_retry():
    result = SpecGuard(ROOT, one_requirement(), InvalidProvider()).analyze().results[0]
    assert result.classification == Classification.INVALID
    assert result.attempt == 2


def test_baseline_failure_marks_all_requirements_inconclusive():
    class FailingRunner:
        def run(self, workspace):
            return RunnerResult(1, "baseline failed")

    report = SpecGuard(ROOT, one_requirement(), DeterministicOfflineProvider(), FailingRunner()).analyze()
    assert not report.baseline_passed
    assert report.results[0].classification == Classification.INCONCLUSIVE


def test_isolated_workspace_copies_and_cleans_up(tmp_path):
    with IsolatedWorkspace(ROOT) as copied:
        assert copied != ROOT
        assert (copied / "demo" / "refund_flow.py").exists()
    assert not copied.exists()
