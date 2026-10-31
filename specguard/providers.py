from __future__ import annotations

from abc import ABC, abstractmethod

from .models import MutationProposal, Requirement


class MutationProvider(ABC):
    @abstractmethod
    def propose(self, requirement: Requirement, source: str) -> MutationProposal:
        """Return one structured, single-requirement mutation proposal."""


class DeterministicOfflineProvider(MutationProvider):
    """Offline provider used by the demo and tests; it never calls a model."""

    _RULES: dict[str, tuple[str, str, str, str]] = {
        "REQ-001": ("if amount <= 0:", "if amount < 0:", "allow a zero refund", "boundary mutation"),
        "REQ-002": ("if amount > order[\"captured_amount\"]:", "if amount >= order[\"captured_amount\"]:", "reject an exact full refund", "boundary mutation"),
        "REQ-003": ("if order[\"status\"] != \"paid\":", "if order[\"status\"] == \"paid\":", "invert the paid-order guard", "predicate inversion"),
        "REQ-004": ("if age_days > 30:", "if age_days >= 30:", "reject a refund on day 30", "boundary mutation"),
        "REQ-005": ("if order[\"digital\"]:", "if not order[\"digital\"]:", "allow digital goods and reject physical goods", "predicate inversion"),
        "REQ-006": ("if idempotency_key in self._requests:", "if idempotency_key not in self._requests:", "process duplicate idempotency keys twice", "predicate inversion"),
        "REQ-007": ("if not reason.strip():", "if reason.strip():", "accept blank reasons and reject nonblank reasons", "predicate inversion"),
        "REQ-008": ("if currency != \"USD\":", "if currency == \"EUR\":", "allow an unsupported currency", "predicate mutation"),
        "REQ-009": ("\"status\": \"pending\"", "\"status\": \"approved\"", "skip the pending state", "constant replacement"),
        "REQ-010": ("round(record[\"amount\"], 2)", "round(record[\"amount\"], 0)", "round to whole units instead of cents", "precision mutation"),
    }

    def propose(self, requirement: Requirement, source: str) -> MutationProposal:
        try:
            original, replacement, description, rationale = self._RULES[requirement.id]
        except KeyError as exc:
            raise ValueError(f"No deterministic mutation rule for {requirement.id}") from exc
        if original not in source:
            raise ValueError(f"Mutation target for {requirement.id} was not found")
        return MutationProposal(requirement.id, description, original, replacement, rationale)


class BedrockMutationProvider(MutationProvider):
    """AWS Bedrock adapter boundary without an invented remote API call."""

    def __init__(self, model_id: str | None = None, client: object | None = None):
        self.model_id = model_id
        self.client = client

    def propose(self, requirement: Requirement, source: str) -> MutationProposal:
        raise RuntimeError(
            "BedrockMutationProvider is a scaffold. Configure an approved Bedrock "
            "client and model contract before enabling remote mutation generation."
        )
