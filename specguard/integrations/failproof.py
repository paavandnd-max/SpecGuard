"""Failproof AI integration boundary.

The Failproof AI Python SDK is not installed in this environment and no local
SDK documentation was found. This module deliberately contains no invented API
calls; wire the actual SDK here after its versioned instructions are available.
"""

from dataclasses import dataclass


@dataclass
class FailproofAdapter:
    enabled: bool = False

    def generate(self, prompt: str) -> str:
        raise RuntimeError(
            "Failproof AI adapter scaffold only: install the approved SDK and "
            "follow its documented API before enabling this integration."
        )
