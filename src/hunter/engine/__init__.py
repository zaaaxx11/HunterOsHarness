"""Engine layer (L1): pluggable scan brains.

Day-one: DeterministicEngine (no LLM). Later: LLMEngine via LiteLLM —
same EngineDriver interface, like how modern agent harnesses mount models.
"""

from hunter.engine.base import (
    CandidateFinding,
    EngineContext,
    EngineDriver,
    EngineResult,
    Evidence,
    ScanPlan,
    TargetSpec,
)
from hunter.engine.deterministic.engine import DeterministicEngine
from hunter.engine.llm import LLMEngine
from hunter.engine.mock import MockEngine

__all__ = [
    "CandidateFinding",
    "DeterministicEngine",
    "EngineContext",
    "EngineDriver",
    "EngineResult",
    "Evidence",
    "LLMEngine",
    "MockEngine",
    "ScanPlan",
    "TargetSpec",
]
