"""
GhostStrike AI Engine
=====================
Autonomous AI agent system for offensive and defensive security operations.
Provides multi-model support (Claude, GPT-4o, Ollama) with a ReACT reasoning
loop, security guardrails, MITRE ATT&CK mapping, and full OpenTelemetry tracing.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from .model_provider import GhostStrikeModelProvider, ModelBackend
from .guardrails import GhostStrikeGuardrails
from .mitre_mapper import MitreMapper
from .findings_extractor import FindingsExtractor
from .tracer import GhostStrikeTracer

__version__ = "3.0.0"
__author__  = "Fouad Ailabouni"
__all__ = [
    "GhostStrikeModelProvider",
    "ModelBackend",
    "GhostStrikeGuardrails",
    "MitreMapper",
    "FindingsExtractor",
    "GhostStrikeTracer",
]
