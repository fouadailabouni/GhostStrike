"""
GhostStrike Report Studio - Data Sources
===========================================
Single loader shared by every report variant/format. Wraps
bash_scripts_for_pentest/lib/engagement_query.py (the shared read layer
also used by the dedup engine, the attack graph builder, and the MCP
server) rather than re-implementing findings/evidence/repro-session
loading a second time.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def _scripts_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "bash_scripts_for_pentest"


def _lib_dir() -> Path:
    return _scripts_dir() / "lib"


_lib_path = str(_lib_dir())
if _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

import engagement_query as eq  # noqa: E402

_cybertoolkit_path = str(Path(__file__).resolve().parent.parent)
if _cybertoolkit_path not in sys.path:
    sys.path.insert(0, _cybertoolkit_path)
from engagement_repository import EngagementRepository  # noqa: E402


def _engagements_file() -> Path:
    return Path(__file__).resolve().parent.parent / "engagements.json"


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class ReportData:
    engagement_id: str
    engagement: Dict = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    runs: List[Dict] = field(default_factory=list)
    repro_sessions: List[Dict] = field(default_factory=list)
    evidence_manifests: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    retests: List[Dict] = field(default_factory=list)

    @property
    def findings_by_severity(self) -> Dict[str, List[Dict]]:
        out: Dict[str, List[Dict]] = {}
        for f in self.findings:
            out.setdefault(f.get("severity", "INFO"), []).append(f)
        return out

    @property
    def severity_counts(self) -> Dict[str, int]:
        return {sev: len(items) for sev, items in self.findings_by_severity.items()}

    def findings_sorted(self) -> List[Dict]:
        return sorted(
            self.findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "INFO"), 5),
        )


def _load_engagement_record(engagement_id: str) -> Dict:
    path = _engagements_file()
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    engagements = raw.get("engagements", {})
    for key, eng in engagements.items():
        if key == engagement_id or eng.get("id") == engagement_id:
            return eng
    return {}


def load_report_data(engagement_id: str) -> ReportData:
    findings = eq.get_findings(engagement_id)
    repo = EngagementRepository(engagement_id)
    try:
        retests = repo.get_retests()
    finally:
        repo.close()
    return ReportData(
        engagement_id=engagement_id,
        engagement=_load_engagement_record(engagement_id),
        findings=findings,
        runs=eq.get_runs(engagement_id),
        repro_sessions=eq.get_repro_sessions(engagement_id),
        evidence_manifests=eq.get_evidence_manifests(engagement_id),
        summary=eq.get_summary(engagement_id),
        retests=retests,
    )