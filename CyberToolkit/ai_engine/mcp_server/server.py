"""
GhostStrike MCP Server
=========================
A LOCAL, stdio-transport MCP server exposing one engagement's data (findings,
attack graph, reproducibility scores) to an MCP client -- Claude Code,
Claude Desktop, Cursor, or any other tool that speaks MCP.

This is NOT a hosted or multi-tenant service. It has no listening socket and
no network exposure: an MCP client spawns this as a child process and talks
to it over that process's own stdin/stdout. The trust boundary is identical
to running the GhostStrike GUI itself -- whoever can launch this process can
read whatever the operating system user running it can read. Do not add
network transports (SSE/streamable-http) to this server without treating
that as a new, separate trust decision, not an incremental option flip.

Every tool here is READ-ONLY. A write tool -- one that could create
findings, mutate an engagement, or trigger a module run from outside
GhostStrike's own GUI/AI-agent approval flow -- is a materially bigger
trust decision than "read my engagement data" and is deliberately not
included in this pass; see the project's roadmap for that as a distinct,
explicitly-approved future addition.

All data access goes through bash_scripts_for_pentest/lib/engagement_query.py
(the same shared read layer used by the dedup engine, Report Studio, and the
attack graph builder) and lib/attack_graph_builder.py, rather than a third
re-implementation of "how to load a finding."

Run directly:
    python3 -m ai_engine.mcp_server.server

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from mcp.server.mcpserver import MCPServer

_lib_dir = str(Path(__file__).resolve().parent.parent.parent.parent / "bash_scripts_for_pentest" / "lib")
if _lib_dir not in sys.path:
    sys.path.insert(0, _lib_dir)

import engagement_query as eq  # noqa: E402
import attack_graph_builder as agb  # noqa: E402

server = MCPServer(
    name="ghoststrike",
    description=(
        "Read-only access to GhostStrike penetration-test engagement data: "
        "engagements, findings, the derived attack graph, and reproducibility "
        "scores. Runs locally over stdio, spawned by the calling MCP client -- "
        "no network exposure, same trust boundary as the GhostStrike GUI itself. "
        "Creates nothing and triggers no module execution."
    ),
)


def _engagements_file() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "engagements.json"


def _load_engagements() -> dict:
    path = _engagements_file()
    if not path.exists():
        return {"active": None, "engagements": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"active": None, "engagements": {}}


@server.tool()
def list_engagements() -> dict:
    """List every GhostStrike engagement known to this installation, with
    the currently active one flagged."""
    raw = _load_engagements()
    active = raw.get("active")
    engagements = raw.get("engagements", {})
    return {
        "active_engagement": active,
        "engagements": [
            {
                "id": eng.get("id", key),
                "client": eng.get("client", ""),
                "environment": eng.get("environment", ""),
                "status": eng.get("status", ""),
                "created": eng.get("created", ""),
                "is_active": key == active,
            }
            for key, eng in engagements.items()
        ],
    }


@server.tool()
def get_engagement(engagement_id: str) -> dict:
    """Get one engagement's metadata plus a summary of its findings, runs,
    and reproducibility sessions."""
    raw = _load_engagements()
    engagements = raw.get("engagements", {})
    record = engagements.get(engagement_id) or next(
        (v for v in engagements.values() if v.get("id") == engagement_id), {}
    )
    summary = eq.get_summary(engagement_id)
    return {"engagement": record, "summary": summary}


@server.tool()
def list_findings(engagement_id: str, severity: Optional[str] = None) -> dict:
    """List an engagement's findings (deduplicated -- merged duplicates are
    excluded, only the primary/surviving finding of each merge group is
    returned). Optionally filter to one severity: CRITICAL, HIGH, MEDIUM,
    LOW, or INFO."""
    findings = eq.get_findings(engagement_id)
    if severity:
        severity = severity.upper()
        findings = [f for f in findings if f.get("severity", "").upper() == severity]
    return {"engagement_id": engagement_id, "count": len(findings), "findings": findings}


@server.tool()
def get_finding(finding_id: str) -> dict:
    """Get one finding by its finding_id, including merge/evidence
    provenance (merged_from, source_count, confidence) if it absorbed
    duplicate reports from other sources."""
    finding = eq.get_finding(finding_id)
    if finding is None:
        return {"error": f"finding_id '{finding_id}' not found"}
    return finding


@server.tool()
def get_attack_graph(engagement_id: str) -> dict:
    """Get the attack graph for an engagement: hosts, services, and
    findings as nodes, with edges carrying evidence/MITRE/confidence/
    remediation. Rebuilt fresh from current findings on every call --
    it is a derived view, never a separate store that can go stale."""
    graph = agb.build_graph(engagement_id)
    return {
        "engagement_id": engagement_id,
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "graph": graph,
    }


@server.tool()
def get_repro_score(engagement_id: str) -> dict:
    """Get aggregate reproducibility scores (0-100, see
    lib/reproducibility.sh's scoring breakdown) across every module-run
    session recorded for this engagement."""
    sessions = eq.get_repro_sessions(engagement_id)
    scored = [
        {"session_id": s.get("session_id"), "module": s.get("module_name"),
         "score": s.get("reproducibility_score")}
        for s in sessions if s.get("reproducibility_score") is not None
    ]
    scores = [s["score"] for s in scored]
    return {
        "engagement_id": engagement_id,
        "session_count": len(sessions),
        "scored_session_count": len(scored),
        "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        "sessions": scored,
    }


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()