"""
GhostStrike AI Engine — Ad-hoc Tool Governance
=================================================
Closes a real gap found during live evaluation: ``ShellExecutor``
(``execute_shell_command``) and ``CodeRunner`` (``execute_code``) let an AI
agent run arbitrary commands/code via ``subprocess`` with no policy/trust/
scope gate and no evidence capture at all -- only ``GhostStrikeRunner``
(``run_ghoststrike_module``) went through ``gs_policy_gate``. A live
multi-model evaluation run confirmed models routinely preferred the
ungoverned path (e.g. one cell issued 945 ``execute_shell_command`` calls
against zero ``run_ghoststrike_module`` calls in the same session), so this
was not a theoretical gap.

Unlike governed modules, an arbitrary shell command or code blob has no
script file to check for a ``gs_policy_gate`` call and no reliable way to
extract a "target" for a scope check (regex-based target extraction from
free-form text is exactly the kind of unreliable filter that creates false
confidence). Rather than pretend a bare-command scope check would be
trustworthy, this module applies the same fail-closed philosophy
``module_runner.py`` already uses for undocumented/unclassified modules
("couldn't determine risk, so ask" -- see ``_module_requires_explicit_
approval``'s docstring): every ad-hoc command is treated as requiring
explicit operator approval, in every autonomy tier, with no SAFE_ENUM/
VALIDATION-style auto-proceed exemption, because there is no reliable way
to classify an arbitrary command as low-risk. Observe mode still only
describes; Recommend and Operate both require ``approval_callback`` to
return true.

Approved calls are then logged into the same per-engagement evidence
directory structure ``lib/evidence.sh`` uses (``engagements/<id>/evidence/
manifest.json``, SHA-256 per artifact), so ad-hoc execution is no longer
untraceable -- it just isn't scope/trust-gated the way a registered module
is, and the returned message says so explicitly rather than implying parity
with ``run_ghoststrike_module``.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional


def gate_or_refuse(
    tool_name: str,
    summary: str,
    autonomy_tier: str,
    approval_callback: Optional[Callable[[Dict], bool]],
    detail: Optional[Dict] = None,
) -> Optional[str]:
    """Returns a refusal/proposal message if the call must NOT proceed, or
    None if the caller is cleared to execute. Every ad-hoc command requires
    approval in every tier (see module docstring) -- there is no autonomy
    tier or trust level at which this auto-proceeds, unlike governed
    modules where SAFE_ENUM/VALIDATION can skip confirmation in Operate
    mode."""
    tier = (autonomy_tier or "recommend").strip().lower()
    if tier not in ("observe", "recommend", "operate"):
        tier = "recommend"

    if tier == "observe":
        return (
            f"PROPOSED (not executed -- Observe mode): would run {tool_name} -- {summary}. "
            f"Observe mode never executes tools; switch to Recommend or Operate to allow this."
        )

    if approval_callback is None:
        return (
            f"REFUSED: {tool_name} requires operator approval before the AI can run it "
            f"(autonomy tier: {tier}), but no approval mechanism is wired up in this session. "
            f"Unlike run_ghoststrike_module, {tool_name} runs arbitrary input with no scope/"
            f"trust classification available, so it cannot be treated as safe by default in "
            f"any tier -- run it manually instead."
        )

    request = {
        "tool_name": tool_name,
        "summary": summary,
        "trust": "UNCLASSIFIED_AD_HOC",
        "reason": (
            f"{tool_name} executes arbitrary input with no fixed trust tier; every call "
            f"requires explicit approval regardless of autonomy tier."
        ),
        **(detail or {}),
    }
    try:
        approved = bool(approval_callback(request))
    except Exception as exc:  # noqa: BLE001 - surfaced to the model, not swallowed
        return f"Error requesting approval for {tool_name}: {exc}"
    if not approved:
        return f"DENIED: operator did not approve this {tool_name} call."
    return None


def capture_ad_hoc_evidence(
    engagement_id: Optional[str],
    tool_name: str,
    command_or_code: str,
    output: str,
    base_dir: Optional[str] = None,
) -> Optional[str]:
    """Writes a hashed evidence record for an approved ad-hoc execution into
    the same engagements/<id>/evidence/ manifest.json structure lib/
    evidence.sh populates for governed modules, so this activity is no
    longer untraceable even though it isn't scope/trust-gated. Best-effort:
    failure to log evidence must never block or fail the underlying tool
    call (fails open on logging only, never on the governance gate above).
    Returns the artifact_id on success, None if logging was skipped/failed.
    """
    if not engagement_id:
        return None  # No active engagement -- nothing to attach evidence to.

    try:
        if base_dir:
            root = Path(base_dir)
        else:
            # CyberToolkit/ai_engine/ -> repo root -> bash_scripts_for_pentest/engagements
            root = Path(__file__).resolve().parent.parent.parent / "bash_scripts_for_pentest"
        evidence_dir = root / "engagements" / engagement_id / "evidence"
        artifacts_dir = evidence_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = evidence_dir / "manifest.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                manifest = {"schema_version": 1, "engagement_id": engagement_id, "artifacts": []}
        else:
            manifest = {"schema_version": 1, "engagement_id": engagement_id, "artifacts": []}

        artifact_id = str(uuid.uuid4())
        artifact_path = artifacts_dir / f"{artifact_id}.log"
        payload = f"COMMAND/CODE:\n{command_or_code}\n\nOUTPUT:\n{output}"
        artifact_path.write_text(payload, encoding="utf-8")
        sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        manifest.setdefault("artifacts", []).append({
            "artifact_id": artifact_id,
            "stored_path": str(artifact_path),
            "sha256": sha256,
            "source_command": tool_name,
            "description": f"ad-hoc {tool_name} call (ungoverned path -- see trust field)",
            "trust": "UNCLASSIFIED_AD_HOC",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return artifact_id
    except OSError:
        return None