"""
GhostStrike AI Engine — Shared Redaction Helper
==================================================
One redaction implementation, reused by every AI-engine tool that puts
real target/environment data (module output, extracted JS secrets, etc.)
into a message that will be sent to an external LLM provider. Previously
duplicated as GhostStrikeRunner._redact() in tools/module_runner.py; that
duplication is exactly the "second pattern set that could drift" failure
mode this module exists to close -- js_analyzer.py had none at all, which
is how token_hits (real hardcoded secrets extracted from scanned JS) were
reaching the LLM completely unredacted.

Fails CLOSED: if every redaction backend is unreachable, redact() raises
RedactionUnavailableError rather than returning the raw text. An operator
who explicitly wants the old best-effort behavior back can opt in via
GS_AI_ALLOW_UNREDACTED_ON_FAILURE=1; nothing bypasses this silently.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional


class RedactionUnavailableError(Exception):
    """Raised by redact() when no redaction backend could be reached.
    See module docstring: this fails closed by design."""


def default_bash_scripts_dir() -> Path:
    # this file -> ai_engine -> CyberToolkit -> GhostStrike -> bash_scripts_for_pentest
    return Path(__file__).resolve().parent.parent.parent / "bash_scripts_for_pentest"


def _to_wsl_path(path: str) -> str:
    norm = path.replace("\\", "/")
    return re.sub(r"^([A-Za-z]):", lambda m: f"/mnt/{m.group(1).lower()}", norm)


def redact(text: str, base_dir: Optional[Path] = None) -> str:
    """Credential/secret redaction before text reaches the LLM (and
    therefore potentially an external API). Reuses lib/common.sh's
    gs_redact so there is exactly one redaction implementation, shared with
    every bash caller and every AI-engine tool, instead of a second (or
    third) pattern set that could drift.
    """
    if not text:
        return text
    base = base_dir or default_bash_scripts_dir()
    common_sh = str(base / "lib" / "common.sh")
    common_wsl = _to_wsl_path(common_sh)

    # Same WSL -> Git Bash -> native fallback chain as everywhere else in
    # the AI engine -- try every way of reaching bash before concluding
    # redaction is genuinely unavailable, not just unavailable via one
    # particular path.
    candidates: List[List[str]] = [
        ["wsl", "bash", "-c", f'source "{common_wsl}" >/dev/null 2>&1; gs_redact']
    ]
    for gb in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.exists(gb):
            candidates.append([gb, "-c", f'source "{common_sh}" >/dev/null 2>&1; gs_redact'])
    if os.name != "nt":
        candidates.append(["bash", "-c", f'source "{common_sh}" >/dev/null 2>&1; gs_redact'])

    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd, input=text, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except Exception:
            continue

    if os.environ.get("GS_AI_ALLOW_UNREDACTED_ON_FAILURE", "").strip() == "1":
        return text
    raise RedactionUnavailableError(
        "no working redaction backend found (WSL/Git Bash/native bash all "
        "unreachable, or gs_redact produced no output) -- refusing to send "
        "unredacted text to the AI model. Set "
        "GS_AI_ALLOW_UNREDACTED_ON_FAILURE=1 to explicitly override this."
    )