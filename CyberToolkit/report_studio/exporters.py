"""
GhostStrike Report Studio - Exporters
=========================================
Markdown -> HTML (same dark theme as lib/evidence.sh's
gs_evidence_export_report, for visual consistency across every HTML surface
GhostStrike produces).

JSON/SARIF are NOT reimplemented here. gs_finding_export_json/
gs_finding_export_sarif in lib/finding_ontology.sh already generate them
correctly (SARIF 2.1.0, in gs_finding_export_sarif's case) -- but both
operate unconditionally on every finding in GS_FINDINGS_DIR, with no
engagement filter and no dedup-exclusion, which doesn't match what a
per-engagement report needs to show. Rather than re-deriving SARIF
generation a second way (exactly the kind of drift this codebase's own
comments repeatedly warn against), the already-scoped, already-deduped
finding list this package loaded is staged into a throwaway temp
directory and the real bash function is invoked against *that* --
reusing the one real implementation, just pointed at the right input.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import markdown as _markdown

from .data_sources import ReportData

_HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #0d1117; color: #c9d1d9; margin: 0; padding: 32px;
      max-width: 900px; margin-left: auto; margin-right: auto;
    }}
    h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 10px; }}
    h2 {{ color: #79c0ff; margin-top: 30px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }}
    h3 {{ color: #a5d6ff; margin-top: 22px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th, td {{ border: 1px solid #21262d; padding: 8px 12px; text-align: left; }}
    th {{ background: #161b22; color: #79c0ff; }}
    code, pre {{ background: #161b22; color: #ffa657; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; }}
    pre {{ padding: 12px; overflow-x: auto; }}
    a {{ color: #58a6ff; }}
    ul, ol {{ line-height: 1.6; }}
    strong {{ color: #e6edf3; }}
    hr {{ border: none; border-top: 1px solid #21262d; margin: 24px 0; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def render_html(markdown_text: str, title: str) -> str:
    body = _markdown.markdown(markdown_text, extensions=["tables", "fenced_code"])
    return _HTML_SHELL.format(title=title, body=body)


def export_html(markdown_text: str, title: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_html(markdown_text, title))
    return out_path


def export_json(data: ReportData, out_path: Path) -> Path:
    """Serializes the already-loaded, already-scoped finding list directly
    -- this list already came from engagement_query.py, the one canonical
    engagement-scoped/dedup-aware loader, so there is nothing to
    re-derive here."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    export = {
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "GhostStrike Report Studio",
        "engagement_id": data.engagement_id,
        "total": len(data.findings),
        "findings": data.findings,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)
        f.write("\n")
    return out_path


def _scripts_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "bash_scripts_for_pentest"


def export_sarif(data: ReportData, out_path: Path) -> Path:
    """Stages data.findings into a throwaway temp dir and invokes the real
    gs_finding_export_sarif (lib/finding_ontology.sh) against it, so SARIF
    2.1.0 generation stays a single implementation shared with every bash
    caller instead of a second, Python-side one that could drift."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    scripts_dir = _scripts_dir()
    finding_ontology = scripts_dir / "lib" / "finding_ontology.sh"
    if not finding_ontology.exists():
        raise FileNotFoundError(f"lib/finding_ontology.sh not found at {finding_ontology}")

    with tempfile.TemporaryDirectory(prefix="gs_report_sarif_") as tmpdir:
        tmp_findings_dir = Path(tmpdir) / "findings"
        tmp_findings_dir.mkdir()
        for f in data.findings:
            fid = f.get("finding_id") or f"finding_{data.findings.index(f)}"
            with open(tmp_findings_dir / f"{fid}.json", "w", encoding="utf-8") as fh:
                json.dump(f, fh)

        bash_candidates = _bash_candidates()
        last_error = None
        for bash_cmd in bash_candidates:
            try:
                env = dict(os.environ)
                env["GS_FINDINGS_DIR"] = str(tmp_findings_dir)
                result = subprocess.run(
                    bash_cmd + [f'source "{_shell_path(finding_ontology, bash_cmd)}" && gs_finding_export_sarif'],
                    capture_output=True, text=True, timeout=30, env=env,
                )
                if result.returncode == 0:
                    sarif_path = tmp_findings_dir / "findings.sarif.json"
                    if sarif_path.exists():
                        shutil.copy(sarif_path, out_path)
                        return out_path
                last_error = result.stderr
            except Exception as exc:
                last_error = str(exc)
                continue

        raise RuntimeError(f"Could not generate SARIF export via gs_finding_export_sarif: {last_error}")


def _bash_candidates():
    """Same WSL -> Git Bash -> native fallback chain used throughout
    ai_engine/tools/module_runner.py, for the same reason: a single-path
    implementation would silently fail on any setup that resolves bash a
    different way."""
    candidates = []
    try:
        r = subprocess.run(["wsl", "--status"], capture_output=True, timeout=5)
        if r.returncode == 0:
            candidates.append(["wsl", "bash", "-c"])
    except Exception:
        pass
    for gb in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.exists(gb):
            candidates.append([gb, "-c"])
    if os.name != "nt":
        candidates.append(["bash", "-c"])
    return candidates


def _shell_path(path: Path, bash_cmd) -> str:
    if bash_cmd and bash_cmd[0] == "wsl":
        norm = str(path).replace("\\", "/")
        import re
        return re.sub(r"^([A-Za-z]):", lambda m: f"/mnt/{m.group(1).lower()}", norm)
    return str(path)