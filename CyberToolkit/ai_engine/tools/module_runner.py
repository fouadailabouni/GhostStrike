"""
GhostStrike AI Engine — Module Runner
=======================================
Bridges the AI agents to GhostStrike's governed bash module arsenal.

Non-negotiable design requirement carried over from the original spec: the
AI must go through the exact same policy/trust/scope gate a manual GUI run
does, with zero exceptions. This runner enforces that in two independent
layers, neither of which is optional:

  1. Gate-or-refuse at dispatch time. Before any module is executed, this
     runner checks bash_scripts_for_pentest/MODULE_INVENTORY.csv for a
     confirmed trust level. A module whose gs_policy_gate wiring hasn't
     been verified (trust_level is UNDOCUMENTED/UNKNOWN/missing) is refused
     outright — the AI never gets to attempt it, regardless of what that
     module's own code does or doesn't enforce. This matters because, as of
     this port, a meaningful fraction of GhostStrike's module catalog still
     doesn't call gs_policy_gate at all (Phase 3 of the production-readiness
     plan is still rolling that out); the AI must not be a way to reach
     those modules ahead of a human being able to.
  2. Runtime enforcement. Every execution is routed through
     lib/repro_runner.sh wrapping the target script, so the module's own
     gs_policy_gate call still runs (scope/trust/approval checks) exactly
     as it would for a manual GUI or CLI invocation. Exit code 77 (policy
     blocked) is surfaced to the LLM as an explicit, readable refusal —
     never swallowed as a generic error the model might retry past.

Command construction (WSL vs. Git Bash vs. native bash) is delegated to a
caller-supplied ``command_builder`` — normally the GUI's own
``_build_shell_command`` — so an AI-initiated run resolves the shell and
exports engagement context (GS_ENGAGEMENT_ID / GS_ENVIRONMENT /
GS_SCOPE_FILE) through the *identical* code path a manual run uses, rather
than a second implementation that could drift from it.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import csv
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

# policy_query.py already parses policy.yaml's per-module
# require_explicit_approval/reason fields for lib/policy_engine.sh -- reused
# here as-is rather than re-parsing the YAML a second way, so there is one
# authoritative "does this module need approval" answer, not two that could
# drift (bash-side enforcement and AI-side prompting reading the same file
# through the same code).
_POLICY_QUERY_IMPORT_ERROR = ""
try:
    _lib_dir = str(Path(__file__).resolve().parent.parent.parent.parent / "bash_scripts_for_pentest" / "lib")
    if _lib_dir not in sys.path:
        sys.path.insert(0, _lib_dir)
    import policy_query as _policy_query
except Exception as _exc:  # pragma: no cover - PyYAML missing, policy.yaml unreadable, etc.
    _policy_query = None
    _POLICY_QUERY_IMPORT_ERROR = str(_exc)

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "run_ghoststrike_module",
        "description": (
            "Execute one of GhostStrike's governed penetration testing modules. "
            "Call with action='list_modules' first to discover available modules, then "
            "action='describe' to see a module's actual command-line flags before running it — "
            "params are passed as CLI flags (e.g. {\"target\": \"10.0.0.1\"} becomes "
            "--target 10.0.0.1), not environment variables. Every call goes through the same "
            "policy/trust/scope gate as a manual run: HIGH_IMPACT and LAB_ONLY modules require "
            "the active engagement to be authorized for that trust level and scope, and a call "
            "to a module whose gate wiring can't be confirmed is refused before anything executes."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "module_name": {
                    "type": "string",
                    "description": "Script filename, e.g. 'nmap_automation.sh' or 'kerberoasting_attack.sh'.",
                },
                "params": {
                    "type": "object",
                    "description": (
                        "Flag/value pairs, e.g. {\"target\": \"10.0.0.1\", \"domain\": \"corp.local\"} "
                        "becomes --target 10.0.0.1 --domain corp.local on the command line. Use "
                        "action='describe' first to see the module's real flag names — they vary "
                        "per module (--target, --dc, --url, --bucket, ...). For a value-less flag "
                        "like --dry-run or --execute-lab, set its value to true, e.g. "
                        "{\"dry-run\": true} becomes --dry-run with no argument after it."
                    ),
                    "additionalProperties": {"type": "string"},
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default 300).",
                    "default": 300,
                },
                "action": {
                    "type": "string",
                    "enum": ["run", "list_modules", "describe"],
                    "description": "'run' executes the module, 'list_modules' lists all available modules, 'describe' shows a module's usage/flags.",
                    "default": "run",
                },
            },
            "required": ["module_name"],
        },
    },
}

# ── Category → readable name ──────────────────────────────────────────────────
_CATEGORY_LABELS: Dict[str, str] = {
    "00-Framework-Core":            "Framework Core",
    "01-Network-Security":          "Network Security",
    "02-Web-Application-Security":  "Web Application Security",
    "03-Wireless-Security":         "Wireless Security",
    "04-Database-Security":         "Database Security",
    "05-Active-Directory":          "Active Directory",
    "06-Password-Attacks":          "Password Attacks",
    "07-Social-Engineering":        "Social Engineering",
    "08-System-Security":           "System Security",
    "09-Container-Security":        "Container Security",
    "10-Mobile-Security":           "Mobile Security",
    "11-Cloud-Security":            "Cloud Security",
    "12-Exploitation":              "Exploitation",
    "13-Post-Exploitation":         "Post-Exploitation",
    "14-Reporting-Tools":           "Reporting",
    "15-Automation-Tools":          "Automation",
    "16-Specialized-Testing":       "Specialised Testing",
    "17-Monitoring-Detection":      "Monitoring & Detection",
    "18-Application-Security":      "Application Security",
    "19-Lab-Environment":           "Lab Environment",
    "20-IoT-Security":              "IoT Security",
    "21-Bypass-Techniques":         "Bypass Techniques",
}

class GhostStrikeRunner:
    """
    AI-facing wrapper for GhostStrike's governed bash module arsenal.
    See module docstring for the gate-or-refuse + repro_runner.sh enforcement design.
    """

    def __init__(
        self,
        scripts_base_dir: Optional[str] = None,
        command_builder: Optional[Callable[[str, List[str]], List[str]]] = None,
        output_callback=None,
        autonomy_tier: str = "recommend",
        approval_callback: Optional[Callable[[Dict], bool]] = None,
    ) -> None:
        if scripts_base_dir:
            self._base = Path(scripts_base_dir)
        else:
            engine_dir = Path(__file__).resolve().parent.parent.parent
            self._base = engine_dir.parent / "bash_scripts_for_pentest"

        # Normally the GUI's own _build_shell_command(path, args) -> List[str],
        # so an AI run resolves WSL/Git-Bash/native bash and exports engagement
        # env vars through the exact same code a manual run uses. Falls back to
        # a minimal self-contained resolver for standalone/non-GUI use.
        self._command_builder = command_builder or self._fallback_command_builder

        self._output_cb = output_callback

        # Observe: never executes, only describes what would run.
        # Recommend (default): every run needs approval_callback to say yes.
        # Operate: SAFE_ENUM/VALIDATION auto-proceed; HIGH_IMPACT/LAB_ONLY and
        # anything policy.yaml flags require_explicit_approval still need
        # approval_callback -- Operate means "stop asking for routine recon,"
        # never "stop asking before anything destructive."
        tier = (autonomy_tier or "recommend").strip().lower()
        if tier not in ("observe", "recommend", "operate"):
            tier = "recommend"
        self._autonomy_tier = tier
        self._approval_cb = approval_callback

        self._module_index: Dict[str, Path] = {}
        self._trust_by_path: Dict[str, str] = {}
        self._build_index()
        self._load_trust_registry()

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        module_name: str,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 300,
        action: str = "run",
    ) -> str:
        if action == "list_modules":
            return self.list_modules()
        if action == "describe":
            return self.describe_module(module_name)

        script_path = self._resolve(module_name)
        if not script_path:
            available = self._closest_matches(module_name)
            hint = f"  Did you mean: {', '.join(available)}?" if available else ""
            return f"Error: module '{module_name}' not found.{hint}"

        rel = self._relative(script_path)
        trust = self._trust_by_path.get(rel, "")

        # Gate-or-refuse must check what the script's code actually does, not
        # what MODULE_INVENTORY.csv's trust_level column says. Those can and
        # do disagree: trust_level is populated from SCRIPT_INVENTORY.md
        # documentation first, which can describe a module's *intended* trust
        # tier before gs_policy_gate has actually been wired into it -- e.g.
        # authorization_framework.sh has a documented trust_level of
        # VALIDATION but contains no gs_policy_gate call at all. Trusting the
        # CSV column alone would let the AI dispatch modules with zero
        # runtime enforcement, which is exactly what this refusal exists to
        # prevent. Reading the file directly is slightly more expensive per
        # call but can't drift from what's actually enforced.
        if not self._has_policy_gate_call(script_path):
            return (
                f"REFUSED: '{module_name}' ({rel}) does not call gs_policy_gate anywhere in "
                f"its own code (checked directly, not via MODULE_INVENTORY.csv, which can be "
                f"stale). This runner will not dispatch a module whose policy/trust/scope "
                f"enforcement can't be confirmed from the script itself — that's a hard rule, "
                f"not a suggestion the model can reason around. Run it manually via the GUI "
                f"instead, or wire gs_policy_gate into it before the AI can use it. "
                f"(Documented trust_level: {trust or 'none'}.)"
            )

        # ── Autonomy tier gate ──
        # This runs *in addition to* the gate-or-refuse check above, never
        # instead of it -- a module with no gs_policy_gate call is refused
        # regardless of tier. This gate decides whether the AI may proceed
        # to attempt a module that *does* have real bash-side enforcement.
        module_basename = Path(rel).name
        approval_required, approval_reason = self._module_requires_explicit_approval(module_basename)
        needs_approval = approval_required or trust in ("HIGH_IMPACT", "LAB_ONLY")

        if self._autonomy_tier == "observe":
            return (
                f"PROPOSED (not executed -- Observe mode): would run '{module_name}' "
                f"(trust={trust}) with params={params or {}}. Observe mode never executes "
                f"tools; switch to Recommend or Operate mode to allow this to run."
            )

        if self._autonomy_tier == "operate" and not needs_approval:
            pass  # SAFE_ENUM/VALIDATION, no policy.yaml override -- proceed without asking.
        else:
            # Recommend tier always asks; Operate tier asks only when the
            # module is HIGH_IMPACT/LAB_ONLY or policy.yaml requires it.
            if self._approval_cb is None:
                return (
                    f"REFUSED: '{module_name}' (trust={trust}) requires operator approval "
                    f"before the AI can run it (autonomy tier: {self._autonomy_tier}), but no "
                    f"approval mechanism is wired up in this session. Run it manually instead."
                )
            request = {
                "module_name": module_name,
                "params": params or {},
                "trust": trust,
                "reason": approval_reason or ("HIGH_IMPACT/LAB_ONLY module" if trust in ("HIGH_IMPACT", "LAB_ONLY") else ""),
            }
            try:
                approved = bool(self._approval_cb(request))
            except Exception as exc:
                return f"Error requesting approval for '{module_name}': {exc}"
            if not approved:
                return (
                    f"DENIED: operator did not approve running '{module_name}' (trust={trust})."
                    + (f" Reason for requiring approval: {approval_reason}" if approval_reason else "")
                )

        repro_runner = self._base / "repro_runner.sh"
        if not repro_runner.exists():
            return f"Error: reproducibility wrapper not found at {repro_runner}."

        cli_args = self._params_to_cli_args(params or {})
        full_args = [str(script_path)] + cli_args

        try:
            cmd = self._command_builder(str(repro_runner), full_args)
        except Exception as exc:
            return f"Error building command: {exc}"

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 15,
            )
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return f"Error: '{module_name}' timed out after {timeout}s."
        except FileNotFoundError:
            return "Error: bash/WSL not found. Ensure WSL2 or Git Bash is installed."
        except Exception as exc:
            return f"Error executing module: {exc}"

        if code == 77:
            output = (
                f"POLICY GATE BLOCKED: gs_policy_gate refused to run '{module_name}' "
                f"(trust={trust}). This is the same gate a manual GUI run goes through — "
                f"it is not an AI-specific restriction, and the model should not retry this "
                f"exact call. Likely cause: no active engagement, wrong environment tier for "
                f"this trust level, target outside declared scope, or missing approval for a "
                f"HIGH_IMPACT/LAB_ONLY module. Gate output:\n{stderr[-2000:]}"
            )
        else:
            output = stdout
            if stderr.strip():
                output += f"\n[STDERR]\n{stderr}"
            if code != 0:
                output += f"\n[EXIT CODE: {code}]"

        output = self._redact(output)

        if self._output_cb:
            self._output_cb(output)

        header = f"[GhostStrike Module: {module_name}  (trust={trust})]\n{'-' * 60}\n"
        return header + output

    def list_modules(self) -> str:
        if not self._module_index:
            return "No modules found. Check the scripts_base_dir configuration."

        by_cat: Dict[str, List[str]] = {}
        for name, path in sorted(self._module_index.items()):
            cat = path.parent.name
            label = _CATEGORY_LABELS.get(cat, cat)
            trust = self._trust_by_path.get(self._relative(path), "?")
            by_cat.setdefault(label, []).append(f"{name}  [{trust}]")

        lines = [f"GhostStrike Module Arsenal ({len(self._module_index)} modules)\n"]
        for cat, modules in sorted(by_cat.items()):
            lines.append(f"\n  [{cat}]")
            for m in modules:
                lines.append(f"    {m}")
        lines.append(
            "\n(The trust label shown here is documentation, not a guarantee. A module is "
            "refused at run-time if its own code has no gs_policy_gate call, regardless of "
            "what its documented trust level says.)"
        )
        return "\n".join(lines)

    def describe_module(self, module_name: str) -> str:
        path = self._resolve(module_name)
        if not path:
            return f"Module '{module_name}' not found."
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(3000)
        except IOError:
            return f"Cannot read module '{module_name}'."

        lines = content.splitlines()
        header = []
        for line in lines[:40]:
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                header.append(stripped)
        trust = self._trust_by_path.get(self._relative(path), "?")
        return (
            f"Module: {module_name}\nLocation: {path}\nTrust level: {trust}\n\n"
            + "\n".join(header[:20])
        )

    # ── Internal: module index and trust registry ──────────────────────────────

    def _build_index(self) -> None:
        if not self._base.exists():
            return
        for script in self._base.rglob("*.sh"):
            if "lib" in script.parts or "benchmarks" in script.parts or "metrics" in script.parts:
                continue
            self._module_index[script.name] = script

    @staticmethod
    def _has_policy_gate_call(script_path: Path) -> bool:
        """Ground-truth check: does this script actually call gs_policy_gate
        anywhere in its own source? Deliberately not cached across the
        runner's lifetime -- a module can get wired mid-session (e.g. an
        operator fixing it while the GUI is open) and refusal should reflect
        the file as it is right now, not as it was when the runner started."""
        try:
            content = script_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        return "gs_policy_gate" in content

    def _module_requires_explicit_approval(self, module_basename: str) -> "tuple[bool, str]":
        """(required, reason) per policy.yaml's modules: block -- the same
        data lib/policy_engine.sh's gs_policy_check_module reads via this
        same policy_query.py, so bash enforcement and AI-side prompting can
        never disagree about which modules need it."""
        if _policy_query is None:
            return False, ""
        policy_path = self._base / "policy.yaml"
        if not policy_path.exists():
            return False, ""
        try:
            policy = _policy_query.load_policy(str(policy_path))
        except Exception:
            return False, ""
        entry = (policy.get("modules", {}) or {}).get(module_basename)
        if entry and entry.get("require_explicit_approval"):
            return True, entry.get("reason", "")
        return False, ""

    def _load_trust_registry(self) -> None:
        csv_path = self._base / "MODULE_INVENTORY.csv"
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    path = (row.get("script_path") or "").strip()
                    trust = (row.get("trust_level") or "").strip()
                    if path:
                        self._trust_by_path[path] = trust
        except (OSError, csv.Error):
            pass  # No inventory readable -- every module falls through to "refused", the safe default.

    def _relative(self, script_path: Path) -> str:
        try:
            return str(script_path.relative_to(self._base)).replace("\\", "/")
        except ValueError:
            return script_path.name

    def _resolve(self, name: str) -> Optional[Path]:
        if not name.endswith(".sh"):
            name = name + ".sh"
        return self._module_index.get(name)

    def _closest_matches(self, query: str, limit: int = 5) -> List[str]:
        query = query.lower().replace(".sh", "")
        hits = [n for n in self._module_index if query in n.lower()]
        return hits[:limit]

    # ── Internal: dispatch plumbing ─────────────────────────────────────────────

    @staticmethod
    def _params_to_cli_args(params: Dict[str, str]) -> List[str]:
        """
        Translate an {key: value} dict into CLI flags. Boolean-flag-shaped
        values (True, "true", "" -- i.e. how a model is likely to signal
        "just set this flag, it takes no argument", for things like
        --dry-run/--no-crack/--execute-lab) become a bare flag with no
        value token; False/"false" omits the flag entirely; anything else
        becomes --flag value.
        """
        args: List[str] = []
        for key, value in params.items():
            flag = "--" + str(key).strip().lower().replace("_", "-")
            if isinstance(value, bool):
                if value:
                    args.append(flag)
                continue
            value_str = str(value).strip()
            if value_str == "" or value_str.lower() == "true":
                args.append(flag)
            elif value_str.lower() == "false":
                continue
            else:
                args.append(flag)
                args.append(value_str)
        return args

    def _redact(self, text: str) -> str:
        """Best-effort credential/secret redaction before output reaches the LLM
        (and therefore potentially an external API). Reuses lib/common.sh's
        gs_redact so there is exactly one redaction implementation, shared with
        every bash caller, instead of a second pattern set that could drift."""
        if not text:
            return text
        common_sh = str(self._base / "lib" / "common.sh")
        common_wsl = self._to_wsl_path(common_sh)

        # Same WSL -> Git Bash -> native fallback chain as everywhere else in
        # this file, not just WSL -- a single-path implementation would
        # silently fail open (no redaction, but still return real output) on
        # any setup that resolves bash a different way. Tried in order;
        # first one that actually runs wins.
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
        return text  # Redaction is best-effort; never let it block returning real output.

    @staticmethod
    def _to_wsl_path(path: str) -> str:
        norm = path.replace("\\", "/")
        return re.sub(r"^([A-Za-z]):", lambda m: f"/mnt/{m.group(1).lower()}", norm)

    def _fallback_command_builder(self, path: str, args: List[str]) -> List[str]:
        """
        WSL-first resolver used when no GUI command_builder was injected --
        which in practice includes every run initiated from inside an agent's
        own tool-calling loop, since each agent constructs its own
        GhostStrikeRunner() internally (see e.g. red_team_agent.py) with no
        hook to pass the GUI's bound _build_shell_command through.

        Engagement context (GS_ENGAGEMENT_ID / GS_ENVIRONMENT / GS_SCOPE_FILE)
        is therefore read from THIS PROCESS's environment, not re-derived here.
        The GUI is responsible for setting those on os.environ before starting
        an AI Co-Pilot session (mirroring exactly what _build_shell_command
        already exports for a manual run) so gs_policy_gate sees the same
        authorization context either way. Explicitly re-exporting them into
        the bash -c string (rather than relying on WSL's WSLENV passthrough,
        which doesn't forward arbitrary Windows env vars by default) is what
        makes that actually cross the WSL boundary.
        """
        wsl_path = self._to_wsl_path(path)
        astr = " ".join(shlex.quote(a) for a in args)

        env_prefix = ""
        for var in ("GS_ENGAGEMENT_ID", "GS_ENVIRONMENT", "GS_SCOPE_FILE"):
            val = os.environ.get(var, "")
            if val:
                if var == "GS_SCOPE_FILE":
                    val = self._to_wsl_path(val)
                env_prefix += f'export {var}={shlex.quote(val)}; '

        inner = f'{env_prefix}bash "{wsl_path}" {astr}'
        try:
            r = subprocess.run(["wsl", "--status"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return ["wsl", "bash", "-c", inner]
        except Exception:
            pass
        for gb in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
            if os.path.exists(gb):
                return [gb, "-c", f'{env_prefix}bash "{path}" {astr}']
        if os.name != "nt":
            return ["bash", "-c", inner]
        return ["bash", "-c", inner]