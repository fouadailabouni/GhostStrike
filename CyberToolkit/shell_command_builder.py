"""
GhostStrike - Shared Shell Command Builder (CyberToolkit/shell_command_builder.py)

Centralizes construction of the WSL / Git Bash / native-bash invocation
command list used to run a bash script (a governed module, or
repro_runner.sh wrapping one) from this Windows-hosted Python process.

Previously duplicated in two places with two different safety levels:
ghoststrike.py's own `_build_shell_command()` built its inner `bash -c
"..."` string with naive `f'"{arg}"'` wrapping -- no escaping of a quote,
backtick, or `$` inside `arg` -- while
ai_engine/tools/module_runner.py's `_fallback_command_builder()` already
used `shlex.quote()` correctly. Confirmed exploitable: a value like
`legituser"; touch /tmp/PWNED; echo "` passed through the naive path
produces a string that runs `touch /tmp/PWNED` as a real shell command.
Any GUI-typed module parameter, or any AI-agent-supplied one (module
parameters flow through this same builder for AI-initiated runs too),
could reach it. This module is now the one place that builds these
command lists, always via shlex.quote(), so there is no second,
differently-safe implementation left to drift out of sync or regress.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Set

_GIT_BASH_CANDIDATES = (
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
)


def to_wsl_path(path: str) -> str:
    """C:\\foo\\bar -> /mnt/c/foo/bar."""
    norm = path.replace("\\", "/")
    return re.sub(r"^([A-Za-z]):", lambda m: f"/mnt/{m.group(1).lower()}", norm)


def to_native_path(path: str) -> str:
    """C:\\foo\\bar -> C:/foo/bar (what Git Bash / native bash on this host expect)."""
    return path.replace("\\", "/")


def q(value: str) -> str:
    """Single-quote-escapes one value for safe embedding in a `bash -c`
    string. This is the only function anywhere in this codebase that
    should wrap a dynamic value for that purpose -- see module docstring
    for why a hand-rolled f'"{x}"' wrapper is not safe."""
    return shlex.quote(value)


def _build_env_prefix(env_vars: Dict[str, str], wsl_path_keys: Set[str], is_wsl: bool) -> str:
    parts = []
    for key, value in env_vars.items():
        if not value:
            continue
        v = to_wsl_path(value) if (is_wsl and key in wsl_path_keys) else value
        parts.append(f"export {key}={q(v)}; ")
    return "".join(parts)


def _build_args_str(args: List[str], path_arg_indices: Set[int], is_wsl: bool) -> str:
    conv = to_wsl_path if is_wsl else to_native_path
    out = [conv(a) if i in path_arg_indices else a for i, a in enumerate(args)]
    return " ".join(q(a) for a in out)


def find_bash_invocation(
    script_path: str,
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    wsl_path_env_keys: Optional[Set[str]] = None,
    path_arg_indices: Optional[Set[int]] = None,
    wsl_status_timeout: float = 5,
    use_sudo: bool = True,
) -> List[str]:
    """
    Returns a subprocess.run()-ready argv list that invokes
    `bash <script_path> <args...>` via WSL, Git Bash, or native bash --
    first one reachable, in that order -- with `env_vars` exported inside
    the bash -c string first (needed to cross the WSL process boundary,
    which does not forward arbitrary Windows environment variables by
    default).

    - `wsl_path_env_keys`: names of env_vars whose value is itself a
      Windows path that needs WSL-path conversion when the WSL branch is
      used (e.g. {"GS_SCOPE_FILE"}), left as a plain Windows/native path
      for the Git Bash / native branches.
    - `path_arg_indices`: positions within `args` that are themselves
      Windows paths needing the same per-branch conversion as
      `script_path` (e.g. when a module path is passed as an *argument*
      to a wrapper script like repro_runner.sh, rather than being
      `script_path` itself).
    - `use_sudo`: whether the final "we're genuinely on native Linux, not
      Windows-hosted at all" fallback branch prefixes the invocation with
      `sudo`. Defaults to True to preserve existing behavior for real
      module execution (raw sockets, packet crafting, and similar
      commonly need root on Linux) -- but a caller invoking a harmless
      helper script that never touches the network or filesystem
      privilege boundary (e.g. a finding-metadata write, a SARIF export
      staged in a temp dir) should pass False. Root has no bearing on the
      WSL or Git Bash branches, both of which are Windows-hosted and
      irrelevant to this flag; it only affects the last, real-Linux path.
      Confirmed via real testing on Linux: an unconditional sudo here
      broke a non-interactive finding-write call with no privilege need
      (`FileNotFoundError: sudo` in a minimal container, and even where
      sudo exists, forcing root on every invocation is a real
      least-privilege violation for calls that were never meant to
      elevate).
    """
    args = args or []
    env_vars = env_vars or {}
    wsl_path_env_keys = wsl_path_env_keys or set()
    path_arg_indices = path_arg_indices or set()

    try:
        # `wsl --status` only confirms the WSL launcher itself works, not
        # that the *default distro* has a usable bash -- on a machine
        # whose default distro is Docker Desktop's minimal internal VM
        # (common: Docker Desktop registers one automatically), `wsl
        # --status` succeeds but `wsl bash -c ...` fails with "bash: not
        # found". Probe the thing we're actually about to rely on.
        r = subprocess.run(["wsl", "bash", "-c", "exit 0"], capture_output=True, timeout=wsl_status_timeout)
        if r.returncode == 0:
            prefix = _build_env_prefix(env_vars, wsl_path_env_keys, is_wsl=True)
            astr = _build_args_str(args, path_arg_indices, is_wsl=True)
            return ["wsl", "bash", "-c", f'{prefix}bash {q(to_wsl_path(script_path))} {astr}']
    except Exception:
        pass

    for gb in _GIT_BASH_CANDIDATES:
        if os.path.exists(gb):
            prefix = _build_env_prefix(env_vars, wsl_path_env_keys, is_wsl=False)
            astr = _build_args_str(args, path_arg_indices, is_wsl=False)
            return [gb, "-c", f'{prefix}bash {q(to_native_path(script_path))} {astr}']

    is_wsl_like = os.name != "nt"
    prefix = _build_env_prefix(env_vars, wsl_path_env_keys, is_wsl=is_wsl_like)
    astr = _build_args_str(args, path_arg_indices, is_wsl=is_wsl_like)
    if is_wsl_like and use_sudo:
        return ["sudo", "bash", "-c", f'{prefix}bash {q(to_wsl_path(script_path))} {astr}']
    return ["bash", "-c", f'{prefix}bash {q(to_native_path(script_path))} {astr}']