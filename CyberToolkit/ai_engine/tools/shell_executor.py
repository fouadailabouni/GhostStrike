"""
GhostStrike AI Engine — Shell Executor
=======================================
Secure shell command execution with session management, environment detection,
streaming output, and multi-layer guardrails.  The primary tool used by all
GhostStrike AI agents to interact with the operating system.

Architecture
------------
  - Synchronous execution  → standard one-shot commands
  - Async / session mode   → interactive programs (ssh, nc, python REPL, etc.)
  - Environment detection  → Docker container, SSH remote, CTF target, local
  - Guardrails integration → every command validated before execution
  - Output sanitisation    → external content flagged before re-entering LLM

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import os
import queue
import shlex
import subprocess
import threading
import time
import uuid
from typing import Callable, Dict, Optional

from ..guardrails import GhostStrikeGuardrails

# ── OpenAI-compatible tool schema ────────────────────────────────────────────
TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "execute_shell_command",
        "description": (
            "Execute any shell command on the target environment. "
            "Supports one-shot commands, interactive sessions (ssh, nc, python), "
            "and session management. "
            "Use session_id to send input to a running interactive session."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute.",
                },
                "interactive": {
                    "type": "boolean",
                    "description": "Set True for commands that keep stdin open (ssh, nc, python).",
                    "default": False,
                },
                "session_id": {
                    "type": "string",
                    "description": "ID of an existing interactive session to send command to.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default 60).",
                    "default": 60,
                },
            },
            "required": ["command"],
        },
    },
}

# ── Interactive session record ────────────────────────────────────────────────
class _Session:
    def __init__(self, session_id: str, command: str) -> None:
        self.session_id   = session_id
        self.command      = command
        self.output_buf   = queue.Queue()
        self.process: Optional[subprocess.Popen] = None
        self.alive        = True
        self.started_at   = time.time()

    def enqueue(self, line: str) -> None:
        self.output_buf.put(line)

    def drain(self, max_lines: int = 200) -> str:
        lines = []
        try:
            while not self.output_buf.empty() and len(lines) < max_lines:
                lines.append(self.output_buf.get_nowait())
        except queue.Empty:
            pass
        return "".join(lines)


class ShellExecutor:
    """
    Secure shell command executor for GhostStrike AI agents.

    Maintains a registry of active interactive sessions so agents can:
    - Start long-running programs (ssh, netcat, etc.)
    - Poll their output asynchronously
    - Send further input to running sessions
    - Terminate sessions cleanly
    """

    # Interactive binary set — triggers persistent session mode
    _INTERACTIVE_BINS = {
        "bash", "sh", "zsh", "fish", "python", "python3", "ipython",
        "node", "ruby", "irb", "psql", "mysql", "sqlite3", "mongo",
        "redis-cli", "ftp", "sftp", "telnet", "ssh", "nc", "ncat",
        "socat", "gdb", "lldb", "r2", "radare2", "tshark", "tcpdump",
        "tail", "journalctl", "watch",
    }

    def __init__(
        self,
        guardrails: Optional[GhostStrikeGuardrails] = None,
        output_callback: Optional[Callable[[str], None]] = None,
        ssh_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_password: Optional[str] = None,
        docker_container: Optional[str] = None,
    ) -> None:
        self._guardrails      = guardrails or GhostStrikeGuardrails()
        self._output_callback = output_callback
        self._ssh_host        = ssh_host or os.getenv("GS_SSH_HOST")
        self._ssh_user        = ssh_user or os.getenv("GS_SSH_USER")
        self._ssh_password    = ssh_password or os.getenv("GS_SSH_PASSWORD")
        self._docker_ctr      = docker_container or os.getenv("GS_DOCKER_CONTAINER")
        self._sessions: Dict[str, _Session] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        command: str,
        interactive: bool = False,
        session_id: Optional[str] = None,
        timeout: int = 60,
    ) -> str:
        """
        Main entry point called by agent tool dispatch.

        Returns a string result suitable for feeding back to the LLM.
        """
        command = command.strip()
        if not command:
            return "Error: empty command."

        # Session management short-circuits
        if command.lower().startswith("session ") or command.lower() in (
            "sessions", "session list", "session ls"
        ):
            return self._handle_session_management(command)

        # Validate with guardrails
        ok, reason = self._guardrails.validate_command(command)
        if not ok:
            return reason

        # Route to correct execution path
        if session_id:
            return self._send_to_session(session_id, command)

        if interactive or self._is_interactive(command):
            return self._start_interactive_session(command)

        return self._run_oneshot(command, timeout)

    # ── One-shot execution ────────────────────────────────────────────────────

    def _run_oneshot(self, command: str, timeout: int) -> str:
        effective_cmd = self._wrap_for_environment(command)
        try:
            result = subprocess.run(
                effective_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "TERM": "xterm-256color"},
            )
            output = result.stdout + (f"\n[stderr]: {result.stderr}" if result.stderr.strip() else "")
        except subprocess.TimeoutExpired:
            output = f"Error: command timed out after {timeout}s."
        except Exception as exc:
            output = f"Error executing command: {exc}"

        sanitised = self._guardrails.sanitise_output(command, output)
        if self._output_callback:
            self._output_callback(sanitised)
        return sanitised

    # ── Interactive sessions ──────────────────────────────────────────────────

    def _start_interactive_session(self, command: str) -> str:
        sid = str(uuid.uuid4())[:8]
        session = _Session(sid, command)
        effective_cmd = self._wrap_for_environment(command)

        try:
            proc = subprocess.Popen(
                effective_cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            session.process = proc
        except Exception as exc:
            return f"Error starting interactive session: {exc}"

        self._sessions[sid] = session

        def _reader():
            for line in proc.stdout:
                session.enqueue(line)
                if self._output_callback:
                    self._output_callback(line)
            session.alive = False

        threading.Thread(target=_reader, daemon=True).start()
        time.sleep(0.3)

        initial = session.drain()
        return (
            f"Interactive session started — ID: {sid}\n"
            f"Use execute_shell_command with session_id='{sid}' to send commands.\n"
            + (f"\nInitial output:\n{initial}" if initial else "")
        )

    def _send_to_session(self, session_id: str, command: str) -> str:
        session = self._sessions.get(session_id)
        if not session:
            return f"Error: session '{session_id}' not found."
        if not session.alive:
            return f"Error: session '{session_id}' has terminated."
        try:
            session.process.stdin.write(command + "\n")
            session.process.stdin.flush()
        except Exception as exc:
            return f"Error sending to session: {exc}"

        time.sleep(0.5)
        output = session.drain()
        return output or f"(sent to session {session_id}, no immediate output)"

    def _handle_session_management(self, command: str) -> str:
        cmd_lower = command.lower().strip()
        parts     = command.split()

        if cmd_lower in ("sessions", "session list", "session ls"):
            if not self._sessions:
                return "No active sessions."
            lines = ["Active sessions:"]
            for sid, s in self._sessions.items():
                age  = int(time.time() - s.started_at)
                stat = "ALIVE" if s.alive else "DEAD"
                lines.append(f"  [{sid}] {stat} | cmd='{s.command}' | age={age}s")
            return "\n".join(lines)

        if len(parts) >= 3 and parts[1].lower() == "output":
            sid = parts[2]
            s   = self._sessions.get(sid)
            return s.drain() if s else f"Session '{sid}' not found."

        if len(parts) >= 3 and parts[1].lower() == "kill":
            sid = parts[2]
            s   = self._sessions.get(sid)
            if s:
                try:
                    s.process.terminate()
                except Exception:
                    pass
                del self._sessions[sid]
                return f"Session '{sid}' terminated."
            return f"Session '{sid}' not found."

        return "Usage: session list | session output <id> | session kill <id>"

    # ── Environment wrapping ─────────────────────────────────────────────────

    def _wrap_for_environment(self, command: str) -> str:
        if self._docker_ctr:
            safe = command.replace("'", "'\\''")
            return f"docker exec {self._docker_ctr} bash -c '{safe}'"
        if self._ssh_host and self._ssh_user:
            safe = command.replace("'", "'\\''")
            if self._ssh_password:
                return (
                    f"sshpass -p '{self._ssh_password}' ssh -o StrictHostKeyChecking=no "
                    f"{self._ssh_user}@{self._ssh_host} '{safe}'"
                )
            return f"ssh -o StrictHostKeyChecking=no {self._ssh_user}@{self._ssh_host} '{safe}'"
        return command

    @staticmethod
    def _is_interactive(command: str) -> bool:
        first = shlex.split(command)[0].lower() if command.strip() else ""
        if first in ShellExecutor._INTERACTIVE_BINS:
            return True
        lower = command.lower()
        return " -i" in lower or "tail -f" in lower or "watch " in lower
