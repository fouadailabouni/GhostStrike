"""
GhostStrike AI Engine — Network Capture
=========================================
SSH into a remote host, start a tcpdump capture, pipe the raw PCAP
stream back locally, and run tshark analysis on it.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from typing import Dict, Optional

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "capture_network_traffic",
        "description": (
            "SSH into a remote host and capture live network traffic using tcpdump, "
            "piped back through SSH and analysed with tshark. "
            "Returns a summary of captured traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "host":      {"type": "string", "description": "Remote host IP or hostname."},
                "username":  {"type": "string", "description": "SSH username."},
                "password":  {"type": "string", "description": "SSH password (or leave empty for key auth)."},
                "interface": {"type": "string", "description": "Network interface (e.g. eth0).", "default": "eth0"},
                "capture_filter": {"type": "string", "description": "tcpdump BPF filter expression.", "default": ""},
                "duration":  {"type": "integer", "description": "Capture duration in seconds (default 15).", "default": 15},
                "port":      {"type": "integer", "description": "SSH port (default 22).", "default": 22},
            },
            "required": ["host", "username"],
        },
    },
}


class NetworkCapture:
    """Remote traffic capture via SSH + tcpdump + tshark pipeline."""

    def capture(
        self,
        host: str,
        username: str,
        password: str = "",
        interface: str = "eth0",
        capture_filter: str = "",
        duration: int = 15,
        port: int = 22,
    ) -> str:
        try:
            import paramiko
        except ImportError:
            return "Error: paramiko not installed. Run: pip install paramiko"

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            pcap_path = tmp.name

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": 10,
            }
            if password:
                connect_kwargs["password"] = password
            else:
                connect_kwargs["look_for_keys"] = True

            ssh.connect(**connect_kwargs)
        except paramiko.AuthenticationException:
            return f"Error: Authentication failed for {username}@{host}"
        except Exception as exc:
            return f"Error connecting to {host}: {exc}"

        try:
            tcpdump_cmd = f"timeout {duration} tcpdump -U -i {interface} -w -"
            if capture_filter:
                tcpdump_cmd += f" '{capture_filter}'"

            _, stdout, stderr_ch = ssh.exec_command(tcpdump_cmd)

            # Write PCAP stream to temp file
            pcap_bytes = b""
            start = time.time()
            while time.time() - start < duration + 2:
                chunk = stdout.read(4096)
                if not chunk:
                    break
                pcap_bytes += chunk

            with open(pcap_path, "wb") as fh:
                fh.write(pcap_bytes)
        except Exception as exc:
            return f"Error capturing traffic: {exc}"
        finally:
            ssh.close()

        if len(pcap_bytes) < 24:
            return "Error: No traffic captured (check interface name and permissions)."

        return self._analyse_pcap(pcap_path, duration)

    def _analyse_pcap(self, pcap_path: str, duration: int) -> str:
        analyses = [
            ("Protocol summary",   f"tshark -r {pcap_path} -q -z io,phs 2>/dev/null"),
            ("Top talkers",        f"tshark -r {pcap_path} -q -z conv,ip 2>/dev/null | head -20"),
            ("DNS queries",        f"tshark -r {pcap_path} -Y 'dns.flags.response==0' -T fields -e dns.qry.name 2>/dev/null | sort -u | head -30"),
            ("HTTP requests",      f"tshark -r {pcap_path} -Y http.request -T fields -e http.host -e http.request.uri 2>/dev/null | head -20"),
            ("Credentials (FTP/Telnet)", f"tshark -r {pcap_path} -Y 'ftp || telnet' -T fields -e text 2>/dev/null | head -20"),
        ]

        lines = [f"=== Network Capture Analysis ({duration}s) ===\n"]

        for label, cmd in analyses:
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=20
                )
                output = result.stdout.strip()
                if output:
                    lines.append(f"--- {label} ---")
                    lines.append(output)
                    lines.append("")
            except Exception:
                pass

        if len(lines) == 1:
            lines.append("tshark not available or PCAP is empty.")

        try:
            os.unlink(pcap_path)
        except Exception:
            pass

        return "\n".join(lines)
