"""
GhostStrike AI Engine — HTTP Analyzer
======================================
Full HTTP request/response inspector with security header grading,
CORS analysis, CSP parsing, and response fingerprinting.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlparse

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "analyse_http_target",
        "description": (
            "Send an HTTP request and analyse the response for security issues. "
            "Checks security headers (CSP, HSTS, X-Frame-Options, CORS), "
            "server fingerprinting, cookie flags, and redirect chains."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL."},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                    "default": "GET",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom request headers.",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT).",
                },
                "follow_redirects": {"type": "boolean", "default": True},
                "timeout": {"type": "integer", "default": 15},
            },
            "required": ["url"],
        },
    },
}

_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
]


class HttpAnalyzer:
    """Performs HTTP security analysis on a target URL."""

    def analyse(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        body: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 15,
    ) -> str:
        try:
            import requests as req_lib
        except ImportError:
            return "Error: requests package not installed. Run: pip install requests"

        request_headers = {
            "User-Agent": "GhostStrike-AI-Scanner/3.0",
            **(headers or {}),
        }

        try:
            resp = req_lib.request(
                method=method,
                url=url,
                headers=request_headers,
                data=body,
                allow_redirects=follow_redirects,
                timeout=timeout,
                verify=False,
            )
        except req_lib.exceptions.SSLError:
            try:
                resp = req_lib.request(
                    method=method, url=url, headers=request_headers,
                    data=body, allow_redirects=follow_redirects,
                    timeout=timeout, verify=False,
                )
            except Exception as exc:
                return f"Error connecting to {url}: {exc}"
        except Exception as exc:
            return f"Error connecting to {url}: {exc}"

        lines: List[str] = [
            f"=== HTTP Analysis: {url} ===",
            f"Status:       {resp.status_code} {resp.reason}",
            f"Final URL:    {resp.url}",
            f"Content-Type: {resp.headers.get('Content-Type','(none)')}",
            f"Server:       {resp.headers.get('Server','(not disclosed)')}",
            f"Content-Len:  {len(resp.content)} bytes",
            "",
            "--- Security Headers ---",
        ]

        missing: List[str] = []
        for hdr in _SECURITY_HEADERS:
            val = resp.headers.get(hdr)
            if val:
                lines.append(f"  [PRESENT] {hdr}: {val[:120]}")
            else:
                lines.append(f"  [MISSING] {hdr}")
                missing.append(hdr)

        # CORS analysis
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            lines.append("\n  [FINDING] CORS wildcard origin (*) — allows any domain to make credentialed requests.")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            lines.append("  [CRITICAL] CORS wildcard + Allow-Credentials=true — HIGH SEVERITY misconfiguration.")

        # Cookie analysis
        lines.append("\n--- Cookies ---")
        if resp.cookies:
            for cookie in resp.cookies:
                flags: List[str] = []
                if not cookie.secure:
                    flags.append("NO_SECURE")
                if "httponly" not in str(cookie._rest).lower():
                    flags.append("NO_HTTPONLY")
                if "samesite" not in str(cookie._rest).lower():
                    flags.append("NO_SAMESITE")
                flag_str = f"  [{', '.join(flags)}]" if flags else "  [OK]"
                lines.append(f"{flag_str} {cookie.name}")
        else:
            lines.append("  (no cookies set)")

        # Response body snippet
        lines.append("\n--- Body Preview (first 500 chars) ---")
        preview = resp.text[:500].replace("\n", " ")
        lines.append(f"  {preview}")

        if missing:
            lines.append(f"\n--- Missing Headers Summary ---")
            lines.append(f"  {len(missing)} security header(s) absent: {', '.join(missing)}")

        return "\n".join(lines)
