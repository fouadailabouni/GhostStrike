"""
GhostStrike AI Engine — JavaScript Surface Analyzer
=====================================================
Fetches JavaScript files from a target URL and extracts API endpoints,
WebSocket URLs, GraphQL operations, authentication flows, and hidden
parameters for subsequent targeted testing.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "analyse_js_surface",
        "description": (
            "Fetch JavaScript files from a target URL and extract the attack surface: "
            "API endpoints, WebSocket URLs, GraphQL operations, hardcoded tokens, "
            "and hidden parameters. Essential for web application recon."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL (HTML page or direct JS file URL).",
                },
                "max_scripts": {
                    "type": "integer",
                    "description": "Max JS files to fetch and analyse (default 10).",
                    "default": 10,
                },
                "deep_scan": {
                    "type": "boolean",
                    "description": "If True, follow discovered JS import paths recursively.",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    },
}

# ── Extraction patterns ────────────────────────────────────────────────────────
_API_PATTERNS = [
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*['"`]([^'"`\s]{5,})['"`]""",
    r"""['"`]((?:/api/|/v\d/|/graphql|/rest/|/auth/)[^\s'"`?#]{3,})['"`]""",
    r"""url\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]""",
]
_WS_PATTERNS   = [r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`]+)['"`]"""]
_GQL_PATTERNS  = [r"""(?:query|mutation|subscription)\s+(\w+)\s*[({]"""]
_TOKEN_PATTERNS = [
    r"""(?:api[_-]?key|secret|token|password|auth|credential)\s*[:=]\s*['"`]([A-Za-z0-9\-_.+/]{8,})['"`]""",
]
_PARAM_PATTERNS = [r"""['"`](\w+)['"` ]*\s*:\s*(?:params|query|data|body)\["""]


class JsAnalyzer:
    """
    JavaScript attack surface extractor for web penetration testing.
    """

    def analyse(
        self,
        url: str,
        max_scripts: int = 10,
        deep_scan: bool = False,
    ) -> str:
        try:
            import requests
        except ImportError:
            return "Error: requests package not installed."

        session = requests.Session()
        session.headers["User-Agent"] = "GhostStrike-JS-Analyzer/3.0"

        # Collect script URLs from the page
        script_urls = self._collect_script_urls(url, session, max_scripts)
        if not script_urls:
            # Maybe the URL itself is a JS file
            script_urls = [url]

        endpoints:    Set[str] = set()
        ws_urls:      Set[str] = set()
        gql_ops:      Set[str] = set()
        token_hits:   List[str] = []
        param_hits:   Set[str] = set()

        for js_url in script_urls[:max_scripts]:
            try:
                resp = session.get(js_url, timeout=10, verify=False)
                if resp.status_code != 200:
                    continue
                content = resp.text
            except Exception:
                continue

            for pat in _API_PATTERNS:
                for match in re.findall(pat, content):
                    if len(match) > 3:
                        endpoints.add(match)

            for pat in _WS_PATTERNS:
                for match in re.findall(pat, content):
                    ws_urls.add(match)

            for pat in _GQL_PATTERNS:
                for match in re.findall(pat, content):
                    gql_ops.add(match)

            for pat in _TOKEN_PATTERNS:
                for match in re.findall(pat, content, re.IGNORECASE):
                    if not self._looks_like_variable(match):
                        token_hits.append(match[:60])

            for pat in _PARAM_PATTERNS:
                for match in re.findall(pat, content):
                    param_hits.add(match)

        lines = [
            f"=== JS Surface Analysis: {url} ===",
            f"Scripts analysed: {len(script_urls[:max_scripts])}",
            "",
        ]

        if endpoints:
            lines.append(f"--- API Endpoints ({len(endpoints)}) ---")
            for ep in sorted(endpoints)[:50]:
                lines.append(f"  {ep}")

        if ws_urls:
            lines.append(f"\n--- WebSocket URLs ({len(ws_urls)}) ---")
            for ws in sorted(ws_urls):
                lines.append(f"  {ws}")

        if gql_ops:
            lines.append(f"\n--- GraphQL Operations ({len(gql_ops)}) ---")
            for op in sorted(gql_ops):
                lines.append(f"  {op}")

        if token_hits:
            lines.append(f"\n--- Potential Hardcoded Secrets ({len(token_hits)}) ---")
            for tok in token_hits[:20]:
                lines.append(f"  [!] {tok}")

        if param_hits:
            lines.append(f"\n--- Hidden Parameters ({len(param_hits)}) ---")
            for p in sorted(param_hits)[:30]:
                lines.append(f"  {p}")

        if not any([endpoints, ws_urls, gql_ops, token_hits]):
            lines.append("No significant attack surface extracted.")

        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_script_urls(
        self, page_url: str, session, limit: int
    ) -> List[str]:
        try:
            resp = session.get(page_url, timeout=10, verify=False)
            if resp.status_code != 200:
                return []
        except Exception:
            return []

        from urllib.parse import urljoin
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        return [urljoin(page_url, s) for s in scripts[:limit]]

    @staticmethod
    def _looks_like_variable(s: str) -> bool:
        return bool(re.match(r"^[a-z_$][a-z0-9_$]*$", s, re.IGNORECASE))
