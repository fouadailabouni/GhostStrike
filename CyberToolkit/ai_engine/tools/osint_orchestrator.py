"""
GhostStrike AI Engine — OSINT Orchestrator
============================================
Orchestrates multi-source open-source intelligence gathering:
  • theHarvester    — emails, names, subdomains, IPs, banners
  • Google dorking  — custom dork queries via requests
  • Shodan          — internet-wide host scanning
  • DNS enumeration — brute-force and record walking
  • Certificate transparency — subdomain discovery via crt.sh

Results are consolidated and fed back to the AI agent for scope
expansion and targeted testing.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Dict, List, Optional

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "osint_recon",
        "description": (
            "Perform multi-source OSINT reconnaissance on a target domain or organisation. "
            "Combines theHarvester, Google dorking, DNS enumeration, and certificate transparency. "
            "Returns emails, subdomains, IP ranges, employee names, and technology stacks."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain (e.g. example.com) or organisation name.",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Sources to use: harvester, google_dork, dns, crt_sh. Default: all.",
                },
                "dork_queries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom Google dork queries to run (optional).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per source (default 50).",
                    "default": 50,
                },
            },
            "required": ["target"],
        },
    },
}

_DEFAULT_DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xls OR filetype:xlsx',
    'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
    'site:{domain} "password" OR "passwd" OR "credentials"',
    '"@{domain}" email',
    'site:{domain} ext:env OR ext:config OR ext:bak',
    'site:{domain} inurl:api OR inurl:swagger OR inurl:openapi',
]


class OsintOrchestrator:
    """
    Multi-source OSINT orchestrator used by the GhostStrike Bug Bounty
    and OSINT agents.  Falls back gracefully when external tools or API
    keys are unavailable.
    """

    def __init__(self) -> None:
        self._shodan_key = os.getenv("SHODAN_API_KEY", "")
        self._google_key = os.getenv("GOOGLE_SEARCH_API_KEY", "")
        self._google_cx  = os.getenv("GOOGLE_SEARCH_CX", "")

    # ── Public API ────────────────────────────────────────────────────────────

    def recon(
        self,
        target: str,
        sources: Optional[List[str]] = None,
        dork_queries: Optional[List[str]] = None,
        limit: int = 50,
    ) -> str:
        sources = sources or ["harvester", "google_dork", "dns", "crt_sh"]
        sections: List[str] = [f"=== OSINT Reconnaissance: {target} ===\n"]

        if "harvester" in sources:
            sections.append(self._run_harvester(target, limit))

        if "crt_sh" in sources:
            sections.append(self._query_crt_sh(target))

        if "dns" in sources:
            sections.append(self._dns_recon(target))

        if "google_dork" in sources:
            queries = dork_queries or [q.format(domain=target) for q in _DEFAULT_DORKS]
            sections.append(self._google_dork(target, queries))

        return "\n\n".join(s for s in sections if s.strip())

    # ── theHarvester ─────────────────────────────────────────────────────────

    def _run_harvester(self, target: str, limit: int) -> str:
        lines = ["--- theHarvester ---"]
        harvesters = ["bing", "certspotter", "dnsdumpster", "hackertarget"]

        for source in harvesters:
            cmd = f"theHarvester -d {target} -b {source} -l {limit} -f /tmp/gs_harvester_{source}"
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=60
                )
                output = result.stdout
                if output.strip():
                    lines.append(f"\n[{source}]")
                    # Extract interesting lines only
                    for line in output.splitlines():
                        stripped = line.strip()
                        if stripped and any(
                            kw in stripped.lower()
                            for kw in ["@", ".", target.split(".")[0]]
                        ):
                            lines.append(f"  {stripped}")
            except subprocess.TimeoutExpired:
                lines.append(f"  [{source}] timed out")
            except FileNotFoundError:
                lines.append("  theHarvester not installed. Run: pip install theHarvester")
                break

        return "\n".join(lines)

    # ── Certificate Transparency ─────────────────────────────────────────────

    def _query_crt_sh(self, target: str) -> str:
        lines = ["--- Certificate Transparency (crt.sh) ---"]
        try:
            import requests
            resp = requests.get(
                f"https://crt.sh/?q=%.{target}&output=json",
                timeout=15,
                headers={"User-Agent": "GhostStrike-OSINT/3.0"},
            )
            if resp.status_code != 200:
                return "--- Certificate Transparency ---\n  crt.sh returned non-200."
            data  = resp.json()
            subs  = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if target in sub:
                        subs.add(sub)
            lines.append(f"  Found {len(subs)} unique subdomains:")
            for sub in sorted(subs)[:80]:
                lines.append(f"    {sub}")
        except ImportError:
            lines.append("  requests not installed.")
        except Exception as exc:
            lines.append(f"  Error: {exc}")
        return "\n".join(lines)

    # ── DNS Recon ─────────────────────────────────────────────────────────────

    def _dns_recon(self, target: str) -> str:
        lines = ["--- DNS Reconnaissance ---"]
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for rtype in record_types:
            try:
                result = subprocess.run(
                    f"dig +short {rtype} {target}",
                    shell=True, capture_output=True, text=True, timeout=10,
                )
                output = result.stdout.strip()
                if output:
                    lines.append(f"  {rtype}: {output.replace(chr(10), ', ')}")
            except Exception:
                pass

        # Zone transfer attempt
        try:
            ns_result = subprocess.run(
                f"dig +short NS {target}",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            for ns in ns_result.stdout.strip().splitlines():
                ns = ns.strip().rstrip(".")
                zt = subprocess.run(
                    f"dig AXFR {target} @{ns}",
                    shell=True, capture_output=True, text=True, timeout=15,
                )
                if "XFR size" in zt.stdout:
                    lines.append(f"\n  [!] Zone transfer SUCCESSFUL from {ns}:")
                    lines.append(zt.stdout[:1000])
        except Exception:
            pass

        return "\n".join(lines)

    # ── Google Dorking ────────────────────────────────────────────────────────

    def _google_dork(self, target: str, queries: List[str]) -> str:
        lines = ["--- Google Dorking ---"]
        if not (self._google_key and self._google_cx):
            lines.append("  GOOGLE_SEARCH_API_KEY / GOOGLE_SEARCH_CX not set.")
            lines.append("  Manual dork queries for operator:")
            for q in queries[:10]:
                lines.append(f"    https://www.google.com/search?q={q.replace(' ', '+')}")
            return "\n".join(lines)

        try:
            import requests
            for query in queries[:6]:
                resp = requests.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={"key": self._google_key, "cx": self._google_cx, "q": query, "num": 5},
                    timeout=10,
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                items = data.get("items", [])
                if items:
                    lines.append(f"\n  Query: {query}")
                    for item in items:
                        lines.append(f"    {item.get('link','')}")
        except Exception as exc:
            lines.append(f"  Error: {exc}")

        return "\n".join(lines)
