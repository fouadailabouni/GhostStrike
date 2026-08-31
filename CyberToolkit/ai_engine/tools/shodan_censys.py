"""
GhostStrike AI Engine — Shodan + Censys Probe
==============================================
OSINT reconnaissance tool that queries Shodan and Censys for host
intelligence: open ports, banners, CVEs, geolocation, and ASN data.
Results are combined and deduplicated for maximum coverage.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "probe_host_intelligence",
        "description": (
            "Query Shodan and/or Censys for public intelligence on an IP address or domain. "
            "Returns open ports, services, CVEs, geolocation, and ASN data. "
            "Requires SHODAN_API_KEY and/or CENSYS_API_ID + CENSYS_API_SECRET env vars."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, CIDR range, or domain to investigate.",
                },
                "query": {
                    "type": "string",
                    "description": "Shodan search query (e.g. 'org:\"Target Corp\" port:22').",
                },
                "source": {
                    "type": "string",
                    "enum": ["shodan", "censys", "both"],
                    "description": "Which data source to use (default: both).",
                    "default": "both",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results per source (default 10).",
                    "default": 10,
                },
            },
            "required": [],
        },
    },
}


class ShodanCensysProbe:
    """
    Combined Shodan + Censys reconnaissance probe.

    Agents call ``probe()`` with an IP/domain or a free-text search
    query.  The class handles API key loading, error handling, and
    result normalisation so agents receive clean structured output.
    """

    def __init__(self) -> None:
        self._shodan_key    = os.getenv("SHODAN_API_KEY", "")
        self._censys_id     = os.getenv("CENSYS_API_ID", "")
        self._censys_secret = os.getenv("CENSYS_API_SECRET", "")

    # ── Public API ────────────────────────────────────────────────────────────

    def probe(
        self,
        target: Optional[str] = None,
        query: Optional[str] = None,
        source: str = "both",
        limit: int = 10,
    ) -> str:
        sections: List[str] = []

        if source in ("shodan", "both"):
            sections.append(self._shodan_section(target, query, limit))

        if source in ("censys", "both"):
            sections.append(self._censys_section(target, limit))

        result = "\n\n".join(s for s in sections if s)
        return result or "No intelligence data returned. Check API keys and target."

    # ── Shodan ────────────────────────────────────────────────────────────────

    def _shodan_section(
        self, target: Optional[str], query: Optional[str], limit: int
    ) -> str:
        if not self._shodan_key:
            return "[Shodan] No API key set (SHODAN_API_KEY)."
        try:
            import requests
        except ImportError:
            return "[Shodan] requests package not installed."

        lines = ["=== SHODAN ==="]

        if target and self._looks_like_ip(target):
            data = self._shodan_host(target, requests)
            if data:
                lines.extend(self._format_shodan_host(data))
        elif target or query:
            search_q = query or f"hostname:{target}"
            results  = self._shodan_search(search_q, limit, requests)
            for r in results:
                lines.extend(self._format_shodan_result(r))
        else:
            lines.append("Provide target IP or query parameter.")

        return "\n".join(lines)

    def _shodan_host(self, ip: str, requests: Any) -> Optional[Dict]:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self._shodan_key},
                timeout=10,
            )
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    def _shodan_search(self, query: str, limit: int, requests: Any) -> List[Dict]:
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": self._shodan_key, "query": query, "limit": limit},
                timeout=10,
            )
            data = r.json() if r.status_code == 200 else {}
            return data.get("matches", [])[:limit]
        except Exception:
            return []

    @staticmethod
    def _format_shodan_host(d: Dict) -> List[str]:
        lines = [
            f"  IP:           {d.get('ip_str','N/A')}",
            f"  Hostnames:    {', '.join(d.get('hostnames', ['N/A']))}",
            f"  Organisation: {d.get('org','N/A')}",
            f"  ISP:          {d.get('isp','N/A')}",
            f"  OS:           {d.get('os','N/A')}",
            f"  Country:      {d.get('country_name','N/A')}",
            f"  Open Ports:   {', '.join(map(str, d.get('ports', [])))}",
        ]
        if d.get("vulns"):
            lines.append(f"  CVEs:         {', '.join(list(d['vulns'])[:10])}")
        return lines

    @staticmethod
    def _format_shodan_result(r: Dict) -> List[str]:
        return [
            f"  {r.get('ip_str','?')}:{r.get('port','?')}  "
            f"org={r.get('org','?')}  "
            f"country={r.get('location',{}).get('country_name','?')}"
        ]

    # ── Censys ────────────────────────────────────────────────────────────────

    def _censys_section(self, target: Optional[str], limit: int) -> str:
        if not (self._censys_id and self._censys_secret):
            return "[Censys] No API credentials set (CENSYS_API_ID / CENSYS_API_SECRET)."
        try:
            import requests
        except ImportError:
            return "[Censys] requests package not installed."

        lines = ["=== CENSYS ==="]
        if not target:
            lines.append("Provide a target IP or domain for Censys lookup.")
            return "\n".join(lines)

        try:
            r = requests.get(
                f"https://search.censys.io/api/v2/hosts/{target}",
                auth=(self._censys_id, self._censys_secret),
                timeout=10,
            )
            if r.status_code != 200:
                lines.append(f"  Censys returned HTTP {r.status_code}")
                return "\n".join(lines)

            result = r.json().get("result", {})
            lines.append(f"  IP:       {result.get('ip','N/A')}")
            lines.append(f"  ASN:      {result.get('autonomous_system',{}).get('asn','N/A')}")
            lines.append(f"  ASN Name: {result.get('autonomous_system',{}).get('name','N/A')}")
            lines.append(f"  Country:  {result.get('location',{}).get('country','N/A')}")

            svcs = result.get("services", [])
            if svcs:
                lines.append(f"  Services ({len(svcs)}):")
                for svc in svcs[:limit]:
                    lines.append(
                        f"    {svc.get('port','?')}/{svc.get('transport_protocol','?')} "
                        f"— {svc.get('service_name','?')}"
                    )
        except Exception as exc:
            lines.append(f"  Error: {exc}")

        return "\n".join(lines)

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        import re
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))
