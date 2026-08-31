"""
GhostStrike AI Engine — Findings Extractor
==========================================
Pipes raw tool output through the LLM to extract structured findings
and auto-populate the GhostStrike findings JSON with CVSS scores,
MITRE ATT&CK mappings, and remediation recommendations.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .mitre_mapper import MitreMapper

_EXTRACTOR_SYSTEM_PROMPT = """You are a professional penetration testing report analyst embedded in GhostStrike.

Given raw tool output from a security assessment, extract structured findings.

For each finding return a JSON object matching this exact schema:
{
  "title": "Short, precise title",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "cvss_score": 0.0-10.0,
  "description": "What was found and why it matters",
  "affected_asset": "IP, hostname, URL, or component",
  "evidence": "Relevant snippet from the tool output",
  "remediation": "Concrete fix recommendation",
  "references": ["CVE-XXXX-XXXX", "CWE-XXX", "OWASP reference if applicable"]
}

Return ONLY a JSON array of findings.  If no findings, return [].
Never wrap in markdown code fences.  Pure JSON only."""


class FindingsExtractor:
    """
    Extracts structured pentest findings from raw tool output using
    the configured LLM and enriches them with MITRE ATT&CK mappings.
    """

    def __init__(self, model_provider: Any) -> None:
        self._model = model_provider
        self._mitre = MitreMapper()

    def extract(
        self,
        tool_output: str,
        tool_name: str = "",
        target: str = "",
        engagement_id: str = "",
    ) -> List[Dict]:
        """
        Send tool output to the LLM and return a list of enriched finding dicts.
        Falls back to a keyword-based heuristic if the LLM call fails.
        """
        context = f"Tool: {tool_name}\nTarget: {target}\n\nOutput:\n{tool_output[:6000]}"

        try:
            resp = self._model.complete(
                messages=[{"role": "user", "content": context}],
                system_prompt=_EXTRACTOR_SYSTEM_PROMPT,
            )
            raw = resp.get("content", "").strip()
            findings = self._parse_json_findings(raw)
        except Exception:
            findings = self._heuristic_extract(tool_output, tool_name, target)

        enriched = []
        for finding in findings:
            finding = self._enrich(finding, tool_output, tool_name, engagement_id)
            enriched.append(finding)
        return enriched

    # ── Enrichment ────────────────────────────────────────────────────────────

    def _enrich(
        self,
        finding: Dict,
        raw_output: str,
        tool_name: str,
        engagement_id: str,
    ) -> Dict:
        techniques = self._mitre.map_output(
            finding.get("description", "") + " " + raw_output[:2000]
        )
        finding["mitre_techniques"] = techniques
        finding["mitre_summary"]    = self._mitre.techniques_summary(techniques)
        finding.setdefault("tool",          tool_name)
        finding.setdefault("engagement_id", engagement_id)
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        finding.setdefault("severity",   "INFO")
        finding.setdefault("cvss_score", self._severity_to_cvss(finding["severity"]))
        return finding

    # ── JSON parsing ──────────────────────────────────────────────────────────

    def _parse_json_findings(self, raw: str) -> List[Dict]:
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        # Try extracting first JSON array from mixed text
        match = re.search(r"\[[\s\S]+\]", raw)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return []

    # ── Heuristic fallback ───────────────────────────────────────────────────

    def _heuristic_extract(
        self, output: str, tool_name: str, target: str
    ) -> List[Dict]:
        findings: List[Dict] = []

        # Open ports
        for match in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", output):
            port, service = match.group(1), match.group(2)
            findings.append({
                "title":          f"Open Port {port}/tcp — {service}",
                "severity":       "INFO",
                "cvss_score":     0.0,
                "description":    f"Port {port} ({service}) is open on {target}.",
                "affected_asset": target,
                "evidence":       match.group(0),
                "remediation":    "Review whether this service is required; restrict with firewall if not.",
                "references":     [],
            })

        # CVE references
        for cve in re.findall(r"CVE-\d{4}-\d+", output):
            findings.append({
                "title":          f"CVE Reference Found: {cve}",
                "severity":       "HIGH",
                "cvss_score":     7.5,
                "description":    f"Tool output references {cve} against target {target}.",
                "affected_asset": target,
                "evidence":       cve,
                "remediation":    f"Review {cve} and apply vendor patches.",
                "references":     [cve],
            })

        # SQL errors
        if re.search(r"(?i)(sql syntax|mysql.*error|ora-\d{5}|psql.*error)", output):
            findings.append({
                "title":          "Potential SQL Injection Response",
                "severity":       "HIGH",
                "cvss_score":     8.0,
                "description":    "Database error strings detected in server response.",
                "affected_asset": target,
                "evidence":       output[:300],
                "remediation":    "Use parameterised queries; sanitise all user-supplied input.",
                "references":     ["CWE-89", "OWASP A03:2021"],
            })

        return findings

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}.get(
            severity.upper(), 0.0
        )
