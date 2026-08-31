"""
GhostStrike AI Engine — NLP Router Agent
=========================================
Translates natural language task descriptions into ordered GhostStrike
module execution plans.  "I want to test the Active Directory environment"
→ returns an ordered list of modules with parameters.

Used by the GUI for the Natural Language Module Selection feature.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from ..model_provider import GhostStrikeModelProvider
from ..tracer import GhostStrikeTracer

_ROUTER_SYSTEM_PROMPT = """You are the GhostStrike Module Router.

Given a natural language description of a penetration testing task,
return an ordered execution plan as a JSON array of module objects.

Each module object must have:
{
  "module_name": "<script filename e.g. nmap_automation.sh>",
  "purpose": "<one line why this module runs at this step>",
  "params": {"KEY": "value"},
  "phase": "<Recon|Enum|Exploit|Post-Exploit|Report>"
}

Available GhostStrike modules:
- nmap_automation.sh, nmap_vulnerability_scanner.sh (Recon)
- dns_recon.sh, subdomain_enum.sh, snmp_enum.sh (Recon)
- owasp_top10_scanner.sh, sqlmap_automated_pentest.sh, jwt_token_manipulator.sh (Web)
- graphql_security_tester.sh, api_security_tester.sh, websocket_security_tester.sh (Web)
- active_directory_tester.sh, kerberos_attack_suite.sh, ntlm_relay_tester.sh (AD)
- password_attack_suite.sh, hash_analyzer_cracker.sh, password_spraying_campaign.sh (Credentials)
- wifi_penetration_tester.sh, bluetooth_scanner.sh (Wireless)
- aws_security_scanner.sh, azure_gcp_enumeration.sh, cloud_storage_bucket_tester.sh (Cloud)
- iot_firmware_analyzer.sh, iot_default_creds_scanner.sh, iot_mqtt_tester.sh (IoT)
- privilege_escalation_checker.sh, persistence_mechanisms.sh (Post-Exploit)
- metasploit_automation.sh (Exploit - LAB_ONLY)
- pentest_report_generator.sh (Report)

Return ONLY valid JSON array. No markdown. No explanation outside the JSON."""


class NLPRouterAgent:
    """
    Translates free-text task descriptions into ordered module execution plans.
    Does not inherit from GhostStrikeAgent — it is a single-shot LLM call.
    """

    def __init__(self, model_provider: GhostStrikeModelProvider) -> None:
        self._model = model_provider

    def route(self, task_description: str) -> List[Dict]:
        """
        Convert a natural language task description into an ordered module plan.

        Returns a list of dicts with keys: module_name, purpose, params, phase.
        Falls back to a sensible default plan on LLM failure.
        """
        resp = self._model.complete(
            messages=[{"role": "user", "content": task_description}],
            system_prompt=_ROUTER_SYSTEM_PROMPT,
        )
        raw = resp.get("content", "").strip()
        try:
            plan = json.loads(raw)
            if isinstance(plan, list):
                return plan
        except json.JSONDecodeError:
            pass
        return self._default_plan(task_description)

    def route_as_text(self, task_description: str) -> str:
        """Return the plan as formatted text for display."""
        plan = self.route(task_description)
        if not plan:
            return "Could not generate a module plan for this task."

        lines = [f"GhostStrike Execution Plan for: '{task_description}'\n"]
        current_phase = ""
        for i, step in enumerate(plan, 1):
            phase = step.get("phase", "")
            if phase != current_phase:
                current_phase = phase
                lines.append(f"\n  [{phase}]")
            module  = step.get("module_name", "?")
            purpose = step.get("purpose", "")
            params  = step.get("params", {})
            param_str = ", ".join(f"{k}={v}" for k, v in params.items()) if params else ""
            lines.append(f"  {i:2d}. {module}")
            if purpose:
                lines.append(f"      Purpose: {purpose}")
            if param_str:
                lines.append(f"      Params:  {param_str}")
        return "\n".join(lines)

    @staticmethod
    def _default_plan(task: str) -> List[Dict]:
        task_lower = task.lower()
        if any(k in task_lower for k in ["ad", "active directory", "domain", "kerberos"]):
            return [
                {"module_name": "nmap_automation.sh",       "purpose": "Network scan", "params": {}, "phase": "Recon"},
                {"module_name": "active_directory_tester.sh","purpose": "AD enumeration", "params": {}, "phase": "Enum"},
                {"module_name": "kerberos_attack_suite.sh", "purpose": "Kerberoast",  "params": {}, "phase": "Exploit"},
            ]
        if any(k in task_lower for k in ["web", "http", "api", "sql"]):
            return [
                {"module_name": "nmap_automation.sh",         "purpose": "Port scan",   "params": {}, "phase": "Recon"},
                {"module_name": "owasp_top10_scanner.sh",     "purpose": "OWASP checks","params": {}, "phase": "Enum"},
                {"module_name": "sqlmap_automated_pentest.sh","purpose": "SQLi test",   "params": {}, "phase": "Exploit"},
            ]
        return [
            {"module_name": "nmap_automation.sh",          "purpose": "Network scan",  "params": {}, "phase": "Recon"},
            {"module_name": "nmap_vulnerability_scanner.sh","purpose": "Vuln scan",    "params": {}, "phase": "Enum"},
            {"module_name": "privilege_escalation_checker.sh","purpose": "Privesc check","params":{}, "phase": "Post-Exploit"},
        ]
