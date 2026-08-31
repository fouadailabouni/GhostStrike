"""
GhostStrike AI Engine — MITRE ATT&CK Mapper
============================================
Maps free-text tool output and agent findings to MITRE ATT&CK Enterprise
technique IDs and tactic names.  Used by the Findings Extractor and the
Output Analyst agent to auto-populate structured findings JSON.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# ── Keyword → (Technique ID, Technique Name, Tactic) ─────────────────────────
_TECHNIQUE_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # pattern                               id            name                             tactic
    (r"(?i)nmap|port.scan|service.enum",   "T1046",  "Network Service Discovery",        "Discovery"),
    (r"(?i)dns.recon|zone.transfer|dnsrecon","T1018", "Remote System Discovery",          "Discovery"),
    (r"(?i)subdomain.enum|subfinder|amass","T1018",   "Remote System Discovery",          "Discovery"),
    (r"(?i)shodan|censys|banner.grab",     "T1046",   "Network Service Discovery",        "Discovery"),
    (r"(?i)ldap.enum|ldapdomaindump",      "T1087",   "Account Discovery",                "Discovery"),
    (r"(?i)smb.enum|smbclient|enum4linux", "T1135",   "Network Share Discovery",          "Discovery"),
    (r"(?i)osint|theHarvester|email.harvest","T1589", "Gather Victim Identity Info",      "Reconnaissance"),
    (r"(?i)whois|shodan.*host",            "T1590",   "Gather Victim Network Info",       "Reconnaissance"),
    (r"(?i)phishing|spear.?phish",         "T1566",   "Phishing",                         "Initial Access"),
    (r"(?i)sql.inject|sqlmap|sqli",        "T1190",   "Exploit Public-Facing Application","Initial Access"),
    (r"(?i)exploit.*vuln|metasploit|msfconsole","T1203","Exploitation for Client Exec",   "Execution"),
    (r"(?i)reverse.shell|bind.shell|nc.*-e","T1059",  "Command and Scripting Interpreter","Execution"),
    (r"(?i)python.*exec|perl.*exec|bash.*exec","T1059","Command and Scripting Interpreter","Execution"),
    (r"(?i)brute.?force|hydra|medusa|password.spray","T1110","Brute Force",               "Credential Access"),
    (r"(?i)hash.crack|hashcat|john.the.ripper","T1110","Brute Force",                     "Credential Access"),
    (r"(?i)mimikatz|lsass|credential.dump","T1003",   "OS Credential Dumping",            "Credential Access"),
    (r"(?i)kerberoast|asreproast|golden.ticket","T1558","Steal or Forge Kerberos Tickets","Credential Access"),
    (r"(?i)pass.the.hash|pth|ntlm.relay",  "T1550",  "Use Alternate Auth Material",      "Lateral Movement"),
    (r"(?i)lateral.mov|psexec|wmi.exec|winrm","T1021","Remote Services",                  "Lateral Movement"),
    (r"(?i)ssh.*lateral|rdesktop|xfreerdp","T1021",   "Remote Services",                  "Lateral Movement"),
    (r"(?i)privesc|privilege.esc|sudo.*exploit","T1068","Exploitation for Privilege Esc", "Privilege Escalation"),
    (r"(?i)suid.*exploit|capabilities.*exploit","T1548","Abuse Elevation Control Mech",   "Privilege Escalation"),
    (r"(?i)persistence|cron.*backdoor|registry.*run","T1053","Scheduled Task/Job",        "Persistence"),
    (r"(?i)webshell|php.*cmd|asp.*shell",  "T1505",   "Server Software Component",        "Persistence"),
    (r"(?i)data.exfil|exfiltrat|curl.*upload","T1041","Exfiltration Over C2 Channel",    "Exfiltration"),
    (r"(?i)dns.tunnel|iodine|dnscat",      "T1048",   "Exfiltration Over Alt Protocol",   "Exfiltration"),
    (r"(?i)c2|command.and.control|beacon|cobalt.strike","T1071","App Layer Protocol",     "Command and Control"),
    (r"(?i)xss|cross.site.scripting",      "T1059",   "Command and Scripting Interpreter","Execution"),
    (r"(?i)ssrf|server.side.request",      "T1190",   "Exploit Public-Facing Application","Initial Access"),
    (r"(?i)idor|insecure.direct.object",   "T1078",   "Valid Accounts",                   "Initial Access"),
    (r"(?i)jwt.*tamper|jwt.*forge|alg.*none","T1134",  "Access Token Manipulation",       "Privilege Escalation"),
    (r"(?i)cors.*misconfigur",             "T1190",   "Exploit Public-Facing Application","Initial Access"),
    (r"(?i)log.*clear|event.*wipe|siem.*evad","T1070", "Indicator Removal",               "Defense Evasion"),
    (r"(?i)av.*bypass|edr.*bypass|amsi",   "T1562",   "Impair Defenses",                  "Defense Evasion"),
    (r"(?i)obfuscat|base64.*exec|encode.*payload","T1027","Obfuscated Files or Info",     "Defense Evasion"),
    (r"(?i)firmware|binwalk|jtag|uart",    "T1542",   "Pre-OS Boot",                      "Persistence"),
    (r"(?i)bluetooth|ble.scan|zigbee",     "T1424",   "Network Service Scanning",         "Discovery"),
    (r"(?i)docker.*escape|container.*breakout","T1611","Escape to Host",                  "Privilege Escalation"),
    (r"(?i)cloud.*enum|aws.*enum|s3.*bucket","T1526", "Cloud Service Discovery",          "Discovery"),
    (r"(?i)memory.dump|volatility|memdump","T1005",   "Data from Local System",           "Collection"),
    (r"(?i)pcap|tcpdump|wireshark|tshark", "T1040",   "Network Sniffing",                 "Credential Access"),
]


class MitreMapper:
    """
    Scans free-text output for MITRE ATT&CK technique indicators.
    Returns a deduplicated list of matching techniques.
    """

    def map_output(self, text: str) -> List[Dict]:
        """
        Scan ``text`` and return a list of matched technique dicts:

        [{"id": "T1046", "name": "...", "tactic": "...", "url": "..."}, ...]
        """
        seen: Dict[str, Dict] = {}
        for pattern, tid, name, tactic in _TECHNIQUE_SIGNATURES:
            if re.search(pattern, text):
                if tid not in seen:
                    seen[tid] = {
                        "id":     tid,
                        "name":   name,
                        "tactic": tactic,
                        "url":    f"https://attack.mitre.org/techniques/{tid}/",
                    }
        return list(seen.values())

    def map_command(self, command: str) -> Optional[Dict]:
        """Return the first matching technique for a single command string."""
        hits = self.map_output(command)
        return hits[0] if hits else None

    def techniques_summary(self, techniques: List[Dict]) -> str:
        if not techniques:
            return "No MITRE ATT&CK techniques identified."
        lines = ["MITRE ATT&CK Techniques Identified:"]
        by_tactic: Dict[str, List[Dict]] = {}
        for t in techniques:
            by_tactic.setdefault(t["tactic"], []).append(t)
        for tactic, items in sorted(by_tactic.items()):
            lines.append(f"\n  [{tactic}]")
            for item in items:
                lines.append(f"    {item['id']} — {item['name']}")
        return "\n".join(lines)
