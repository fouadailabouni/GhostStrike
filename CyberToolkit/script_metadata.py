"""
GhostStrike - Complete Script Metadata Database
Contains parameters, descriptions, expected output, quality status, and dependencies
for all 103 penetration testing scripts.
"""

# Quality ratings
GOOD = "GOOD"
PARTIAL = "PARTIAL"
NEEDS_WORK = "NEEDS_WORK"

SCRIPT_DATABASE = {
    # ═══════════════════════════════════════════════════════════════
    # 00-Framework-Core (5 scripts)
    # ═══════════════════════════════════════════════════════════════
    "authorization_framework.sh": {
        "name": "Authorization Framework",
        "category": "00-Framework-Core",
        "description": "Enforces authorization, scope validation, kill switch, safe mode, and audit logging for pentest operations.",
        "params": [
            {"name": "command", "type": "select", "required": True,
             "options": ["setup_auth", "setup_scope", "safe_mode_on", "safe_mode_off", "kill_switch_on", "kill_switch_off", "audit_log", "validate", "help"],
             "help": "Framework command to execute"},
        ],
        "extra_args_help": "Additional arguments depending on command (e.g., validate <script> <target>)",
        "dependencies": ["jq"],
        "quality": GOOD,
        "expected_output": (
            "Setup commands create config files (.auth_config.json, .scope_config.json).\n"
            "validate: Returns PASS/FAIL for authorization checks.\n"
            "audit_log: Shows CSV-formatted audit trail of all operations.\n"
            "kill_switch_on/off: Enables/disables emergency stop for all toolkit operations."
        ),
    },

    "pentest_roadmap.sh": {
        "name": "Pentest Roadmap",
        "category": "00-Framework-Core",
        "description": "Interactive guided workflow that walks you step-by-step through a penetration test. Supports network, webapp, wireless, AD, cloud, IoT types.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": False, "help": "Target IP or range"},
            {"name": "--type", "type": "text", "required": False, "help": "Pentest type: network|webapp|wireless|activedir|cloud|iot|full"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": [],
        "quality": GOOD,
        "expected_output": "Step-by-step guided pentest workflow with progress tracking.",
    },

    "mitre_attack_framework.sh": {
        "name": "MITRE ATT&CK Framework",
        "category": "00-Framework-Core",
        "description": "Maps penetration testing activities to MITRE ATT&CK framework techniques, generates reports and heatmaps.",
        "params": [
            {"name": "command", "type": "select", "required": True,
             "options": ["init", "map", "info", "report", "heatmap", "detections", "coverage", "help"],
             "help": "Framework command"},
        ],
        "extra_args_help": "map <activity> [target] [tool] | info <technique_id> | report <scan_id> ...",
        "dependencies": ["jq"],
        "quality": GOOD,
        "expected_output": (
            "init: Creates ATT&CK mapping database.\n"
            "map: Maps activity to MITRE technique (e.g., 'port_scan' -> T1046).\n"
            "info: Shows technique details (tactic, description, detection).\n"
            "report: Generates HTML coverage report with technique breakdown.\n"
            "heatmap: Visual ASCII heatmap of technique coverage."
        ),
    },
    "json_output_framework.sh": {
        "name": "JSON Output Framework",
        "category": "00-Framework-Core",
        "description": "Standardized JSON output format for all testing scripts with findings management and CSV export.",
        "params": [
            {"name": "command", "type": "select", "required": True,
             "options": ["init", "add_finding", "generate", "export_csv", "validate", "help"],
             "help": "Framework command"},
        ],
        "extra_args_help": "init <script> <target> [output_dir] | add_finding <title> <desc> <severity> ...",
        "dependencies": ["jq"],
        "quality": GOOD,
        "expected_output": (
            "init: Creates JSON report structure file.\n"
            "add_finding: Appends vulnerability finding with CVSS, CVE, MITRE mapping.\n"
            "generate: Outputs complete JSON report with all findings and risk score.\n"
            "export_csv: Converts findings to CSV format.\n"
            "validate: Checks JSON structure validity."
        ),
    },
    "ci_linting_framework.sh": {
        "name": "CI/CD Linting Framework",
        "category": "00-Framework-Core",
        "description": "Automated CI/linting pipeline with ShellCheck, BATS tests, security checks, and GitHub Actions workflow generation.",
        "params": [
            {"name": "command", "type": "select", "required": True,
             "options": ["init", "shellcheck", "test", "security", "json", "full", "pipeline", "report", "help"],
             "help": "Pipeline command"},
        ],
        "extra_args_help": "Optional [directory] for shellcheck/security/json/full/pipeline commands",
        "dependencies": ["shellcheck", "bats", "jq", "curl", "git"],
        "quality": GOOD,
        "expected_output": (
            "init: Creates .shellcheckrc and test directory structure.\n"
            "shellcheck: Runs ShellCheck on all .sh files, reports warnings/errors.\n"
            "test: Executes BATS test suite.\n"
            "security: Checks for hardcoded credentials, missing disclaimers.\n"
            "full: Runs all checks and generates HTML report.\n"
            "pipeline: Generates GitHub Actions CI workflow YAML."
        ),
    },
    "framework_tester.sh": {
        "name": "Framework Tester",
        "category": "00-Framework-Core",
        "description": "Comprehensive testing of all framework components with pass/fail tracking and HTML report generation.",
        "params": [],
        "extra_args_help": "No arguments needed - runs all tests automatically",
        "dependencies": ["jq"],
        "quality": GOOD,
        "expected_output": (
            "Runs syntax validation and functional tests on all framework scripts.\n"
            "Output: [PASS] or [FAIL] for each test case.\n"
            "Generates HTML test report with summary statistics.\n"
            "Example: 'Testing authorization_framework.sh... [PASS] setup_auth [PASS] validate'"
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 01-Network-Security (12 scripts)
    # ═══════════════════════════════════════════════════════════════

    "netdiscover_automation.sh": {
        "name": "Network Device Discovery",
        "category": "01-Network-Security",
        "description": "Discovers all devices on the local network using ARP scanning, netdiscover, and nmap ping sweep with OS fingerprinting.",
        "params": [
            {"name": "-r/--range", "type": "text", "required": False, "help": "IP range (auto-detected if empty)"},
            {"name": "-i/--interface", "type": "text", "required": False, "help": "Network interface (auto-detected)"},
            {"name": "-m/--mode", "type": "text", "required": False, "help": "Scan mode: quick|full|stealth"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "arp-scan (optional)", "netdiscover (optional)"],
        "quality": GOOD,
        "expected_output": "Discovers all live hosts with IP, MAC, vendor, OS, and open ports.",
    },

    "mitm_attack_suite.sh": {
        "name": "MITM Attack Suite",
        "category": "01-Network-Security",
        "description": "End-to-end Man-in-the-Middle testing: ARP spoofing, traffic capture, credential sniffing, DNS poisoning.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP address"},
            {"name": "-g/--gateway", "type": "text", "required": False, "help": "Gateway IP (auto-detected)"},
            {"name": "-i/--interface", "type": "text", "required": False, "help": "Network interface"},
            {"name": "-m/--mode", "type": "text", "required": False, "help": "Mode: recon|arp|dns|sniff|full"},
            {"name": "-d/--duration", "type": "text", "required": False, "help": "Capture duration seconds (default: 120)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["arpspoof", "tcpdump", "tshark", "dsniff (optional)", "ettercap (optional)"],
        "quality": GOOD,
        "expected_output": "ARP spoofing, traffic capture, credential extraction, protocol analysis report.",
    },

    "dns_recon.sh": {
        "name": "DNS Reconnaissance",
        "category": "01-Network-Security",
        "description": "Comprehensive DNS reconnaissance: record enumeration, zone transfers, cache snooping, DNSSEC/SPF/DMARC checks, WHOIS lookup.",
        "params": [
            {"name": "domain", "type": "text", "required": True, "help": "Target domain name (e.g., example.com)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory path"},
            {"name": "-T/--timeout", "type": "text", "required": False, "help": "DNS query timeout in seconds"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Enable verbose output"},
        ],
        "dependencies": ["dig", "nslookup", "host", "whois", "curl"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: DNS Records - A, AAAA, MX, NS, TXT, SOA, CNAME records listed.\n"
            "Phase 2: Zone Transfer - Attempts AXFR against each nameserver.\n"
            "Phase 3: Cache Snooping - Tests for DNS cache poisoning vectors.\n"
            "Phase 4: Reverse DNS - PTR record lookups.\n"
            "Phase 5: DNSSEC/SPF/DMARC validation results.\n"
            "Phase 6: WHOIS registration data.\n"
            "Output saved to: dns_recon_<timestamp>/ directory."
        ),
    },
    "nmap_automation.sh": {
        "name": "Nmap Advanced Scanner",
        "category": "01-Network-Security",
        "description": "Full nmap automation with ALL scan types (SYN/Connect/ACK/FIN/Xmas/Null/SCTP/Idle), timing T0-T5, NSE script categories, evasion (fragmentation/decoys/source-port/MAC spoofing), UDP, OS/version detection, and 15+ NSE enumeration categories.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP, hostname, CIDR, or range"},
            {"name": "--scan", "type": "select", "required": False, "options": ["syn", "connect", "ack", "window", "maimon", "null", "fin", "xmas", "idle", "sctp-init", "sctp-cookie", "ip-proto", "ping", "list"], "help": "Scan type"},
            {"name": "-p/--ports", "type": "text", "required": False, "help": "Port range (e.g., 22,80,443 or 1-1024 or -)"},
            {"name": "-T/--timing", "type": "select", "required": False, "options": ["0", "1", "2", "3", "4", "5"], "help": "Timing: 0=Paranoid 1=Sneaky 2=Polite 3=Normal 4=Aggressive 5=Insane"},
            {"name": "-sV/--version", "type": "flag", "required": False, "help": "Enable service/version detection"},
            {"name": "-O/--os-detect", "type": "flag", "required": False, "help": "Enable OS detection"},
            {"name": "-A/--aggressive", "type": "flag", "required": False, "help": "Aggressive mode (-O -sV -sC --traceroute)"},
            {"name": "-sU/--udp", "type": "flag", "required": False, "help": "Enable UDP scan"},
            {"name": "--scripts", "type": "text", "required": False, "help": "NSE scripts (e.g., vuln,exploit,safe,brute,http-enum)"},
            {"name": "-f/--fragment", "type": "flag", "required": False, "help": "Fragment packets for evasion"},
            {"name": "-D/--decoys", "type": "text", "required": False, "help": "Decoy addresses (RND:10 or IPs)"},
            {"name": "-Pn/--no-ping", "type": "flag", "required": False, "help": "Skip host discovery"},
        ],
        "dependencies": ["nmap"],
        "quality": GOOD,
        "expected_output": (
            "7-phase scan: host discovery, port scan (chosen type), UDP, version/OS,\n"
            "NSE scripts, vulnerability scan, comprehensive NSE categories (15 protocol-\n"
            "specific categories: HTTP, SMB, SSL, SSH, DNS, FTP, SNMP, MySQL, MSSQL,\n"
            "RDP, SMTP, LDAP, NFS, VNC). All output in TXT+XML+grepable formats.\n"
            "Full scan report with open ports, vulns, and CVE references."
        ),
    },
    "nmap_vulnerability_scanner.sh": {
        "name": "Nmap Vuln & Exploit Scanner",
        "category": "01-Network-Security",
        "description": "18-phase deep vulnerability & exploitation scanner: CVE matching, 40+ exploit NSE scripts (EternalBlue, SambaCry, Shellshock, Heartbleed, Drupalgeddon, BlueKeep, backdoors), protocol-specific vulns, brute force, malware detection.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP, hostname, or CIDR range"},
            {"name": "-p/--ports", "type": "text", "required": False, "help": "Port specification"},
            {"name": "-T/--timing", "type": "select", "required": False, "options": ["0", "1", "2", "3", "4", "5"], "help": "Timing template"},
            {"name": "--skip-exploit", "type": "flag", "required": False, "help": "Skip exploitation scripts (safe mode)"},
            {"name": "--skip-brute", "type": "flag", "required": False, "help": "Skip brute force scripts"},
            {"name": "-Pn/--no-ping", "type": "flag", "required": False, "help": "Skip host discovery"},
            {"name": "-f/--fragment", "type": "flag", "required": False, "help": "Fragment packets for evasion"},
        ],
        "dependencies": ["nmap"],
        "quality": GOOD,
        "expected_output": (
            "18-phase vulnerability scan with TXT+XML per phase:\n"
            "Phase 1: Service/OS fingerprinting\n"
            "Phase 2: General vuln scan  |  Phase 3: CVE database (vulners)\n"
            "Phase 4: SMB (MS17-010, MS08-067, SambaCry, DoublePulsar)\n"
            "Phase 5: HTTP (Struts, Drupalgeddon, Shellshock, 20+ web vulns)\n"
            "Phase 6: SSH  |  Phase 7: SSL/TLS (Heartbleed, POODLE, Logjam)\n"
            "Phase 8: FTP (vsftpd/ProFTPD backdoors)\n"
            "Phase 9: Databases (MySQL, MSSQL, PostgreSQL, MongoDB, Redis)\n"
            "Phase 10-13: DNS, SNMP, Mail, RDP\n"
            "Phase 14-18: Auth/brute, exploit, malware, backdoor, intrusive\n"
            "Final report with CVE list, vuln count, recommendations."
        ),
    },
    "nmap_waf_bypass.sh": {
        "name": "Nmap WAF Bypass Scanner",
        "category": "01-Network-Security",
        "description": "Nmap scanning with WAF detection and evasion: fragmentation, decoys, source port manipulation, timing evasion, idle scan.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target IP or hostname"},
            {"name": "-t/--type", "type": "select", "required": False, "options": ["basic", "stealth", "comprehensive"], "help": "Scan type"},
            {"name": "-p/--ports", "type": "text", "required": False, "help": "Port range (e.g., 1-1000)"},
            {"name": "-s/--stealth", "type": "select", "required": False, "options": ["1", "2", "3"], "help": "Stealth level (1-3)"},
            {"name": "-T/--timing", "type": "select", "required": False, "options": ["0", "1", "2", "3", "4", "5"], "help": "Nmap timing template"},
            {"name": "-z/--zombie", "type": "text", "required": False, "help": "Zombie host for idle scan"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "masscan (optional)"],
        "quality": GOOD,
        "expected_output": (
            "WAF Detection: Identifies WAF presence (ModSecurity, Cloudflare, etc.)\n"
            "Evasion Results: Shows which bypass techniques succeeded/failed.\n"
            "Scan Results: Open ports found through each evasion method.\n"
            "Comparison: Normal scan vs. evasion scan port differences."
        ),
    },
    "service_discovery.sh": {
        "name": "Service Discovery",
        "category": "01-Network-Security",
        "description": "Multi-phase network service discovery: port scan, version detection, banner grabbing, web/SSL/DB enumeration, OS fingerprinting.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target IP or hostname"},
            {"name": "-p/--ports", "type": "text", "required": False, "help": "Port range (default: 1-65535)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-t/--threads", "type": "text", "required": False, "help": "Number of threads"},
            {"name": "-T/--timeout", "type": "text", "required": False, "help": "Connection timeout in seconds"},
            {"name": "-s/--scan-type", "type": "select", "required": False, "options": ["tcp", "udp", "both"], "help": "Scan type"},
            {"name": "-b/--banner-grab", "type": "flag", "required": False, "help": "Enable banner grabbing"},
        ],
        "dependencies": ["nmap", "nc", "telnet", "curl", "wget", "openssl"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Port Scan - Open TCP/UDP ports listed.\n"
            "Phase 2: Version Detection - Service names and version numbers.\n"
            "Phase 3: Banner Grabbing - Raw service banners via netcat.\n"
            "Phase 4: Web Enumeration - HTTP headers, technologies detected.\n"
            "Phase 5: SSL Certificate Analysis - Cert details, expiry, chain.\n"
            "Phase 6-9: Database, OS, Vulnerability detection.\n"
            "Final consolidated report with all findings."
        ),
    },
    "subdomain_enum.sh": {
        "name": "Subdomain Enumeration",
        "category": "01-Network-Security",
        "description": "Subdomain discovery via DNS brute-force, certificate transparency logs, zone transfer, reverse DNS, and takeover detection.",
        "params": [
            {"name": "domain", "type": "text", "required": True, "help": "Target domain (e.g., example.com)"},
            {"name": "-w/--wordlist", "type": "text", "required": False, "help": "Custom wordlist file path"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-t/--threads", "type": "text", "required": False, "help": "Number of threads"},
            {"name": "-d/--dns", "type": "text", "required": False, "help": "Custom DNS servers"},
        ],
        "dependencies": ["dig", "nslookup", "host", "curl"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: DNS Brute Force - Tests ~200 common subdomains.\n"
            "Phase 2: Certificate Transparency - Queries crt.sh for issued certs.\n"
            "Phase 3: Zone Transfer - Attempts AXFR on each nameserver.\n"
            "Phase 4: Reverse DNS - PTR record lookups.\n"
            "Phase 5: Subdomain Takeover Check - Tests CNAME for vulnerable services.\n"
            "Output: Deduplicated list of discovered subdomains with IPs."
        ),
    },
    "snmp_enum.sh": {
        "name": "SNMP Enumeration",
        "category": "01-Network-Security",
        "description": "SNMP enumeration: community string brute-force, system info, network interfaces, processes, storage, users, software inventory.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target IP address"},
            {"name": "-c/--community", "type": "text", "required": False, "help": "Community string list (comma-separated)"},
            {"name": "-f/--community-file", "type": "text", "required": False, "help": "Community string wordlist file"},
            {"name": "-v/--version", "type": "select", "required": False, "options": ["1", "2c", "3"], "help": "SNMP version"},
            {"name": "-p/--port", "type": "text", "required": False, "help": "SNMP port (default: 161)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["snmpwalk", "snmpget", "snmp-check (optional)", "nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: SNMP Service Discovery - Port scan for SNMP (161/162).\n"
            "Phase 2: Community String Testing - Tests public/private/common strings.\n"
            "Phase 3: System Information - sysDescr, sysUpTime, sysContact.\n"
            "Phase 4: Network Interfaces - Interface names, IPs, MAC addresses.\n"
            "Phase 5: Running Processes - Process list via hrSWRunName OID.\n"
            "Phase 6: Users/Software - Installed packages and user accounts."
        ),
    },
    "ssl_tls_analyzer.sh": {
        "name": "SSL/TLS Analyzer",
        "category": "01-Network-Security",
        "description": "SSL/TLS certificate and protocol analysis: cert info, chain verification, protocol testing, cipher suites, vulnerability checks.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target hostname or IP"},
            {"name": "-p/--port", "type": "text", "required": False, "help": "Port (default: 443)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
            {"name": "--no-vuln-check", "type": "flag", "required": False, "help": "Skip vulnerability checks"},
        ],
        "dependencies": ["openssl", "curl", "nmap"],
        "quality": GOOD,
        "expected_output": (
            "Certificate Info: Subject, Issuer, Validity dates, SANs, Key size.\n"
            "Chain Verification: Certificate chain validation result.\n"
            "Protocol Support: SSLv3, TLS 1.0/1.1/1.2/1.3 enabled/disabled.\n"
            "Cipher Suites: List of supported ciphers with strength rating.\n"
            "Vulnerabilities: Heartbleed, POODLE, CCS Injection, HSTS status.\n"
            "Risk Rating: Overall SSL/TLS security grade."
        ),
    },
    "network_traffic_analyzer.sh": {
        "name": "Network Traffic Analyzer",
        "category": "01-Network-Security",
        "description": "Network traffic capture and analysis: tcpdump capture, protocol breakdown, endpoint analysis, anomaly detection, flow analysis.",
        "params": [
            {"name": "-i/--interface", "type": "text", "required": True, "help": "Network interface (e.g., eth0, wlan0)"},
            {"name": "-d/--duration", "type": "text", "required": False, "help": "Capture duration in seconds"},
            {"name": "-f/--filter", "type": "text", "required": False, "help": "BPF filter expression"},
            {"name": "-c/--capture-file", "type": "text", "required": False, "help": "Existing PCAP file to analyze"},
            {"name": "-a/--analyze-only", "type": "flag", "required": False, "help": "Analyze existing capture only"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["tcpdump", "tshark", "netstat/ss", "capinfos (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Capture: Saves PCAP file for specified duration.\n"
            "Protocol Analysis: Breakdown by protocol (TCP/UDP/ICMP/ARP/DNS/HTTP).\n"
            "Endpoint Analysis: Top talkers by IP with packet counts.\n"
            "Anomaly Detection: Port scans, cleartext auth, large transfers flagged.\n"
            "Flow Analysis: Connection state summary.\n"
            "Requires root/sudo for live capture."
        ),
    },
    "firewall_rule_tester.sh": {
        "name": "Firewall Rule Tester",
        "category": "01-Network-Security",
        "description": "Firewall rule assessment: connectivity, port filtering, stealth techniques, protocol-specific tests, rate limiting detection.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP or hostname"},
            {"name": "-p/--ports", "type": "text", "required": False, "help": "Port range to test"},
            {"name": "--type", "type": "select", "required": False, "options": ["basic", "stealth", "comprehensive"], "help": "Test type"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "nc", "telnet (optional)", "hping3 (optional)", "curl", "ping"],
        "quality": GOOD,
        "expected_output": (
            "Connectivity: ICMP ping and traceroute results.\n"
            "Port Filtering: Per-port open/closed/filtered status.\n"
            "Stealth Tests: SYN, ACK, FIN, Xmas scan results compared.\n"
            "Protocol Tests: HTTP, DNS, SMTP response through firewall.\n"
            "Rate Limiting: Detection of connection rate throttling.\n"
            "Summary: Firewall rule effectiveness assessment."
        ),
    },
    "vpn_security_assessment.sh": {
        "name": "VPN Security Assessment",
        "category": "01-Network-Security",
        "description": "VPN security assessment for OpenVPN, IPSec, PPTP, L2TP, and WireGuard with protocol-specific vulnerability testing.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "VPN server IP or hostname"},
            {"name": "--type", "type": "select", "required": False, "options": ["openvpn", "ipsec", "pptp", "l2tp", "wireguard"], "help": "VPN protocol type"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "ike-scan (optional)", "curl", "dig", "openssl"],
        "quality": GOOD,
        "expected_output": (
            "Service Detection: VPN service identification on common ports.\n"
            "Protocol Analysis: Protocol-specific vulnerability checks.\n"
            "Cipher Assessment: Encryption strength evaluation.\n"
            "Leak Testing: DNS leak and IPv6 leak detection.\n"
            "Recommendations: Security improvement suggestions per protocol."
        ),
    },
    "system_config_audit.sh": {
        "name": "System Configuration Audit",
        "category": "01-Network-Security",
        "description": "Local system configuration security audit: users, network, services, filesystem, kernel hardening parameters.",
        "params": [
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose mode"},
            {"name": "-q/--quick", "type": "flag", "required": False, "help": "Quick scan (skip heavy checks)"},
            {"name": "-r/--remediation", "type": "flag", "required": False, "help": "Include remediation steps"},
            {"name": "--no-network", "type": "flag", "required": False, "help": "Skip network checks"},
            {"name": "--no-users", "type": "flag", "required": False, "help": "Skip user checks"},
            {"name": "--no-services", "type": "flag", "required": False, "help": "Skip service checks"},
            {"name": "--no-filesystem", "type": "flag", "required": False, "help": "Skip filesystem checks"},
        ],
        "dependencies": ["standard Linux utilities"],
        "quality": GOOD,
        "expected_output": (
            "User Audit: Privileged users, empty passwords, expired accounts.\n"
            "Network: Open ports, listening services, firewall rules.\n"
            "Services: Running services, unnecessary service detection.\n"
            "Filesystem: World-writable files, SUID/SGID binaries, /tmp permissions.\n"
            "Hardening: Kernel parameters (ASLR, core dumps), SELinux/AppArmor status.\n"
            "Report: HTML-styled report with findings and severity ratings."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 02-Web-Application-Security (8 scripts)
    # ═══════════════════════════════════════════════════════════════
    
    "directory_bruteforce.sh": {
        "name": "Directory & File Bruteforce",
        "category": "02-Web-Application-Security",
        "description": "Discovers hidden directories and files using gobuster, dirb, or ffuf.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-w/--wordlist", "type": "text", "required": False, "help": "Wordlist path"},
            {"name": "-x/--extensions", "type": "text", "required": False, "help": "Extensions (php,txt)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["gobuster or dirb or ffuf"],
        "quality": GOOD,
        "expected_output": "Discovers hidden directories, files, and endpoints.",
    },
    "cms_scanner.sh": {
        "name": "CMS Scanner",
        "category": "02-Web-Application-Security",
        "description": "Detects and scans CMS: WordPress (wpscan), Joomla, Drupal, Magento.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["wpscan (optional)", "curl"],
        "quality": GOOD,
        "expected_output": "CMS detection and vulnerability scanning.",
    },
    "http_security_headers.sh": {
        "name": "HTTP Security Headers Analyzer",
        "category": "02-Web-Application-Security",
        "description": "Checks HSTS, CSP, CORS, X-Frame-Options, cookie flags, server disclosure.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": "Security headers analysis with CORS and cookie checks.",
    },
    "ssrf_tester.sh": {
        "name": "SSRF Vulnerability Tester",
        "category": "02-Web-Application-Security",
        "description": "Tests for SSRF: internal service access, cloud metadata exposure.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target URL with parameter"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": "SSRF payload testing against internal services and cloud metadata.",
    },
    "file_upload_tester.sh": {
        "name": "File Upload Tester",
        "category": "02-Web-Application-Security",
        "description": "Tests file upload for extension bypass, content-type manipulation, webshell upload.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Upload endpoint URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": "File upload bypass testing results.",
    },
    "owasp_top10_scanner.sh": {
        "name": "OWASP Top 10 Scanner",
        "category": "02-Web-Application-Security",
        "description": "OWASP Top 10 comprehensive web testing: recon, injection, auth, sensitive data, XXE, access control, XSS, and more.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL (e.g., https://example.com)"},
            {"name": "wordlist_path", "type": "text", "required": False, "help": "Custom wordlist path (default: seclists common.txt)"},
        ],
        "dependencies": ["curl", "sqlmap", "gobuster/dirb", "whatweb", "nikto", "hydra", "testssl.sh"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Reconnaissance - Technology fingerprinting, directory discovery.\n"
            "Phase 2: Injection Testing - SQL injection via sqlmap, command injection payloads.\n"
            "Phase 3: Authentication - Default credential and brute-force testing.\n"
            "Phase 4: Sensitive Data - SSL/TLS assessment, header analysis.\n"
            "Phase 5-10: XXE, Access Control, Misconfiguration, XSS, Components.\n"
            "Output: HTML executive summary with all findings."
        ),
    },
    "sqlmap_automated_pentest.sh": {
        "name": "SQLMap Automated Pentest",
        "category": "02-Web-Application-Security",
        "description": "Automated sqlmap wrapper for SQL injection testing with multiple injection techniques and database enumeration.",
        "params": [
            {"name": "-u/--url", "type": "text", "required": True, "help": "Target URL with parameter (e.g., http://site.com/page?id=1)"},
            {"name": "-c/--cookie", "type": "text", "required": False, "help": "Session cookie string"},
            {"name": "-d/--data", "type": "text", "required": False, "help": "POST data string"},
            {"name": "-db/--database", "type": "text", "required": False, "help": "Target database name"},
            {"name": "-t/--table", "type": "text", "required": False, "help": "Target table name"},
            {"name": "-a/--all", "type": "flag", "required": False, "help": "Run all tests"},
            {"name": "-q/--quick", "type": "flag", "required": False, "help": "Quick scan mode"},
        ],
        "dependencies": ["sqlmap", "curl"],
        "quality": GOOD,
        "expected_output": (
            "Injection Detection: Lists injectable parameters and techniques.\n"
            "Database Enumeration: Database names, table names, column names.\n"
            "Data Extraction: Sample data from discovered tables.\n"
            "WAF Bypass: Attempts tamper scripts if WAF detected.\n"
            "Report: Consolidated findings with injection points and evidence."
        ),
    },
    "webapp_testing.sh": {
        "name": "Web Application Tester",
        "category": "02-Web-Application-Security",
        "description": "Basic 5-phase web application testing: directory discovery, technology detection, Nikto scan, SSL/TLS, HTTP headers.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL (e.g., https://example.com)"},
        ],
        "dependencies": ["gobuster/dirb", "whatweb", "nikto", "testssl.sh/sslscan", "curl"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Directory Discovery - Found directories and files.\n"
            "Phase 2: Technology Detection - CMS, framework, server info.\n"
            "Phase 3: Nikto Scan - Known vulnerability checks.\n"
            "Phase 4: SSL/TLS Analysis - Certificate and cipher assessment.\n"
            "Phase 5: HTTP Headers - Security header analysis (HSTS, CSP, X-Frame)."
        ),
    },
    "api_security_tester.sh": {
        "name": "API Security Tester",
        "category": "02-Web-Application-Security",
        "description": "REST API security testing: authentication bypass, HTTP method validation, rate limiting detection.",
        "params": [
            {"name": "-u/--url", "type": "text", "required": True, "help": "API base URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": (
            "Authentication: Tests for endpoints accessible without auth.\n"
            "HTTP Methods: Tests GET/POST/PUT/DELETE/PATCH/OPTIONS responses.\n"
            "Rate Limiting: Sends rapid requests to detect throttling.\n"
            "Note: Limited scope - no injection testing or schema validation."
        ),
    },
    "advanced_web_app_tester.sh": {
        "name": "Advanced Web App Tester",
        "category": "02-Web-Application-Security",
        "description": "Advanced web testing: JWT vulnerabilities, GraphQL introspection, WebSocket security, NoSQL injection, SSRF/XXE/SSTI.",
        "params": [
            {"name": "-u/--url", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-c/--cookie", "type": "text", "required": False, "help": "Session cookie"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": (
            "GraphQL: Introspection query results, schema discovery.\n"
            "CORS: Cross-origin policy analysis.\n"
            "Headers: Security header assessment.\n"
            "HTTP Methods: Allowed methods per endpoint.\n"
            "Note: NoSQL/SSRF/XXE sections generate payload files for manual testing."
        ),
    },
    "graphql_security_tester.sh": {
        "name": "GraphQL Security Tester",
        "category": "02-Web-Application-Security",
        "description": "GraphQL-specific security testing: introspection, query depth attacks, complexity attacks, injection, authorization.",
        "params": [
            {"name": "graphql_endpoint", "type": "text", "required": True, "help": "GraphQL endpoint URL (e.g., https://api.example.com/graphql)"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Introspection - Full schema dump if enabled.\n"
            "Phase 2: Depth Attack - Nested query with response time.\n"
            "Phase 3: Complexity - Resource-intensive query results.\n"
            "Phase 4: Injection - SQL/NoSQL injection in GraphQL variables.\n"
            "Phase 5: Authorization - Tests for unauthenticated access."
        ),
    },
    "websocket_security_tester.sh": {
        "name": "WebSocket Security Tester",
        "category": "02-Web-Application-Security",
        "description": "WebSocket security: endpoint discovery, CSWSH, injection, auth bypass, DoS & rate limiting.",
        "params": [
            {"name": "websocket_url", "type": "text", "required": True, "help": "WebSocket URL (e.g., ws://example.com/ws)"},
        ],
        "dependencies": ["curl", "nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: WebSocket endpoint discovery (common paths, upgrade check).\n"
            "Phase 2: Handshake testing (origin validation, CSWSH, downgrade).\n"
            "Phase 3: Message injection (XSS, SQLi, command injection).\n"
            "Phase 4: Auth & authorization testing (unauthenticated, token replay).\n"
            "Phase 5: DoS & rate limiting (connection flood, large messages)."
        ),
    },
    "jwt_token_manipulator.sh": {
        "name": "JWT Token Manipulator",
        "category": "02-Web-Application-Security",
        "description": "JWT token analysis and manipulation: decoding, algorithm confusion (none/HS256), payload manipulation, signature attacks.",
        "params": [
            {"name": "jwt_token", "type": "text", "required": True, "help": "JWT token string (eyJ...)"},
        ],
        "dependencies": ["base64", "jq"],
        "quality": GOOD,
        "expected_output": (
            "Header Decode: Algorithm, type, key ID.\n"
            "Payload Decode: Claims (sub, iss, exp, iat, roles).\n"
            "Algorithm Confusion: Modified tokens with 'none' algorithm.\n"
            "Payload Manipulation: Tokens with altered roles/admin claims.\n"
            "Note: Signature attacks and timing tests are informational only."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 03-Wireless-Security (2 scripts)
    # ═══════════════════════════════════════════════════════════════
    "wifi_penetration_tester.sh": {
        "name": "WiFi Penetration Tester",
        "category": "03-Wireless-Security",
        "description": "WiFi penetration testing: monitor mode, network scanning, WPA/WPA2 handshake capture, password cracking, WPS testing.",
        "params": [
            {"name": "-i/--interface", "type": "text", "required": True, "help": "Wireless interface (e.g., wlan0)"},
            {"name": "-b/--bssid", "type": "text", "required": False, "help": "Target BSSID (MAC address)"},
            {"name": "-s/--ssid", "type": "text", "required": False, "help": "Target SSID name"},
            {"name": "-w/--wordlist", "type": "text", "required": False, "help": "Password wordlist file"},
            {"name": "-d/--duration", "type": "text", "required": False, "help": "Capture duration in seconds"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng", "iwconfig", "reaver (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Monitor Mode: Interface set to monitor mode.\n"
            "Network Scan: List of nearby APs with BSSID, channel, encryption.\n"
            "Handshake Capture: WPA/WPA2 4-way handshake captured.\n"
            "Password Crack: Dictionary attack results against handshake.\n"
            "WPS Test: WPS PIN brute-force attempt results.\n"
            "Requires: Root privileges and compatible wireless adapter."
        ),
    },
    
    "rogue_ap_detector.sh": {
        "name": "Rogue AP & Evil Twin Detector",
        "category": "03-Wireless-Security",
        "description": "Detects rogue access points and evil twin attacks by scanning for duplicate SSIDs.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": False, "help": "Target SSID"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmcli or airodump-ng"],
        "quality": GOOD,
        "expected_output": "Rogue AP detection with SSID duplication analysis.",
    },
    "deauth_tester.sh": {
        "name": "WiFi Deauth Tester",
        "category": "03-Wireless-Security",
        "description": "Tests WiFi resilience to deauthentication frame attacks.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target AP BSSID"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aircrack-ng"],
        "quality": GOOD,
        "expected_output": "Deauthentication resilience testing.",
    },
    "bluetooth_scanner.sh": {
        "name": "Bluetooth Scanner",
        "category": "03-Wireless-Security",
        "description": "Bluetooth device discovery and service enumeration with security analysis.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": False, "help": "Target MAC address"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["bluetoothctl", "hcitool", "rfkill", "sdptool"],
        "quality": GOOD,
        "expected_output": (
            "Discovery: Nearby Bluetooth devices with names and MACs.\n"
            "Service Enum: SDP service records for target device.\n"
            "Note: Limited scope - no vulnerability testing or pairing attacks."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 04-Database-Security (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "database_penetration_tester.sh": {
        "name": "Database Penetration Tester",
        "category": "04-Database-Security",
        "description": "Database pentest: service detection, default credentials, brute-force, SQL injection, privilege escalation for MySQL/PostgreSQL/MSSQL/Oracle/MongoDB.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Database server IP or hostname"},
            {"name": "-p/--port", "type": "text", "required": False, "help": "Database port"},
            {"name": "-d/--db-type", "type": "select", "required": False, "options": ["mysql", "postgres", "mssql", "oracle", "mongo"], "help": "Database type"},
            {"name": "-u/--username", "type": "text", "required": False, "help": "Username for auth testing"},
            {"name": "-P/--password", "type": "text", "required": False, "help": "Password for auth testing"},
            {"name": "-w/--wordlist", "type": "text", "required": False, "help": "Password wordlist file"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "hydra", "sqlmap", "mysql (optional)", "psql (optional)", "mongo (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Service Detection: Database type and version identified.\n"
            "Default Credentials: Tests common default user/pass combinations.\n"
            "Brute Force: Hydra-based password attack results.\n"
            "Enumeration: Database names, tables, users listed.\n"
            "Privilege Escalation: FILE privilege, INTO OUTFILE, COPY testing.\n"
            "Report: Consolidated findings with severity ratings."
        ),
    },
    "database_attack_vectors.sh": {
        "name": "Database Attack Vectors",
        "category": "04-Database-Security",
        "description": "Advanced SQL injection variants, stored procedure abuse, privilege escalation, and data exfiltration techniques.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target database server"},
        ],
        "extra_args_help": "-d mysql|postgres|mssql -p PORT -u USER -P PASS -w WEB_URL",
        "dependencies": ["nmap", "sqlmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Service detection & version fingerprinting via nmap.\n"
            "Phase 2: SQL injection testing (union, error, blind, time-based, stacked).\n"
            "Phase 3: Stored procedure abuse (xp_cmdshell, UDF, PL/pgSQL).\n"
            "Phase 4: Privilege escalation (GRANT abuse, FILE priv, COPY).\n"
            "Phase 5: Data exfiltration techniques (DNS/HTTP OOB).\n"
            "Phase 6: Nmap NSE database scripts."
        ),
    },
    "nosql_database_tester.sh": {
        "name": "NoSQL Database Tester",
        "category": "04-Database-Security",
        "description": "NoSQL database security testing for MongoDB, CouchDB, Redis, and Elasticsearch.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target NoSQL database server"},
        ],
        "extra_args_help": "-d mongodb|redis|couchdb|elasticsearch -p PORT -u USER -P PASS",
        "dependencies": ["nmap", "curl"],
        "quality": GOOD,
        "expected_output": (
            "MongoDB: Anonymous access, database listing, collection enum, NoSQL injection payloads.\n"
            "Redis: Unauthenticated access, CONFIG dump, key enum, RCE techniques.\n"
            "CouchDB: Admin party detection, _all_dbs, config access, CVE checks.\n"
            "Elasticsearch: Cluster health, index listing, data sampling, script execution."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 05-Active-Directory (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "active_directory_tester.sh": {
        "name": "Active Directory Tester",
        "category": "05-Active-Directory",
        "description": "AD penetration testing: DC discovery, user enumeration, null sessions, Kerberos attacks, password spraying, BloodHound collection.",
        "params": [
            {"name": "-d/--domain", "type": "text", "required": True, "help": "Target domain (e.g., corp.local)"},
            {"name": "-i/--dc-ip", "type": "text", "required": True, "help": "Domain Controller IP address"},
            {"name": "-u/--username", "type": "text", "required": False, "help": "Username for authenticated tests"},
            {"name": "-p/--password", "type": "text", "required": False, "help": "Password for authenticated tests"},
            {"name": "-w/--wordlist", "type": "text", "required": False, "help": "Password wordlist file"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "smbclient", "rpcclient", "enum4linux", "ldapsearch", "Impacket", "bloodhound-python (optional)"],
        "quality": GOOD,
        "expected_output": (
            "DC Discovery: Domain controller ports and services.\n"
            "User Enumeration: Domain users via RPC/LDAP.\n"
            "Null Sessions: Anonymous access testing on SMB/RPC.\n"
            "Kerberos: ASREPRoast and Kerberoasting results.\n"
            "Password Spray: Results of password spraying attack.\n"
            "SMB Shares: Accessible share listing.\n"
            "BloodHound: AD relationship data collection."
        ),
    },
    "kerberos_attack_suite.sh": {
        "name": "Kerberos Attack Suite",
        "category": "05-Active-Directory",
        "description": "Kerberos-specific attacks: AS-REP Roasting, Kerberoasting, Golden/Silver Ticket, delegation abuse, Pass-the-Ticket.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target domain controller IP"},
        ],
        "extra_args_help": "-d DOMAIN -u USER -p PASS -H NTLM_HASH -U userlist.txt",
        "dependencies": ["nmap", "python3", "impacket (GetNPUsers.py, GetUserSPNs.py, ticketer.py)"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Kerberos enumeration via nmap/kerbrute.\n"
            "Phase 2: AS-REP Roasting - captures hashes for offline cracking.\n"
            "Phase 3: Kerberoasting - TGS ticket extraction.\n"
            "Phase 4: Delegation abuse analysis (unconstrained, constrained, RBCD).\n"
            "Phase 5: Golden/Silver Ticket analysis & DCSync check.\n"
            "Phase 6: Pass-the-Ticket TGT request."
        ),
    },
    
    "bloodhound_ad_mapper.sh": {
        "name": "BloodHound AD Mapper",
        "category": "05-Active-Directory",
        "description": "AD attack path analysis with BloodHound/SharpHound and LDAP enumeration.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Domain Controller IP"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["bloodhound-python (optional)", "ldapsearch"],
        "quality": GOOD,
        "expected_output": "AD data collection and LDAP user/computer enumeration.",
    },
    "responder_poisoner.sh": {
        "name": "Responder LLMNR Poisoner",
        "category": "05-Active-Directory",
        "description": "LLMNR/NBT-NS/mDNS poisoning detection and NTLM hash capture.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Network interface"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["responder (optional)", "tcpdump"],
        "quality": GOOD,
        "expected_output": "Broadcast protocol detection and NTLM hash capture.",
    },
    "ntlm_relay_tester.sh": {
        "name": "NTLM Relay Tester",
        "category": "05-Active-Directory",
        "description": "NTLM relay attack testing: SMB signing, LLMNR/NBT-NS poisoning, coercion attacks, relay target analysis.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target network CIDR or host"},
        ],
        "extra_args_help": "-d DOMAIN -u USER -p PASS -i INTERFACE",
        "dependencies": ["nmap", "python3"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: SMB signing enumeration - finds relay targets.\n"
            "Phase 2: LLMNR/NBT-NS/mDNS poisoning analysis.\n"
            "Phase 3: WebDAV enumeration for HTTP relay paths.\n"
            "Phase 4: Coercion attack detection (PetitPotam, PrinterBug, DFS).\n"
            "Phase 5: NTLM relay target analysis (LDAP, SMB, HTTP, MSSQL).\n"
            "Phase 6: IPv6 DNS takeover analysis."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 06-Password-Attacks (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "password_attack_suite.sh": {
        "name": "Password Attack Suite",
        "category": "06-Password-Attacks",
        "description": "Comprehensive password attacks: brute force (hydra), hash cracking (john/hashcat), password spraying, wordlist generation.",
        "params": [
            {"name": "mode", "type": "select", "required": True,
             "options": ["--brute-force", "--hash-crack", "--password-spray", "--generate-wordlist"],
             "help": "Attack mode"},
            {"name": "-t/--target", "type": "text", "required": False, "help": "Target hostname or IP"},
            {"name": "-s/--service", "type": "select", "required": False,
             "options": ["ssh", "ftp", "smb", "rdp", "http", "mysql", "postgres"],
             "help": "Target service for brute force"},
            {"name": "-u/--username", "type": "text", "required": False, "help": "Single username"},
            {"name": "-U/--userlist", "type": "text", "required": False, "help": "Username list file"},
            {"name": "-p/--passwordlist", "type": "text", "required": False, "help": "Password list file"},
            {"name": "-H/--hashfile", "type": "text", "required": False, "help": "Hash file for cracking"},
            {"name": "--hashtype", "type": "select", "required": False,
             "options": ["md5", "sha1", "sha256", "ntlm", "bcrypt"],
             "help": "Hash type"},
            {"name": "-T/--threads", "type": "text", "required": False, "help": "Number of threads (default: 4)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["hydra", "john", "hashcat", "crunch", "cewl"],
        "quality": GOOD,
        "expected_output": (
            "Brute Force: Hydra attack results - found credentials listed.\n"
            "Hash Crack: John/Hashcat cracking results with recovered passwords.\n"
            "Password Spray: Results per user account with success/lockout status.\n"
            "Wordlist Gen: Custom wordlist generated from target info.\n"
            "Analysis: Password strength statistics and recommendations."
        ),
    },
    "hash_analyzer_cracker.sh": {
        "name": "Hash Analyzer & Cracker",
        "category": "06-Password-Attacks",
        "description": "Hash identification, dictionary/rule/brute-force cracking, and online lookup with hashcat and john.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Hash string or file path"},
        ],
        "extra_args_help": "-m auto|dictionary|rules|brute|combo|lookup -w WORDLIST -H HASHCAT_MODE",
        "dependencies": ["hashcat or john", "hashid"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Hash identification (pattern matching, hashid, hash-identifier).\n"
            "Phase 2: Dictionary attack with wordlist (hashcat -a 0 / john --wordlist).\n"
            "Phase 3: Rule-based attack (best64, rockyou rules).\n"
            "Phase 4: Brute force / mask attack (common password patterns).\n"
            "Phase 5: Online hash lookup services.\n"
            "Report: Cracked vs uncracked statistics."
        ),
    },
    "password_spraying_campaign.sh": {
        "name": "Password Spraying Campaign",
        "category": "06-Password-Attacks",
        "description": "Multi-protocol password spraying with lockout evasion: SMB, RDP, LDAP, SSH, OWA, Kerberos.",
        "params": [
            {"name": "target_domain", "type": "text", "required": True, "help": "Target host or domain controller IP"},
        ],
        "extra_args_help": "-d DOMAIN -U userlist.txt -p PASSWORD -s smb|rdp|ldap|ssh|owa|kerberos -D DELAY -L LOCKOUT",
        "dependencies": ["nmap", "crackmapexec or hydra"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Account lockout policy enumeration.\n"
            "Phase 2: User enumeration (RID brute, kerbrute).\n"
            "Phase 3: Password spraying with lockout-aware timing.\n"
            "Phase 4: Credential validation and access testing."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 07-Social-Engineering (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "social_engineering_toolkit.sh": {
        "name": "Social Engineering Toolkit",
        "category": "07-Social-Engineering",
        "description": "Social engineering assessment: email harvesting via theHarvester, phishing template generation, awareness reporting.",
        "params": [
            {"name": "-d/--domain", "type": "text", "required": True, "help": "Target domain"},
            {"name": "-c/--company", "type": "text", "required": False, "help": "Company name"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["theHarvester"],
        "quality": GOOD,
        "expected_output": (
            "Email Harvesting: Emails found via theHarvester (LinkedIn, Google, etc.)\n"
            "Phishing Templates: IT Support and HR themed HTML email templates.\n"
            "Awareness Report: Summary of social engineering attack surface.\n"
            "Note: No automated sending capability - templates for manual use."
        ),
    },
    "phishing_campaign_automation.sh": {
        "name": "Phishing Campaign Automation",
        "category": "07-Social-Engineering",
        "description": "Phishing campaign setup: domain recon (SPF/DKIM/DMARC), template generation, landing pages, GoPhish integration.",
        "params": [
            {"name": "target_domain", "type": "text", "required": True, "help": "Target domain"},
        ],
        "extra_args_help": "-T it_support|hr|ceo|delivery|mfa -S SMTP_SERVER -f FROM_EMAIL",
        "dependencies": ["curl", "dig", "nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Domain recon - MX, SPF, DKIM, DMARC analysis.\n"
            "Phase 2: 5 phishing email templates (IT, HR, CEO, Delivery, MFA).\n"
            "Phase 3: Credential harvesting landing page.\n"
            "Phase 4: GoPhish integration and manual send instructions."
        ),
    },
    "email_harvesting_osint.sh": {
        "name": "Email Harvesting OSINT",
        "category": "07-Social-Engineering",
        "description": "Email harvesting via theHarvester, DNS, web scraping, WHOIS, breach databases, and validation.",
        "params": [
            {"name": "target_domain", "type": "text", "required": True, "help": "Target domain"},
        ],
        "dependencies": ["curl", "dig"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: theHarvester email collection (Google, Bing, LinkedIn).\n"
            "Phase 2: DNS-based discovery (MX, SOA, DMARC, crt.sh).\n"
            "Phase 3: Web scraping for emails on target pages.\n"
            "Phase 4: WHOIS contact extraction.\n"
            "Phase 5: Breach database checks.\n"
            "Phase 6: Deduplicated email list with usernames."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 08-System-Security (4 scripts)
    # ═══════════════════════════════════════════════════════════════
    "system_config_audit.sh": {
        "name": "System Config Audit (08)",
        "category": "08-System-Security",
        "description": "Comprehensive system configuration auditor: users, groups, network config, services, file permissions.",
        "params": [
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose mode"},
        ],
        "dependencies": ["ss/netstat", "ps", "systemctl", "find", "awk"],
        "quality": GOOD,
        "expected_output": (
            "User Audit: Privileged accounts, empty passwords, shell access.\n"
            "Network: Open ports, listening services.\n"
            "Services: Enabled/running service inventory.\n"
            "Files: World-writable files, SUID/SGID binaries found.\n"
            "Report: Consolidated security assessment."
        ),
    },
    "log_analyzer.sh": {
        "name": "Log Analyzer",
        "category": "08-System-Security",
        "description": "Security-focused log analysis: auth logs, system logs, web server logs for anomalies and attack pattern detection.",
        "params": [
            {"name": "-p/--path", "type": "text", "required": False, "help": "Log path (default: /var/log)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["grep", "awk", "sort"],
        "quality": GOOD,
        "expected_output": (
            "Auth Analysis: Failed/successful logins, SSH brute force attempts.\n"
            "System Logs: Errors, kernel messages, service failures.\n"
            "Web Logs: 404s, SQL injection attempts, XSS patterns.\n"
            "Anomalies: Off-hours logins, repeated failures, large transfers."
        ),
    },
    "patch_management_scanner.sh": {
        "name": "Patch Management Scanner",
        "category": "08-System-Security",
        "description": "System update and vulnerability scanner checking for missing patches across Debian, RedHat, and Fedora systems.",
        "params": [
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["apt/yum/dnf (auto-detected)", "uname"],
        "quality": GOOD,
        "expected_output": (
            "Package Manager: Detected (apt/yum/dnf).\n"
            "Available Updates: Count and list of pending updates.\n"
            "Security Updates: Critical security patches needed.\n"
            "Kernel: Current vs. available kernel versions.\n"
            "Vulnerable Packages: Version check for OpenSSL, SSH, Apache, etc."
        ),
    },
    "file_integrity_monitor.sh": {
        "name": "File Integrity Monitor",
        "category": "08-System-Security",
        "description": "File integrity monitoring with SHA256 baseline creation, integrity checking, and real-time inotifywait monitoring.",
        "params": [
            {"name": "mode", "type": "select", "required": True,
             "options": ["--baseline", "--check", "--monitor"],
             "help": "Operation mode"},
            {"name": "-d/--dirs", "type": "text", "required": False, "help": "Directories to monitor (space-separated)"},
            {"name": "-b/--baseline", "type": "text", "required": False, "help": "Baseline file path"},
            {"name": "-e/--email", "type": "text", "required": False, "help": "Alert email address"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["sha256sum", "find", "inotifywait (inotify-tools)", "mail (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Baseline: Creates SHA256 hash database of all files.\n"
            "Check: Compares current state vs baseline.\n"
            "  - MODIFIED: Files with changed hash/size/permissions.\n"
            "  - NEW: Files added since baseline.\n"
            "  - DELETED: Files removed since baseline.\n"
            "Monitor: Real-time alerts on file create/modify/delete events."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 09-Container-Security (1 script)
    # ═══════════════════════════════════════════════════════════════
    "container_security_scanner.sh": {
        "name": "Container Security Scanner",
        "category": "09-Container-Security",
        "description": "Docker/container security assessment: daemon config, running containers, images, networks inspection.",
        "params": [
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["docker", "jq"],
        "quality": GOOD,
        "expected_output": (
            "Docker Daemon: Version, storage driver, security options.\n"
            "Containers: Running container list with security settings.\n"
            "Images: Image inventory with layer analysis.\n"
            "Networks: Docker network configuration.\n"
            "Note: No deep vulnerability scanning (missing trivy/grype integration)."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 10-Mobile-Security (2 scripts)
    # ═══════════════════════════════════════════════════════════════
    "android_apk_analyzer.sh": {
        "name": "Android APK Analyzer",
        "category": "10-Mobile-Security",
        "description": "Android APK security analysis: package info, manifest permissions, sensitive data scanning, security feature checks.",
        "params": [
            {"name": "-f/--file", "type": "text", "required": True, "help": "APK file path"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aapt (Android SDK)", "unzip", "strings", "grep"],
        "quality": GOOD,
        "expected_output": (
            "Package Info: App name, version, SDK versions, package name.\n"
            "Permissions: All requested permissions with risk assessment.\n"
            "Components: Activities, services, receivers, providers.\n"
            "Sensitive Data: Hardcoded passwords, API keys, tokens, URLs.\n"
            "Security Features: Certificate pinning, obfuscation, root detection."
        ),
    },
    "ios_app_analyzer.sh": {
        "name": "iOS App Analyzer",
        "category": "10-Mobile-Security",
        "description": "iOS IPA security analysis: app structure, binary protections (PIE, stack canary, ARC), code signing verification.",
        "params": [
            {"name": "-f/--file", "type": "text", "required": True, "help": "IPA file path"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["unzip", "plutil (macOS)", "otool (macOS)", "codesign (macOS)"],
        "quality": GOOD,
        "expected_output": (
            "App Structure: Bundle contents and Info.plist analysis.\n"
            "Binary Protection: PIE, stack canary, ARC detection.\n"
            "Code Signing: Signature verification status.\n"
            "Note: Requires macOS for full functionality (otool, plutil, codesign)."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 11-Cloud-Security (4 scripts)
    # ═══════════════════════════════════════════════════════════════
    "aws_security_scanner.sh": {
        "name": "AWS Security Scanner",
        "category": "11-Cloud-Security",
        "description": "AWS cloud security assessment: S3 bucket policies, EC2 security groups, IAM privileges, RDS exposure, CloudTrail logging.",
        "params": [
            {"name": "-p/--profile", "type": "text", "required": False, "help": "AWS CLI profile name"},
            {"name": "-r/--region", "type": "text", "required": False, "help": "AWS region (default: us-east-1)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aws (AWS CLI)"],
        "quality": GOOD,
        "expected_output": (
            "S3 Buckets: Public bucket detection, policy analysis.\n"
            "EC2: Security group rules, 0.0.0.0/0 exposure detection.\n"
            "IAM: Users with admin privileges, MFA status.\n"
            "RDS: Publicly accessible database instances.\n"
            "CloudTrail: Logging enabled/disabled status.\n"
            "Root Account: Recent root account activity."
        ),
    },
    "azure_gcp_enumeration.sh": {
        "name": "Azure/GCP Enumeration",
        "category": "11-Cloud-Security",
        "description": "Azure tenant recon, storage enumeration, and GCP bucket/Firebase/App Engine discovery.",
        "params": [
            {"name": "cloud_target", "type": "text", "required": True, "help": "Target domain or tenant ID"},
        ],
        "extra_args_help": "-c azure|gcp|both",
        "dependencies": ["curl", "dig"],
        "quality": GOOD,
        "expected_output": (
            "Azure: Tenant ID extraction, user enumeration via GetCredentialType.\n"
            "Azure: Blob/File/Table storage discovery with public access checks.\n"
            "Azure: App Service, Key Vault, SQL endpoint discovery.\n"
            "GCP: GCS bucket discovery, App Engine, Firebase database exposure.\n"
            "GCP: Service enumeration via gcloud CLI."
        ),
    },
    "cloud_storage_bucket_tester.sh": {
        "name": "Cloud Storage Bucket Tester",
        "category": "11-Cloud-Security",
        "description": "Cloud storage bucket security testing: AWS S3, GCS, Azure Blob, DigitalOcean Spaces with name permutation.",
        "params": [
            {"name": "bucket_name", "type": "text", "required": True, "help": "Bucket name, domain, or URL"},
        ],
        "extra_args_help": "-c aws|gcs|azure|do|all",
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": (
            "S3: Public listing, file access, write access, ACL/policy checks.\n"
            "GCS: Bucket listing, IAM policy, sensitive file detection.\n"
            "Azure: Container listing, blob enumeration, public access checks.\n"
            "DO Spaces: Multi-region space discovery.\n"
            "Report: Findings with severity ratings."
        ),
    },
    
    "iam_privesc_scanner.sh": {
        "name": "Cloud IAM PrivEsc Scanner",
        "category": "11-Cloud-Security",
        "description": "Scans AWS/Azure/GCP IAM for privilege escalation paths and wildcard policies.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Cloud: aws|azure|gcp"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aws-cli or az-cli or gcloud"],
        "quality": GOOD,
        "expected_output": "IAM enumeration and privilege escalation analysis.",
    },
    "serverless_tester.sh": {
        "name": "Serverless Security Tester",
        "category": "11-Cloud-Security",
        "description": "Tests Lambda/Azure Functions for secrets in env vars, VPC gaps, runtime issues.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Cloud: aws|azure|gcp"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["aws-cli or az-cli or gcloud"],
        "quality": GOOD,
        "expected_output": "Serverless function enumeration and security analysis.",
    },
    "container_orchestration_security.sh": {
        "name": "Container Orchestration Security",
        "category": "11-Cloud-Security",
        "description": "Kubernetes API, Kubelet, Docker API, etcd security testing and container escape analysis.",
        "params": [
            {"name": "k8s_target", "type": "text", "required": True, "help": "Kubernetes API server or Docker host"},
        ],
        "extra_args_help": "-p PORT (K8s API port, default 6443)",
        "dependencies": ["curl", "nmap"],
        "quality": GOOD,
        "expected_output": "STATUS: STUB - This script needs implementation. Currently outputs placeholder text only.",
    },

    # ═══════════════════════════════════════════════════════════════
    # 12-Exploitation (1 script)
    # ═══════════════════════════════════════════════════════════════
    "metasploit_automation.sh": {
        "name": "Metasploit Automation",
        "category": "12-Exploitation",
        "description": "Generates Metasploit resource scripts (.rc) for exploitation and vulnerability scanning with auto-payload selection.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP address"},
            {"name": "-p/--port", "type": "text", "required": False, "help": "Target port"},
            {"name": "-e/--exploit", "type": "text", "required": False, "help": "Exploit module path"},
            {"name": "-P/--payload", "type": "text", "required": False, "help": "Payload module path"},
            {"name": "--lhost", "type": "text", "required": False, "help": "Local host IP for reverse shell"},
            {"name": "--lport", "type": "text", "required": False, "help": "Local port for reverse shell (default: 4444)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["msfconsole (Metasploit Framework)"],
        "quality": GOOD,
        "expected_output": (
            "RC Script Generation: Metasploit resource scripts created.\n"
            "Payload Selection: Auto-selected payload based on target OS.\n"
            "Vulnerability Scan: Generated vuln scan .rc script.\n"
            "Note: Generates scripts but doesn't execute msfconsole directly.\n"
            "Usage: Run generated .rc files with 'msfconsole -r <file>.rc'"
        ),
    },

    # ═══════════════════════════════════════════════════════════════

    "searchsploit_automation.sh": {
        "name": "SearchSploit Exploit Finder",
        "category": "12-Exploitation",
        "description": "Searches Exploit-DB for known exploits based on discovered services, CVEs, or free-text queries. Auto-discovers from nmap results.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": False, "help": "Target IP (auto-finds nmap results)"},
            {"name": "-s/--services", "type": "text", "required": False, "help": "Comma-separated services (smb,rdp,ssh)"},
            {"name": "-c/--cves", "type": "text", "required": False, "help": "Comma-separated CVEs (CVE-2017-0144)"},
            {"name": "-q/--query", "type": "text", "required": False, "help": "Free-text search query"},
            {"name": "-n/--nmap-file", "type": "text", "required": False, "help": "Path to nmap output file to parse"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["searchsploit (exploit-db)"],
        "quality": GOOD,
        "expected_output": "Service Search: Searches Exploit-DB for each discovered service. CVE Search: Finds public exploits for specific CVEs. Smart Search: Combines service+version for targeted results. Report: Generates summary with total exploits found.",
    },

    # 13-Post-Exploitation (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "privilege_escalation_checker.sh": {
        "name": "Privilege Escalation Checker",
        "category": "13-Post-Exploitation",
        "description": "Enumerates Linux privilege escalation vectors: SUID/SGID, sudo permissions, processes, kernel vulns, capabilities.",
        "params": [
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-q/--quick", "type": "flag", "required": False, "help": "Quick mode (skip kernel/capabilities)"},
        ],
        "dependencies": ["find", "ps", "netstat/ss", "getcap", "sudo", "uname"],
        "quality": GOOD,
        "expected_output": (
            "SUID/SGID: List of SUID/SGID binaries with GTFOBins matches.\n"
            "Sudo: Current user's sudo permissions.\n"
            "Writable Files: World-writable directories and files.\n"
            "Processes: Running processes with root ownership.\n"
            "Kernel: Kernel version with known exploit suggestions.\n"
            "Capabilities: Files with elevated Linux capabilities.\n"
            "Cron: Writable cron jobs and scripts."
        ),
    },
    "persistence_mechanisms.sh": {
        "name": "Persistence Mechanisms",
        "category": "13-Post-Exploitation",
        "description": "Plants persistence on compromised targets: backdoor users, cron shells, SSH keys, SUID, webshells, services, netcat listeners.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP"},
            {"name": "-u/--user", "type": "text", "required": False, "help": "SSH username (default: root)"},
            {"name": "-p/--pass", "type": "text", "required": False, "help": "SSH password"},
            {"name": "-k/--key", "type": "text", "required": False, "help": "SSH private key file"},
            {"name": "--lhost", "type": "text", "required": False, "help": "Attacker IP for reverse shells"},
            {"name": "--lport", "type": "text", "required": False, "help": "Attacker port (default: 5555)"},
            {"name": "-m/--mode", "type": "text", "required": False, "help": "Mode: all|cron|user|ssh|service|suid|netcat|php"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "extra_args_help": "-m detect|reference",
        "dependencies": ["nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Cron job persistence detection.\n"
            "Phase 2: Systemd/init.d service persistence.\n"
            "Phase 3: SSH authorized keys analysis.\n"
            "Phase 4: Startup/profile persistence (.bashrc, LD_PRELOAD).\n"
            "Phase 5: Rootkit and hidden process detection.\n"
            "Phase 6: MITRE ATT&CK persistence technique reference."
        ),
    },
    
    "lateral_movement.sh": {
        "name": "Lateral Movement Toolkit",
        "category": "13-Post-Exploitation",
        "description": "Maps lateral movement: SMB, WinRM, SSH pivoting, Pass-the-Hash, CrackMapExec.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP or subnet"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap", "crackmapexec (optional)", "impacket (optional)"],
        "quality": GOOD,
        "expected_output": "Lateral movement path mapping: SMB signing, WinRM, SSH, PtH.",
    },
    "data_exfiltration_simulator.sh": {
        "name": "Data Exfiltration Simulator",
        "category": "13-Post-Exploitation",
        "description": "DLP testing via DNS, HTTP, ICMP, SMB exfiltration simulation and encoding bypass techniques.",
        "params": [
            {"name": "target_network", "type": "text", "required": True, "help": "Target network or host"},
        ],
        "extra_args_help": "-l LISTENER_IP -s DATA_SIZE_KB",
        "dependencies": ["curl", "nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: Network egress channel testing.\n"
            "Phase 2: DNS exfiltration simulation.\n"
            "Phase 3: HTTP/HTTPS exfiltration with encoding.\n"
            "Phase 4: ICMP exfiltration simulation.\n"
            "Phase 5: File-based exfiltration techniques.\n"
            "Phase 6: DLP control assessment checklist."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 14-Reporting-Tools (1 script)
    # ═══════════════════════════════════════════════════════════════
    "pentest_report_generator.sh": {
        "name": "Pentest Report Generator",
        "category": "14-Reporting-Tools",
        "description": "Generates structured Markdown pentest reports with executive summary, findings, recommendations. Optional HTML via pandoc.",
        "params": [
            {"name": "-c/--client", "type": "text", "required": True, "help": "Client name"},
            {"name": "-p/--project", "type": "text", "required": True, "help": "Project name"},
            {"name": "-d/--date", "type": "text", "required": False, "help": "Report date"},
            {"name": "-t/--tester", "type": "text", "required": False, "help": "Tester name"},
            {"name": "-s/--scan-dirs", "type": "text", "required": False, "help": "Scan result directories (comma-separated)"},
            {"name": "-r/--report-type", "type": "select", "required": False, "options": ["full", "executive", "technical"], "help": "Report type"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["pandoc (optional)", "find"],
        "quality": GOOD,
        "expected_output": (
            "Report Sections: Executive summary, scope, methodology, findings.\n"
            "Scan Integration: Collects results from scan output directories.\n"
            "Formats: Markdown output, optional HTML conversion via pandoc.\n"
            "Note: Finding content uses placeholder templates - fill manually."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 15-Automation-Tools (2 scripts)
    # ═══════════════════════════════════════════════════════════════
    "pentest_automation.sh": {
        "name": "Pentest Automation",
        "category": "15-Automation-Tools",
        "description": "End-to-end automated pentest: host discovery, port scanning, service enumeration (SMB/HTTP/SSH), vulnerability assessment.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target IP or CIDR range"},
        ],
        "dependencies": ["nmap", "enum4linux (optional)", "gobuster (optional)", "nikto (optional)", "testssl.sh (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Host Discovery: Live hosts found on network.\n"
            "Port Scan: Open ports per host.\n"
            "Service Enumeration: Per-service results (SMB shares, HTTP dirs, SSH banners).\n"
            "Vulnerability Assessment: NSE script findings.\n"
            "Report: Structured report combining all scan results."
        ),
    },
    "install_pentest_tools.sh": {
        "name": "Install Pentest Tools",
        "category": "15-Automation-Tools",
        "description": "Installs common penetration testing tools on Ubuntu/Debian via apt and git (nmap, masscan, nikto, gobuster, etc.).",
        "params": [],
        "extra_args_help": "No arguments - installs all tools automatically. Requires sudo.",
        "dependencies": ["apt", "git", "sudo"],
        "quality": GOOD,
        "expected_output": (
            "Package Installation: apt install of nmap, masscan, nikto, gobuster, etc.\n"
            "Git Clones: testssl.sh, SecLists repositories cloned.\n"
            "Configuration: Symlinks and permissions set.\n"
            "Note: Ubuntu/Debian only. Requires sudo privileges."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 16-Specialized-Testing (3 scripts)
    # ═══════════════════════════════════════════════════════════════
    "iot_security_tester.sh": {
        "name": "IoT Security Tester",
        "category": "16-Specialized-Testing",
        "description": "Scans for IoT devices using common IoT ports, UPnP, MQTT, CoAP. Includes default credentials reference list.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target IP or range"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
        ],
        "dependencies": ["nmap"],
        "quality": GOOD,
        "expected_output": (
            "IoT Discovery: Devices found on IoT-specific ports.\n"
            "UPnP/MQTT/CoAP: Protocol-specific scan results.\n"
            "Default Creds: Reference list of common IoT default credentials.\n"
            "Note: Credential list is informational - no automated testing."
        ),
    },
    "thick_client_tester.sh": {
        "name": "Thick Client Tester",
        "category": "16-Specialized-Testing",
        "description": "Thick client app security: binary protection (ASLR/DEP/PIE), string analysis, config security, DLL hijacking, network analysis.",
        "params": [
            {"name": "-a/--app", "type": "text", "required": True, "help": "Application binary path"},
            {"name": "-t/--target-os", "type": "select", "required": False, "options": ["windows", "linux", "macos"], "help": "Target OS"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
        ],
        "dependencies": ["readelf/objdump (Linux)", "otool/codesign (macOS)", "strings"],
        "quality": GOOD,
        "expected_output": (
            "Binary Analysis: ASLR, DEP, PIE, RELRO, stack canary status.\n"
            "String Search: Hardcoded credentials, URLs, API keys.\n"
            "Config Files: Insecure configuration detection.\n"
            "Network: Communication analysis.\n"
            "Note: Depends on framework files in 00-Framework-Core/."
        ),
    },
    "ics_scada_tester.sh": {
        "name": "ICS/SCADA Tester",
        "category": "16-Specialized-Testing",
        "description": "ICS/SCADA security testing: Modbus, S7comm, BACnet, EtherNet/IP, DNP3, network segmentation.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target ICS/SCADA system IP"},
        ],
        "dependencies": ["nmap"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: ICS protocol discovery (Modbus, S7, BACnet, EtherNet/IP ports).\n"
            "Phase 2: Modbus protocol testing and function code reference.\n"
            "Phase 3: Siemens S7comm device info and security analysis.\n"
            "Phase 4: BACnet & EtherNet/IP discovery.\n"
            "Phase 5: ICS network segmentation (Purdue Model) check."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 17-Monitoring-Detection (4 scripts)
    # ═══════════════════════════════════════════════════════════════
    "intrusion_detection_system.sh": {
        "name": "IDS/IPS Detection Tester",
        "category": "17-Monitoring-Detection",
        "description": "Tests IDS/IPS detection capabilities: signature evasion, protocol anomaly, application layer, volume-based, behavioral testing.",
        "params": [
            {"name": "target_ip", "type": "text", "required": True, "help": "Target IP address"},
        ],
        "dependencies": ["nmap", "curl", "nc", "hping3 (optional)", "python3 (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: IDS Detection - Identifies IDS presence.\n"
            "Phase 2: Signature Evasion - Fragmented/decoy scan results.\n"
            "Phase 3: Protocol Anomaly - FIN/Xmas/Null scan responses.\n"
            "Phase 4: Application Layer - HTTP method/payload testing.\n"
            "Phase 5-8: Volume, Behavioral, Signature DB, Advanced evasion."
        ),
    },
    "threat_intelligence_collector.sh": {
        "name": "Threat Intelligence Collector",
        "category": "17-Monitoring-Detection",
        "description": "Collects threat intelligence: OSINT, reputation, certificates, network, vulnerabilities, malware IOCs.",
        "params": [
            {"name": "target", "type": "text", "required": True, "help": "Target domain or IP address"},
        ],
        "dependencies": ["dig", "whois", "curl", "openssl", "nmap", "amass (optional)"],
        "quality": GOOD,
        "expected_output": (
            "OSINT: DNS records, WHOIS data, subdomain enumeration.\n"
            "Certificates: SSL cert analysis via crt.sh and openssl.\n"
            "Network: Port scan and geolocation results.\n"
            "Note: Reputation, vulnerability, and malware phases require API keys."
        ),
    },
    "security_metrics_dashboard.sh": {
        "name": "Security Metrics Dashboard",
        "category": "17-Monitoring-Detection",
        "description": "Generates interactive HTML security dashboard with system, network, auth, and vulnerability metrics.",
        "params": [
            {"name": "target", "type": "text", "required": False, "help": "Target (default: localhost)"},
        ],
        "dependencies": [],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: System metrics (users, processes, disk, memory).\n"
            "Phase 2: Network metrics (listening ports, firewall rules).\n"
            "Phase 3: Authentication metrics (failed logins, SSH config, password policy).\n"
            "Phase 4: Vulnerability indicators (SUID, world-writable, pending updates).\n"
            "Phase 5: Interactive HTML dashboard with GhostStrike theme."
        ),
    },
    "incident_response_toolkit.sh": {
        "name": "Incident Response Toolkit",
        "category": "17-Monitoring-Detection",
        "description": "IR data collection: volatile data triage, user/auth analysis, filesystem, network forensics, log collection.",
        "params": [
            {"name": "incident_type", "type": "select", "required": False,
             "options": ["general", "malware", "phishing", "data_breach", "ransomware"],
             "help": "Incident type (default: general)"},
        ],
        "dependencies": ["uname", "ip/ifconfig", "ps", "ss/netstat"],
        "quality": GOOD,
        "expected_output": (
            "Phase 1: System triage - volatile data, processes, connections.\n"
            "Phase 2: User & auth analysis - logins, sudo, bash history.\n"
            "Phase 3: Filesystem analysis - recently modified/created files.\n"
            "Phase 4: Network forensics - connections, firewall, interfaces.\n"
            "Phase 5: Log collection - auth, syslog, web, audit logs.\n"
            "Phase 6: Incident-specific checks (malware/phishing/ransomware)."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 18-Application-Security (2 scripts)
    # ═══════════════════════════════════════════════════════════════
    "code_quality_checker.sh": {
        "name": "Code Quality Checker",
        "category": "18-Application-Security",
        "description": "Static analysis security testing: SAST, secrets detection, code complexity, insecure functions, config security.",
        "params": [
            {"name": "project_path", "type": "text", "required": True, "help": "Path to project directory"},
        ],
        "dependencies": ["bandit (optional)", "semgrep (optional)", "truffleHog (optional)", "grep", "find", "jq"],
        "quality": GOOD,
        "expected_output": (
            "SAST: Results from bandit/semgrep if available.\n"
            "Secrets: Detected hardcoded passwords, API keys, tokens.\n"
            "Complexity: File size analysis (basic).\n"
            "Insecure Functions: Potentially dangerous function calls.\n"
            "Config: Configuration file security assessment."
        ),
    },
    "dependency_vulnerability_scanner.sh": {
        "name": "Dependency Vulnerability Scanner",
        "category": "18-Application-Security",
        "description": "Scans project dependencies across NPM, Python, Maven, Composer, Bundler, Docker for known vulnerabilities.",
        "params": [
            {"name": "project_path", "type": "text", "required": True, "help": "Path to project directory"},
        ],
        "dependencies": ["npm/yarn", "safety/pip-audit", "mvn", "composer", "bundler-audit", "trivy"],
        "quality": GOOD,
        "expected_output": (
            "Detection: Identifies project type from manifest files.\n"
            "NPM: npm audit / yarn audit results.\n"
            "Python: safety / pip-audit vulnerability report.\n"
            "Docker: trivy container scan results.\n"
            "Supply Chain: Dependency source verification.\n"
            "Report: Consolidated vulnerability report across ecosystems."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 19-Lab-Environment (1 script)
    # ═══════════════════════════════════════════════════════════════
    "docker_lab_setup.sh": {
        "name": "Docker Lab Setup",
        "category": "19-Lab-Environment",
        "description": "Sets up Docker-based pentest lab with DVWA, WebGoat, Juice Shop, NodeGoat, WordPress, and vulnerable services.",
        "params": [
            {"name": "command", "type": "select", "required": True,
             "options": ["setup", "start", "stop", "destroy", "status", "rebuild", "logs"],
             "help": "Lab management command"},
            {"name": "-d/--dir", "type": "text", "required": False, "help": "Lab directory path"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
        ],
        "dependencies": ["docker", "docker-compose"],
        "quality": GOOD,
        "expected_output": (
            "setup: Creates docker-compose.yml with all vulnerable apps.\n"
            "start: Launches all containers, shows access URLs.\n"
            "  - DVWA: http://localhost:8080\n"
            "  - WebGoat: http://localhost:8081\n"
            "  - Juice Shop: http://localhost:3000\n"
            "stop: Gracefully stops all containers.\n"
            "status: Shows running/stopped state of each service.\n"
            "destroy: Removes all containers, networks, and volumes."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    # 20-IoT-Security (16 scripts)
    # ═══════════════════════════════════════════════════════════════
    "iot_firmware_analyzer.sh": {
        "name": "IoT Firmware Analyzer",
        "category": "20-IoT-Security",
        "description": "IoT firmware security analysis: extraction (binwalk), filesystem analysis, credentials, crypto, vulnerability patterns.",
        "params": [
            {"name": "firmware_file", "type": "text", "required": True, "help": "Path to firmware file"},
        ],
        "dependencies": ["binwalk", "ent", "checksec", "openssl", "strings", "find"],
        "quality": GOOD,
        "expected_output": (
            "Extraction: Firmware components extracted via binwalk.\n"
            "Filesystem: Directory structure, file types, permissions.\n"
            "Credentials: Hardcoded passwords, SSH keys, certificates.\n"
            "Network Config: IP addresses, ports, protocol configurations.\n"
            "Binary Analysis: Security features (NX, ASLR, canaries).\n"
            "Crypto: Weak algorithms, key material, entropy analysis."
        ),
    },
    "iot_default_creds_scanner.sh": {
        "name": "IoT Default Credentials Scanner",
        "category": "20-IoT-Security",
        "description": "Scans IoT devices for default credentials across HTTP, SSH, Telnet, FTP, SNMP, RTSP, MQTT.",
        "params": [{"name": "target", "type": "text", "required": True, "help": "Target IoT device IP or CIDR"}],
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: IoT device discovery (services, OS, UPnP).\n"
            "Phase 2: HTTP default credentials (30+ common IoT cred pairs).\n"
            "Phase 3: Service credentials (Telnet, SSH, FTP, SNMP, RTSP, MQTT)."
        ),
    },
    "iot_mqtt_tester.sh": {
        "name": "MQTT Protocol Tester",
        "category": "20-IoT-Security",
        "description": "MQTT security: anonymous access, topic enumeration, message injection, TLS analysis, data sniffing.",
        "params": [{"name": "target", "type": "text", "required": True, "help": "MQTT broker address"}],
        "extra_args_help": "-p PORT -u USER -P PASS",
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: MQTT broker discovery (ports, WebSocket, management API).\n"
            "Phase 2: Authentication testing (anonymous, default creds).\n"
            "Phase 3: Topic enumeration & data sniffing (wildcard, $SYS).\n"
            "Phase 4: Injection & manipulation (retained, will messages).\n"
            "Phase 5: TLS/SSL configuration check."
        ),
    },
    "iot_coap_tester.sh": {
        "name": "CoAP Protocol Tester",
        "category": "20-IoT-Security",
        "description": "CoAP security: resource discovery, method testing, DTLS check, observe, block transfer, multicast.",
        "params": [{"name": "target", "type": "text", "required": True, "help": "CoAP endpoint address"}],
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": "CoAP discovery (UDP 5683/5684), /.well-known/core, GET/PUT/POST/DELETE, DTLS analysis, observe subscription.",
    },
    "iot_ota_interceptor.sh": {
        "name": "OTA Update Interceptor",
        "category": "20-IoT-Security",
        "description": "OTA update analysis: server discovery, TLS validation, firmware download inspection, signature verification.",
        "params": [{"name": "target", "type": "text", "required": True, "help": "Target device or update URL"}],
        "dependencies": ["nmap", "curl", "openssl"], "quality": GOOD,
        "expected_output": "Update server discovery, TLS cert analysis, firmware download check, signature/checksum validation, rollback protection.",
    },
    "iot_uart_jtag_helper.sh": {
        "name": "UART/JTAG Helper",
        "category": "20-IoT-Security",
        "description": "Hardware debug interface helper: serial port detection, baud rate, JTAG pinout, OpenOCD configs, flash dump.",
        "params": [{"name": "device", "type": "text", "required": True, "help": "Target device or serial port"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": "Serial port detection, baud rate analysis, JTAG/SWD pinout reference, OpenOCD templates, flash dump commands.",
    },
    "iot_wireless_ble_scanner.sh": {
        "name": "BLE Security Scanner",
        "category": "20-IoT-Security",
        "description": "BLE security: device discovery, GATT enumeration, characteristic read/write, pairing analysis.",
        "params": [{"name": "device_mac", "type": "text", "required": True, "help": "Target BLE device MAC or 'scan'"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": "BLE device scan, GATT service/characteristic enumeration, read/write tests, pairing mode analysis.",
    },
    "iot_zigbee_thread_scanner.sh": {
        "name": "Zigbee/Thread Scanner",
        "category": "20-IoT-Security",
        "description": "Zigbee/Thread: network detection, channel scanning, key analysis, border router discovery.",
        "params": [{"name": "network_id", "type": "text", "required": True, "help": "Target network or 'scan'"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": "Zigbee channel scan, network key analysis, KillerBee reference, Thread border router mDNS discovery.",
    },
    "iot_network_isolation_tester.sh": {
        "name": "IoT Network Isolation Tester",
        "category": "20-IoT-Security",
        "description": "IoT network isolation: cross-segment testing, VLAN check, mDNS/SSDP leakage, gateway reachability.",
        "params": [{"name": "iot_network", "type": "text", "required": True, "help": "IoT network CIDR"}],
        "dependencies": ["nmap", "ping"], "quality": GOOD,
        "expected_output": "Cross-segment connectivity, VLAN isolation check, mDNS/SSDP leakage detection, firewall rule analysis.",
    },
    "iot_fuzz_coap_mqtt.sh": {
        "name": "IoT Protocol Fuzzer",
        "category": "20-IoT-Security",
        "description": "IoT protocol fuzzing: MQTT/CoAP malformed packets, oversized payloads, edge cases, crash detection.",
        "params": [{"name": "protocol_endpoint", "type": "text", "required": True, "help": "Protocol endpoint address"}],
        "dependencies": ["curl"], "quality": GOOD,
        "expected_output": "MQTT fuzzing (malformed CONNECT/PUBLISH), CoAP fuzzing (methods, options), crash/hang detection.",
    },
    "iot_firmware_emulation_runner.sh": {
        "name": "Firmware Emulation Runner",
        "category": "20-IoT-Security",
        "description": "Firmware emulation: QEMU setup, binwalk extraction, filesystem analysis, FirmAE/Firmadyne reference.",
        "params": [{"name": "firmware_file", "type": "text", "required": True, "help": "Path to firmware file"}],
        "dependencies": ["binwalk"], "quality": GOOD,
        "expected_output": "Firmware extraction, filesystem analysis, credential search, QEMU emulation config, FirmAE reference.",
    },
    "iot_cloud_api_tester.sh": {
        "name": "IoT Cloud API Tester",
        "category": "20-IoT-Security",
        "description": "IoT cloud API security: auth testing, IDOR, rate limiting, data exposure, MQTT cloud broker.",
        "params": [{"name": "api_endpoint", "type": "text", "required": True, "help": "API endpoint URL"}],
        "dependencies": ["curl"], "quality": GOOD,
        "expected_output": "API discovery, auth bypass testing, IDOR on device IDs, rate limiting, data exposure check.",
    },
    "iot_device_hardening_audit.sh": {
        "name": "IoT Device Hardening Audit",
        "category": "20-IoT-Security",
        "description": "IoT hardening: open ports, default creds, TLS config, debug interfaces, update mechanism, services.",
        "params": [{"name": "device_ip", "type": "text", "required": True, "help": "Device IP address"}],
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": "Port audit, default credential check, TLS analysis, debug interface exposure, firmware version, update check.",
    },
    "iot_supply_chain_scanner.sh": {
        "name": "IoT Supply Chain Scanner",
        "category": "20-IoT-Security",
        "description": "Supply chain: vendor identification, CVE lookup, third-party libraries, EOL detection, SBOM analysis.",
        "params": [{"name": "vendor_info", "type": "text", "required": True, "help": "Vendor, product, or device IP"}],
        "dependencies": ["curl", "nmap"], "quality": GOOD,
        "expected_output": "Vendor fingerprint, CVE database lookup, component detection, EOL/EOS check, SBOM reference.",
    },
    "iot_physical_attack_plan.sh": {
        "name": "Physical Attack Planner",
        "category": "20-IoT-Security",
        "description": "Physical attack surface: debug interfaces, storage chips, side-channel, tamper detection, assessment template.",
        "params": [{"name": "device_model", "type": "text", "required": True, "help": "Device model or identifier"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": "Physical interface checklist (UART/JTAG/SWD), storage analysis, side-channel reference, tamper detection.",
    },
    "iot_reporting_formatter.sh": {
        "name": "IoT Report Formatter",
        "category": "20-IoT-Security",
        "description": "Consolidates IoT assessment results into HTML report with risk scoring and remediation.",
        "params": [{"name": "assessment_data", "type": "text", "required": True, "help": "Assessment data directory"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": "STATUS: STUB - This script needs implementation.",
    },

    # ═══════════════════════════════════════════════════════════════
    # 21-Bypass-Techniques (20 scripts)
    # ═══════════════════════════════════════════════════════════════
    "ids_ips_bypass.sh": {
        "name": "IDS/IPS Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests IDS/IPS bypass: packet fragmentation, timing attacks, protocol manipulation, source spoofing, payload obfuscation.",
        "params": [
            {"name": "target_ip", "type": "text", "required": True, "help": "Target IP address"},
        ],
        "dependencies": ["nmap", "curl", "openssl", "nc", "ping"],
        "quality": GOOD,
        "expected_output": (
            "10 bypass phases with results per technique:\n"
            "Fragmentation: Fragmented scan vs. normal scan comparison.\n"
            "Timing: Slow scan evasion results.\n"
            "Protocol: FIN/Xmas/Null/ACK scan responses.\n"
            "Spoofing: Decoy scan results.\n"
            "Application: HTTP evasion technique results.\n"
            "Payload/Network/Session/Crypto/Advanced evasion results."
        ),
    },
    "authentication_bypass.sh": {
        "name": "Authentication Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests auth bypass: SQL injection, default creds, session fixation, JWT manipulation, OAuth, HPP, verb tampering, NoSQL/LDAP injection.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL (e.g., https://example.com/login)"},
        ],
        "dependencies": ["curl", "base64", "jq"],
        "quality": GOOD,
        "expected_output": (
            "12 bypass phases:\n"
            "Auth Discovery: Login form and mechanism identification.\n"
            "SQL Injection: Auth bypass payload results.\n"
            "Default Creds: Common username/password test results.\n"
            "Session Fixation: Session manipulation results.\n"
            "JWT: Token decode and manipulation results.\n"
            "OAuth/HPP/Verb/NoSQL/LDAP/Password Reset/Race Condition results."
        ),
    },
    "rate_limiting_bypass.sh": {
        "name": "Rate Limiting Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests rate limiting bypass: header manipulation, user-agent rotation, session rotation, parameter pollution, encoding.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL"},
        ],
        "dependencies": ["curl", "nc"],
        "quality": GOOD,
        "expected_output": (
            "10 bypass phases:\n"
            "Detection: Baseline rate limit identification.\n"
            "Headers: X-Forwarded-For, X-Real-IP manipulation results.\n"
            "User-Agent: Rotation effectiveness.\n"
            "Sessions: Cookie rotation results.\n"
            "Parameter Pollution: HPP bypass results.\n"
            "Encoding/Protocol/Advanced evasion results."
        ),
    },
    "ssl_tls_bypass.sh": {
        "name": "SSL/TLS Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests SSL/TLS bypass: version downgrade, cert validation bypass, SNI bypass, cipher manipulation, HSTS bypass.",
        "params": [
            {"name": "target_host", "type": "text", "required": True, "help": "Target hostname"},
            {"name": "port", "type": "text", "required": False, "help": "Port (default: 443)"},
        ],
        "dependencies": ["openssl", "curl", "nmap", "nc"],
        "quality": GOOD,
        "expected_output": (
            "8 bypass phases:\n"
            "Downgrade: SSLv3/TLS1.0 acceptance results.\n"
            "Certificate: Validation bypass attempts.\n"
            "SNI: SNI manipulation responses.\n"
            "Ciphers: Weak/export cipher acceptance.\n"
            "Protocol: POODLE/BEAST/CRIME/FREAK/Logjam checks.\n"
            "HSTS: Header analysis and bypass attempts."
        ),
    },
    "csrf_protection_bypass.sh": {
        "name": "CSRF Protection Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests CSRF protection bypass: token manipulation, Referer bypass, method override, Content-Type bypass. Generates PoC HTML.",
        "params": [
            {"name": "-u/--url", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-c/--cookies", "type": "text", "required": False, "help": "Cookie file path"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
        ],
        "dependencies": ["curl", "grep", "sed", "awk"],
        "quality": GOOD,
        "expected_output": (
            "Token Analysis: CSRF token presence and format.\n"
            "Token Bypass: Missing/empty/invalid/reused token results.\n"
            "Referer Bypass: Header manipulation results.\n"
            "Method Override: X-HTTP-Method-Override results.\n"
            "Content-Type: Alternative content type results.\n"
            "PoC: HTML proof-of-concept file generated."
        ),
    },
    "dlp_bypass.sh": {
        "name": "DLP Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests Data Loss Prevention bypass: encoding, compression, steganography, protocol manipulation, fragmentation, timing.",
        "params": [
            {"name": "-u/--url", "type": "text", "required": True, "help": "Target URL"},
            {"name": "-d/--data", "type": "text", "required": False, "help": "Sensitive data file"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
        ],
        "dependencies": ["curl", "base64", "xxd", "openssl", "zip", "gzip"],
        "quality": GOOD,
        "expected_output": (
            "Encoding: Base64/URL/Hex/ROT13 bypass results.\n"
            "Compression: GZIP/ZIP/password-ZIP bypass results.\n"
            "Steganography: Image comment, whitespace hiding results.\n"
            "Protocol: HTTP method/content-type variation results.\n"
            "Fragmentation: Split/interleave/reverse data results.\n"
            "Timing: Slow exfiltration detection threshold testing."
        ),
    },
    "endpoint_detection_bypass.sh": {
        "name": "EDR/AV Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests EDR bypass: AV detection, process evasion, network evasion, payload encoding, signature evasion, anti-analysis.",
        "params": [
            {"name": "-t/--target", "type": "text", "required": True, "help": "Target host"},
            {"name": "-m/--mode", "type": "select", "required": False, "options": ["safe", "moderate", "aggressive"], "help": "Test mode (default: safe)"},
            {"name": "-o/--output", "type": "text", "required": False, "help": "Output directory"},
            {"name": "-v/--verbose", "type": "flag", "required": False, "help": "Verbose output"},
        ],
        "dependencies": ["curl", "nmap", "nc", "python3", "base64", "xxd", "openssl"],
        "quality": GOOD,
        "expected_output": (
            "EDR Detection: AV/EDR product identification.\n"
            "Process Evasion: Name obfuscation, DLL injection results.\n"
            "Network Evasion: C2 channel detection bypass results.\n"
            "Payload Evasion: Encoded payload detection results.\n"
            "Signature Evasion: Obfuscation technique results.\n"
            "Generated: Python scripts for further testing."
        ),
    },
    "captcha_bypass.sh": {
        "name": "CAPTCHA Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests CAPTCHA bypass: detection, automation, OCR-based bypass, audio bypass, behavioral analysis, rate limiting.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL with CAPTCHA"},
        ],
        "dependencies": ["curl", "tesseract (optional)", "gocr (optional)"],
        "quality": GOOD,
        "expected_output": (
            "Detection: CAPTCHA type identification (reCAPTCHA, hCaptcha, etc.)\n"
            "Automation: Bot detection analysis.\n"
            "OCR: Image CAPTCHA solving attempts.\n"
            "Note: Audio and behavioral phases are mostly informational."
        ),
    },
    "input_validation_bypass.sh": {
        "name": "Input Validation Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Tests input validation bypass: URL/double-URL/hex encoding, case manipulation, comment insertion for SQL/XSS.",
        "params": [
            {"name": "target_url", "type": "text", "required": True, "help": "Target URL"},
        ],
        "dependencies": ["curl"],
        "quality": GOOD,
        "expected_output": (
            "Encoding Bypass: URL, double-URL, hex encoded payload results.\n"
            "Case Manipulation: Mixed case bypass results.\n"
            "Comment Insertion: SQL/XSS comment bypass results.\n"
            "Note: Phases 4-12 (whitespace, path traversal, XXE, etc.) are stubs."
        ),
    },
    "dns_tunneling_bypass.sh": {
        "name": "DNS Tunneling Bypass",
        "category": "21-Bypass-Techniques",
        "description": "DNS tunneling feasibility testing: record types, exfil simulation, DoH/DoT, tool references.",
        "params": [{"name": "target", "type": "text", "required": True, "help": "Target domain or IP"}],
        "extra_args_help": "-d DNS_SERVER",
        "dependencies": ["dig", "nmap"], "quality": GOOD,
        "expected_output": (
            "Phase 1: DNS infrastructure recon (resolver, recursion, record types).\n"
            "Phase 2: Tunneling feasibility (query length, depth, DoH/DoT).\n"
            "Phase 3: DNS exfiltration simulation (hex/base32 encoded).\n"
            "Phase 4: Tool reference (iodine, dnscat2, dns2tcp)."
        ),
    },
    "authorization_bypass.sh": {
        "name": "Authorization Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Authorization bypass: IDOR, privilege escalation, path traversal, URL normalization, JWT manipulation.",
        "params": [{"name": "target_app", "type": "text", "required": True, "help": "Target application URL"}],
        "extra_args_help": "-c COOKIE -T 'Bearer TOKEN'",
        "dependencies": ["curl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: IDOR testing (numeric IDs, method change).\n"
            "Phase 2: Privilege escalation (admin endpoints, role injection).\n"
            "Phase 3: Path traversal & URL normalization bypass.\n"
            "Phase 4: JWT/token manipulation techniques."
        ),
    },
    "sandbox_escape.sh": {
        "name": "Sandbox Escape",
        "category": "21-Bypass-Techniques",
        "description": "Sandbox escape: container detection, Docker socket, privileged mode, chroot, AppArmor/seccomp bypass.",
        "params": [{"name": "sandbox_env", "type": "text", "required": False, "help": "Target (default: localhost)"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": (
            "Phase 1: Environment detection (container, namespace, capabilities).\n"
            "Phase 2: Container escape checks (Docker socket, privileged, cgroups).\n"
            "Phase 3: chroot escape checks.\n"
            "Phase 4: Security module bypass (AppArmor, seccomp, SELinux)."
        ),
    },
    "smb_relay_bypass.sh": {
        "name": "SMB Relay Bypass",
        "category": "21-Bypass-Techniques",
        "description": "SMB relay bypass: signing analysis, cross-protocol relay, coercion attacks, EPA/channel binding checks.",
        "params": [{"name": "target_network", "type": "text", "required": True, "help": "Target network CIDR or host"}],
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: SMB signing analysis and relay target identification.\n"
            "Phase 2: Cross-protocol relay paths (LDAP, HTTP, MSSQL, ADCS).\n"
            "Phase 3: Authentication coercion (PetitPotam, PrinterBug, DFS).\n"
            "Phase 4: EPA & channel binding bypass analysis."
        ),
    },
    "kerberos_bypass.sh": {
        "name": "Kerberos Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Kerberos bypass: pre-auth, encryption downgrade, delegation abuse, PAC manipulation, clock skew.",
        "params": [{"name": "domain_controller", "type": "text", "required": True, "help": "Domain controller IP"}],
        "extra_args_help": "-d DOMAIN -u USER -p PASS",
        "dependencies": ["nmap", "python3"], "quality": GOOD,
        "expected_output": (
            "Phase 1: Pre-authentication bypass (AS-REP Roasting).\n"
            "Phase 2: Encryption downgrade (RC4 vs AES, overpass-the-hash).\n"
            "Phase 3: Delegation abuse (unconstrained, constrained, RBCD).\n"
            "Phase 4: PAC manipulation (noPac, MS14-068, Diamond Ticket)."
        ),
    },
    "ldap_injection_bypass.sh": {
        "name": "LDAP Injection Bypass",
        "category": "21-Bypass-Techniques",
        "description": "LDAP injection: filter bypass, authentication bypass, blind LDAP extraction, enumeration.",
        "params": [{"name": "ldap_server", "type": "text", "required": True, "help": "LDAP server address"}],
        "extra_args_help": "-w WEB_URL (for web-based LDAP injection)",
        "dependencies": ["nmap", "curl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: LDAP service recon (rootDSE, anonymous bind, brute force).\n"
            "Phase 2: LDAP injection payloads (auth bypass, filter injection).\n"
            "Phase 3: Blind LDAP injection (boolean, character extraction).\n"
            "Phase 4: LDAP enumeration (users, groups, computers)."
        ),
    },
    "proxy_load_balancer_bypass.sh": {
        "name": "Proxy/LB Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Proxy/WAF/CDN bypass: origin discovery, header manipulation, WAF rule evasion, encoding bypass.",
        "params": [{"name": "target_infrastructure", "type": "text", "required": True, "help": "Target URL or domain"}],
        "dependencies": ["curl", "dig", "nmap"], "quality": GOOD,
        "expected_output": (
            "Phase 1: Proxy/CDN/WAF detection (headers, indicators).\n"
            "Phase 2: Origin server discovery (DNS, crt.sh, subdomains).\n"
            "Phase 3: Header-based bypass (X-Forwarded-For, Host, IP spoof).\n"
            "Phase 4: WAF rule bypass (encoding, content-type, chunked)."
        ),
    },
    "network_segmentation_bypass.sh": {
        "name": "Network Segmentation Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Segmentation bypass: VLAN hopping, firewall ACL testing, tunneling, pivoting techniques.",
        "params": [{"name": "target_network", "type": "text", "required": True, "help": "Target network CIDR"}],
        "extra_args_help": "-s SOURCE_NETWORK",
        "dependencies": ["nmap", "ping"], "quality": GOOD,
        "expected_output": (
            "Phase 1: Cross-segment connectivity testing (ICMP, TCP, UDP).\n"
            "Phase 2: Firewall/ACL rule testing (fragmentation, source port).\n"
            "Phase 3: VLAN & Layer 2 bypass (DTP, double tagging, ARP).\n"
            "Phase 4: Tunneling & pivoting (SSH, chisel, DNS, ICMP tunnels)."
        ),
    },
    "captive_portal_bypass.sh": {
        "name": "Captive Portal Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Captive portal bypass: DNS leak, MAC spoofing, protocol tunneling, direct IP access.",
        "params": [{"name": "portal_network", "type": "text", "required": True, "help": "Portal gateway IP or network"}],
        "extra_args_help": "-i INTERFACE",
        "dependencies": ["nmap", "curl", "dig"], "quality": GOOD,
        "expected_output": (
            "Phase 1: Portal reconnaissance (gateway, DNS, ARP table).\n"
            "Phase 2: DNS-based bypass (external DNS, DoH, tunneling).\n"
            "Phase 3: MAC spoofing (authenticated client cloning).\n"
            "Phase 4: Protocol & port bypass (VPN, ICMP, allowed domains)."
        ),
    },
    "certificate_pinning_bypass.sh": {
        "name": "Certificate Pinning Bypass",
        "category": "21-Bypass-Techniques",
        "description": "Cert pinning bypass: TLS analysis, Frida/Objection, Android/iOS bypass, proxy interception setup.",
        "params": [{"name": "target_app", "type": "text", "required": True, "help": "Target domain or app"}],
        "dependencies": ["curl", "openssl"], "quality": GOOD,
        "expected_output": (
            "Phase 1: Certificate & TLS analysis (chain, pins, HPKP).\n"
            "Phase 2: Android bypass (Frida, Objection, APK patching).\n"
            "Phase 3: iOS bypass (SSL Kill Switch, Frida hooks).\n"
            "Phase 4: Proxy interception setup (CA install, tool config)."
        ),
    },
    "siem_log_evasion.sh": {
        "name": "SIEM/Log Evasion",
        "category": "21-Bypass-Techniques",
        "description": "SIEM evasion: log coverage analysis, blind spots, LOLBins, timestomping, detection rule testing.",
        "params": [{"name": "target_network", "type": "text", "required": True, "help": "Target network or 'localhost'"}],
        "dependencies": [], "quality": GOOD,
        "expected_output": (
            "Phase 1: Log coverage analysis (active sources, syslog, audit).\n"
            "Phase 2: Detection blind spots (LOLBins, process logging gaps).\n"
            "Phase 3: Evasion techniques (log tampering, fileless, encoding).\n"
            "Phase 4: Detection rule testing (trigger events, SIEM validation)."
        ),
    },
}
