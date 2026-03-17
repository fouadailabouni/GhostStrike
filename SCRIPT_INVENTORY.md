# GhostStrike — Complete Script Inventory
> © 2026 Fouad Ailabouni. All Rights Reserved.
> Generated: 2026-03-15 | Total Scripts: 103 + lib/common.sh

## Trust Level Legend
| Level | Description |
|-------|-------------|
| SAFE_ENUM | Passive enumeration & read-only discovery — safe on production |
| VALIDATION | Non-destructive probes & configuration checks |
| HIGH_IMPACT | Active exploitation — requires written authorization |
| LAB_ONLY | Destructive techniques — lab/isolated environment only |

## Quality Status Legend
| Status | Description |
|--------|-------------|
| GOOD | Full professional implementation, all phases complete |
| PARTIAL | Functional but some techniques or phases still expanding |

---

## 00 — Framework Core (5 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 1 | authorization_framework.sh | 409 | VALIDATION | RBAC checks, permission matrix, scope enforcement, audit trail | GOOD |
| 2 | ci_linting_framework.sh | 738 | SAFE_ENUM | ShellCheck CI, static analysis, lint scoring, badge output | GOOD |
| 3 | framework_tester.sh | 565 | VALIDATION | Self-test suite, module integration tests, pass/fail scoring | GOOD |
| 4 | json_output_framework.sh | 483 | SAFE_ENUM | JSON schema output, finding normalization, report serialization | GOOD |
| 5 | mitre_attack_framework.sh | 546 | SAFE_ENUM | ATT&CK mapping, tactic/technique tagging, TTP matrix export | GOOD |

---

## 01 — Network Security (12 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 6 | dns_recon.sh | 574 | SAFE_ENUM | Zone transfer, subdomain brute-force, DNS records, reverse lookups | GOOD |
| 7 | firewall_rule_tester.sh | 377 | VALIDATION | Port probing, rule bypass, egress/ingress testing, response codes | PARTIAL |
| 8 | network_traffic_analyzer.sh | 441 | VALIDATION | Packet capture, protocol analysis, anomaly detection, flow stats | GOOD |
| 9 | nmap_automation.sh | 630 | VALIDATION | -sV -sS -A -T4, NSE scripts, vuln/exploit NSE, OS detection, service enum | GOOD |
| 10 | nmap_vulnerability_scanner.sh | 549 | VALIDATION | CVE detection, NSE vuln scripts, service fingerprinting, risk scoring | GOOD |
| 11 | nmap_waf_bypass.sh | 599 | HIGH_IMPACT | WAF evasion, decoy scanning, fragmentation, source port spoofing | GOOD |
| 12 | service_discovery.sh | 597 | SAFE_ENUM | Nmap/masscan sweep, banner grabbing, service version identification | GOOD |
| 13 | snmp_enum.sh | 657 | SAFE_ENUM | SNMPv1/v2/v3, community strings, MIB walk, oid dump, user enum | GOOD |
| 14 | ssl_tls_analyzer.sh | 350 | SAFE_ENUM | SSLyze/testssl, cipher suites, cert validity, HSTS, OCSP | PARTIAL |
| 15 | subdomain_enum.sh | 652 | SAFE_ENUM | Amass/subfinder/gobuster, DNS brute-force, cert transparency CT | GOOD |
| 16 | system_config_audit.sh | 845 | VALIDATION | CIS benchmarks, sysctl, PAM config, SSH hardening, service audit | GOOD |
| 17 | vpn_security_assessment.sh | 450 | VALIDATION | IKE scanning, VPN fingerprint, PSK testing, split tunnel check | GOOD |

---

## 02 — Web Application Security (8 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 18 | advanced_web_app_tester.sh | 341 | HIGH_IMPACT | OWASP Top 10, XSS/SQLi/IDOR/SSRF, auth bypass chains, race conditions | PARTIAL |
| 19 | api_security_tester.sh | 143 | VALIDATION | REST/GraphQL endpoints, auth header tests, rate-limit probes | GOOD |
| 20 | graphql_security_tester.sh | 551 | HIGH_IMPACT | Introspection abuse, batch query DoS, field suggestion, injection | GOOD |
| 21 | jwt_token_manipulator.sh | 567 | HIGH_IMPACT | alg:none attack, RS→HS256 confusion, weak secret brute, kid injection | GOOD |
| 22 | owasp_top10_scanner.sh | 752 | HIGH_IMPACT | Full OWASP A01–A10, nikto, nuclei templates, active/passive | GOOD |
| 23 | sqlmap_automated_pentest.sh | 411 | HIGH_IMPACT | SQLmap crawl, blind/time-based SQLi, dump, OS shell, tamper scripts | GOOD |
| 24 | webapp_testing.sh | 108 | VALIDATION | Basic curl probes, header checks, simple form submission tests | GOOD |
| 25 | websocket_security_tester.sh | 422 | HIGH_IMPACT | WS hijacking, CSWSH, message injection, token replay, origin bypass | GOOD |

---

## 03 — Wireless Security (2 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 26 | bluetooth_scanner.sh | 182 | SAFE_ENUM | HCI inquiry, bluetoothctl, device discovery, service profile enum | GOOD |
| 27 | wifi_penetration_tester.sh | 423 | HIGH_IMPACT | WPA2/WPA3 handshake capture, PMKID, evil twin, deauth, aircrack-ng | GOOD |

---

## 04 — Database Security (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 28 | database_attack_vectors.sh | 563 | HIGH_IMPACT | MySQL/MSSQL/Oracle/PostgreSQL auth bypass, priv-esc, UDF load | GOOD |
| 29 | database_penetration_tester.sh | 416 | HIGH_IMPACT | Credential stuffing, weak creds, schema dump, stored proc abuse | GOOD |
| 30 | nosql_database_tester.sh | 497 | HIGH_IMPACT | MongoDB/Redis/CouchDB auth bypass, NoSQL injection, data exposure | GOOD |

---

## 05 — Active Directory (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 31 | active_directory_tester.sh | 414 | HIGH_IMPACT | BloodHound, LDAPsearch, AS-REP roasting, ACL abuse, DC sync | GOOD |
| 32 | kerberos_attack_suite.sh | 506 | HIGH_IMPACT | Kerberoasting, AS-REP, Pass-The-Ticket, Golden/Silver ticket, S4U | GOOD |
| 33 | ntlm_relay_tester.sh | 503 | HIGH_IMPACT | Responder, ntlmrelayx, SMB relay, LDAP relay, coerce auth, signing | GOOD |

---

## 06 — Password Attacks (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 34 | hash_analyzer_cracker.sh | 588 | HIGH_IMPACT | Hash-ID, hashcat rules/masks, john the ripper, rainbow tables | GOOD |
| 35 | password_attack_suite.sh | 452 | HIGH_IMPACT | Hydra/medusa, credential stuffing, mask attacks, combinator | GOOD |
| 36 | password_spraying_campaign.sh | 472 | HIGH_IMPACT | O365/AD spray, lockout-aware timing, Kerbrute, spray metrics | GOOD |

---

## 07 — Social Engineering (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 37 | email_harvesting_osint.sh | 433 | SAFE_ENUM | theHarvester, hunter.io, LinkedIn scrape, breach data correlation | GOOD |
| 38 | phishing_campaign_automation.sh | 465 | HIGH_IMPACT | GoPhish integration, lure crafting, tracking pixels, C2 callback | GOOD |
| 39 | social_engineering_toolkit.sh | 221 | HIGH_IMPACT | SET menu wrapper, credential harvester, Java applet, spear-phish | PARTIAL |

---

## 08 — System Security (4 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 40 | file_integrity_monitor.sh | 394 | SAFE_ENUM | SHA256 baseline, inotify watch, recursive diff, FIM alert report | PARTIAL |
| 41 | log_analyzer.sh | 167 | SAFE_ENUM | auth.log/syslog parse, fail2ban patterns, brute-force detection | GOOD |
| 42 | patch_management_scanner.sh | 228 | SAFE_ENUM | apt/yum/dnf CVE scan, USN advisories, unpatched package report | PARTIAL |
| 43 | system_config_audit.sh | 171 | SAFE_ENUM | CIS Level-1 checks, SUID files, world-writable dirs, umask | GOOD |

---

## 09 — Container Security (1 script)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 44 | container_security_scanner.sh | 696 | VALIDATION | Trivy/Grype image scan, Dockerfile lint, CIS Docker benchmark, secrets | GOOD |

---

## 10 — Mobile Security (2 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 45 | android_apk_analyzer.sh | 493 | VALIDATION | Apktool decompile, MobSF, OWASP MASVS checks, perm audit, dex | GOOD |
| 46 | ios_app_analyzer.sh | 516 | VALIDATION | IPA unpack, class-dump, Frida dynamic hooks, MASVS checks | GOOD |

---

## 11 — Cloud Security (4 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 47 | aws_security_scanner.sh | 656 | VALIDATION | Prowler/ScoutSuite, S3 public ACL, IAM over-privilege, CIS AWS | GOOD |
| 48 | azure_gcp_enumeration.sh | 512 | VALIDATION | AzureHound, Microburst, GCP IAM audit, storage bucket enumeration | GOOD |
| 49 | cloud_storage_bucket_tester.sh | 492 | VALIDATION | S3/Azure Blob/GCS public access, ACL read/write test, listing | GOOD |
| 50 | container_orchestration_security.sh | 366 | VALIDATION | K8s RBAC audit, pod security policy, etcd exposure, dashboard | PARTIAL |

---

## 12 — Exploitation (1 script)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 51 | metasploit_automation.sh | 389 | LAB_ONLY | msfconsole rc-files, auto-exploit, payload generation, session mgmt | PARTIAL |

---

## 13 — Post-Exploitation (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 52 | data_exfiltration_simulator.sh | 443 | LAB_ONLY | DNS/HTTP/ICMP exfil channels, data staging, chunking, C2 callback | GOOD |
| 53 | persistence_mechanisms.sh | 397 | LAB_ONLY | Cron, systemd, LD_PRELOAD, .bashrc/.profile, PAM backdoor | PARTIAL |
| 54 | privilege_escalation_checker.sh | 821 | HIGH_IMPACT | SUID/SGID, sudo misconfig, cron wildcards, PATH hijack, GTFOBins | GOOD |

---

## 14 — Reporting Tools (1 script)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 55 | pentest_report_generator.sh | 516 | SAFE_ENUM | HTML/PDF/Markdown reports, CVSS scoring, findings table, exec summary | GOOD |

---

## 15 — Automation Tools (2 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 56 | install_pentest_tools.sh | 574 | SAFE_ENUM | Full toolchain install (nmap, msfconsole, burp, metasploit, etc.) | GOOD |
| 57 | pentest_automation.sh | 602 | VALIDATION | Full pipeline: recon→scan→exploit→report orchestration | GOOD |

---

## 16 — Specialized Testing (3 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 58 | ics_scada_tester.sh | 344 | HIGH_IMPACT | Modbus/DNP3/IEC-104 probe, coil read, register enum, HMI fingerprint | PARTIAL |
| 59 | iot_security_tester.sh | 151 | VALIDATION | MQTT/CoAP probe, default credential check, firmware version | GOOD |
| 60 | thick_client_tester.sh | 868 | HIGH_IMPACT | DLL injection, memory dump, traffic intercept, API reverse, SQLi | GOOD |

---

## 17 — Monitoring & Detection (4 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 61 | incident_response_toolkit.sh | 478 | SAFE_ENUM | IR triage, artifact collection, forensic timeline, IOC matching | GOOD |
| 62 | intrusion_detection_system.sh | 546 | SAFE_ENUM | Suricata/Snort rules, alert tuning, PCAP analysis, signature gen | GOOD |
| 63 | security_metrics_dashboard.sh | 402 | SAFE_ENUM | CVSS trends, SLA metrics, finding counts, risk heat map | GOOD |
| 64 | threat_intelligence_collector.sh | 530 | SAFE_ENUM | OTX/VirusTotal/MISP feeds, IOC enrichment, TTP hunting | GOOD |

---

## 18 — Application Security (2 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 65 | code_quality_checker.sh | 526 | SAFE_ENUM | Semgrep/bandit/eslint SAST, complexity, hardcoded secrets, SCA | GOOD |
| 66 | dependency_vulnerability_scanner.sh | 563 | SAFE_ENUM | npm audit, safety, OWASP dep-check, SBOM generation, CVE feed | GOOD |

---

## 19 — Lab Environment (1 script)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 67 | docker_lab_setup.sh | 918 | LAB_ONLY | DVWA, Juice Shop, Metasploitable, VulnHub containers, network config | GOOD |

---

## 20 — IoT Security (16 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 68 | iot_cloud_api_tester.sh | 289 | VALIDATION | REST/MQTT cloud API auth, IDOR, rate-limit, JWT/OAuth abuse | PARTIAL |
| 69 | iot_coap_tester.sh | 279 | VALIDATION | CoAP GET/PUT/POST, resource discovery, block transfer, DTLS | PARTIAL |
| 70 | iot_default_creds_scanner.sh | 228 | HIGH_IMPACT | Default username/password lists across 200+ IoT device vendors | PARTIAL |
| 71 | iot_device_hardening_audit.sh | 304 | VALIDATION | OWASP IoT Top 10, service inventory, UART/SSH config check | PARTIAL |
| 72 | iot_firmware_analyzer.sh | 638 | VALIDATION | Binwalk extract, EMBA scan, hardcoded creds, CVE matching | GOOD |
| 73 | iot_firmware_emulation_runner.sh | 284 | LAB_ONLY | QEMU/FirmAE emulation, network bridge setup, service start | PARTIAL |
| 74 | iot_fuzz_coap_mqtt.sh | 270 | HIGH_IMPACT | Boofuzz/radamsa CoAP+MQTT fuzzing, crash detection, replay | PARTIAL |
| 75 | iot_mqtt_tester.sh | 310 | HIGH_IMPACT | MQTT broker auth, topic wildcard abuse, pub/sub test, broker info | PARTIAL |
| 76 | iot_network_isolation_tester.sh | 254 | VALIDATION | VLAN hop attempt, ARP spoof test, broadcast isolation check | PARTIAL |
| 77 | iot_ota_interceptor.sh | 310 | HIGH_IMPACT | OTA update MITM, firmware signature bypass, version downgrade | PARTIAL |
| 78 | iot_physical_attack_plan.sh | 307 | LAB_ONLY | JTAG/UART extraction plan, debug port map, boot mode manipulation | PARTIAL |
| 79 | iot_reporting_formatter.sh | 311 | SAFE_ENUM | IoT finding formatter, OWASP IoT Top 10 mapping, HTML report | PARTIAL |
| 80 | iot_supply_chain_scanner.sh | 306 | VALIDATION | Component inventory, CVE lookup, vendor security advisories | PARTIAL |
| 81 | iot_uart_jtag_helper.sh | 317 | LAB_ONLY | UART baud detection, JTAG pin scan, OpenOCD config generation | PARTIAL |
| 82 | iot_wireless_ble_scanner.sh | 309 | VALIDATION | BLE GATT enumeration, characteristic read/write, pairing test | PARTIAL |
| 83 | iot_zigbee_thread_scanner.sh | 325 | VALIDATION | Zigbee channel scan, network key sniff, Thread border router enum | PARTIAL |

---

## 21 — Bypass Techniques (20 scripts)

| # | Script | Lines | Trust Level | Key Techniques | Quality |
|---|--------|-------|-------------|----------------|---------|
| 84 | authentication_bypass.sh | 683 | HIGH_IMPACT | SQL auth bypass, JWT none/confusion, SAML forge, OAuth PKCE skip | GOOD |
| 85 | authorization_bypass.sh | 341 | HIGH_IMPACT | IDOR, path traversal, BOLA/BFLA, mass assignment, method override | PARTIAL |
| 86 | captcha_bypass.sh | 428 | HIGH_IMPACT | Token replay, OCR solver, audio bypass, ML solver integration | GOOD |
| 87 | captive_portal_bypass.sh | 260 | HIGH_IMPACT | DNS/HTTP tunnel, MAC spoofing, DNS port 53 bypass, redirect spoof | PARTIAL |
| 88 | certificate_pinning_bypass.sh | 263 | HIGH_IMPACT | Frida SSL unpin, objection, apk-mitm repack, SSLKillSwitch2 | PARTIAL |
| 89 | csrf_protection_bypass.sh | 615 | HIGH_IMPACT | Token prediction, same-site bypass, Referer spoof, JSON CSRF | GOOD |
| 90 | dlp_bypass.sh | 668 | HIGH_IMPACT | Steganography, encoding chains, DNS/ICMP covert channel, OOB | GOOD |
| 91 | dns_tunneling_bypass.sh | 365 | HIGH_IMPACT | Iodine/dnscat2, TXT/CNAME tunnels, DNS exfil, query padding | PARTIAL |
| 92 | endpoint_detection_bypass.sh | 889 | LAB_ONLY | AMSI bypass, ETW patch, process hollowing, reflective DLL load | GOOD |
| 93 | ids_ips_bypass.sh | 385 | HIGH_IMPACT | IP fragmentation, TTL manipulation, protocol anomaly, evasion | GOOD |
| 94 | input_validation_bypass.sh | 439 | HIGH_IMPACT | Unicode bypass, null byte inject, double-encoding, parser diff | GOOD |
| 95 | kerberos_bypass.sh | 259 | HIGH_IMPACT | RC4 downgrade, AS-REP without preauth, S4U2self delegation abuse | PARTIAL |
| 96 | ldap_injection_bypass.sh | 274 | HIGH_IMPACT | LDAP filter injection, blind LDAP enum, OOB exfiltration | PARTIAL |
| 97 | network_segmentation_bypass.sh | 308 | HIGH_IMPACT | VLAN double-tag hop, GRE tunnel, pivot via compromised proxy | PARTIAL |
| 98 | proxy_load_balancer_bypass.sh | 296 | HIGH_IMPACT | Host header injection, cache poisoning, HRS, X-Forwarded-For bypass | PARTIAL |
| 99 | rate_limiting_bypass.sh | 487 | HIGH_IMPACT | IP rotation, header spoofing, distributed spray, race condition | GOOD |
| 100 | sandbox_escape.sh | 379 | LAB_ONLY | cgroup escape, namespace pivot, procfs abuse, dirty-cow, container | PARTIAL |
| 101 | siem_log_evasion.sh | 275 | LAB_ONLY | Log deletion, timestamp tampering, decoy event injection, parser abuse | PARTIAL |
| 102 | smb_relay_bypass.sh | 255 | HIGH_IMPACT | SMB signing check, NTLMv2 relay, LDAP shadow cred, coerce auth | PARTIAL |
| 103 | ssl_tls_bypass.sh | 561 | HIGH_IMPACT | BEAST/POODLE/DROWN, protocol downgrade, fake cert, HSTS bypass | GOOD |

---

## Summary Statistics

| Category | Scripts | GOOD | PARTIAL |
|----------|---------|------|---------|
| 00-Framework-Core | 5 | 5 | 0 |
| 01-Network-Security | 12 | 10 | 2 |
| 02-Web-Application-Security | 8 | 8 | 0 |
| 03-Wireless-Security | 2 | 2 | 0 |
| 04-Database-Security | 3 | 3 | 0 |
| 05-Active-Directory | 3 | 3 | 0 |
| 06-Password-Attacks | 3 | 3 | 0 |
| 07-Social-Engineering | 3 | 2 | 1 |
| 08-System-Security | 4 | 2 | 2 |
| 09-Container-Security | 1 | 1 | 0 |
| 10-Mobile-Security | 2 | 2 | 0 |
| 11-Cloud-Security | 4 | 3 | 1 |
| 12-Exploitation | 1 | 0 | 1 |
| 13-Post-Exploitation | 3 | 2 | 1 |
| 14-Reporting-Tools | 1 | 1 | 0 |
| 15-Automation-Tools | 2 | 2 | 0 |
| 16-Specialized-Testing | 3 | 3 | 0 |
| 17-Monitoring-Detection | 4 | 4 | 0 |
| 18-Application-Security | 2 | 2 | 0 |
| 19-Lab-Environment | 1 | 1 | 0 |
| 20-IoT-Security | 16 | 2 | 14 |
| 21-Bypass-Techniques | 20 | 11 | 9 |
| **TOTAL** | **103** | **71** | **32** |

### Trust Level Distribution
| Trust Level | Count |
|-------------|-------|
| SAFE_ENUM | 27 |
| VALIDATION | 28 |
| HIGH_IMPACT | 40 |
| LAB_ONLY | 8 |
