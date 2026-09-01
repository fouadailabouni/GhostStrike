# Quick Start

## 1. Launch the GUI

```bash
make gui
# or: python3 CyberToolkit/ghoststrike.py
```

Create a new engagement from the GUI (or `gs_engagement`-style helpers under
`lib/engagement.sh` if you're scripting) before running modules against a
real target — the policy engine expects `GS_ENGAGEMENT_ID` and a scope file
outside of `lab` environments (see [SAFETY_MODEL.md](SAFETY_MODEL.md)).

## 2. Run a module directly

```bash
cd bash_scripts_for_pentest

# Network scan, with policy enforcement + evidence capture
./repro_runner.sh 01-Network-Security/nmap_automation.sh 192.168.1.0/24

# Web application assessment
./repro_runner.sh 02-Web-Application-Security/owasp_top10_scanner.sh https://target.example.com
```

`repro_runner.sh` wraps any module with reproducibility instrumentation —
tool versions, logged commands, artifact hashes — and scores the run 0–100
afterward. You can also invoke a module directly without the wrapper; the
policy gate still runs either way.

## 3. Try it safely against a known-vulnerable target

```bash
cd bash_scripts_for_pentest
./benchmarks/run_benchmarks.sh --target all --report
```

This runs real modules against DVWA, Juice Shop, and a Metasploitable-style
lab container and scores PASS/FAIL against expected findings defined in
`benchmarks/scenarios/*.yaml` — a safe way to see GhostStrike work end-to-end
before pointing it at anything else.

## 4. Check reproducibility of past runs

```bash
cd bash_scripts_for_pentest
./metrics/reproducibility_report.sh
```

## 5. Try AI Co-Pilot mode (optional)

Toggle Manual → AI in the GUI. Pick a persona (Red Team, Blue Team, Web
Pentest, CTF Solver, DFIR, ...) and describe a task in plain language. Every
module call the agent makes still passes through the same `gs_policy_gate`
check a manual run does — see [AI_COPILOT.md](AI_COPILOT.md).

## Next

- [MODULE_SYSTEM.md](MODULE_SYSTEM.md) — categories, trust levels, adding a module
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit together
- [SAFETY_MODEL.md](SAFETY_MODEL.md) — policy engine, scope enforcement, the vault