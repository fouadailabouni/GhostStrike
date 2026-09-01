# Installing GhostStrike

GhostStrike is a Linux-native toolkit: the bash module framework needs a real
bash + coreutils environment, and the GUI is a desktop app, not a web service.
On Windows, run it under WSL2.

## Requirements

| Component | Requirement | Why |
|---|---|---|
| Bash | 4.0+ | The module framework itself |
| Python | 3.8+ | GUI, AI Co-Pilot, Report Studio, MCP server |
| nmap | any recent | Network discovery/scanning modules |
| sqlmap | any recent | SQL injection modules |
| nikto | any recent | Web server scanning modules |
| metasploit-framework | any recent | Exploitation/session modules |
| jq | any recent | JSON parsing across most modules |
| python3-jsonschema | — | Finding schema validation |
| pyyaml | — | `policy.yaml`-driven policy enforcement |
| anthropic / openai | optional | Only needed for AI Co-Pilot mode |
| mcp>=2.0.0 | optional | Only needed for the MCP server |
| weasyprint | optional | Only needed for Report Studio PDF export |

## Install

```bash
git clone https://github.com/fouadailabouni/GhostStrike.git
cd GhostStrike

# System tools
sudo apt-get update
sudo apt-get install -y nmap masscan nikto dirb sqlmap metasploit-framework jq python3-pip

# Python dependencies
make install
# equivalent to: pip install -r CyberToolkit/requirements.txt

# Optional: AI Co-Pilot mode
pip3 install anthropic openai

# Optional: initialize the credential vault
make vault-init
```

Or run the installer, which does environment detection, classifies missing
tools into CORE/RECOMMENDED/SPECIALIZED tiers, and prompts before installing
anything beyond CORE:

```bash
./install.sh          # interactive
./install.sh --yes    # non-interactive, installs CORE + RECOMMENDED
```

Check overall health any time with:

```bash
bash bash_scripts_for_pentest/00-Framework-Core/system_doctor.sh
```

### Troubleshooting: `pip install` fails

Two real failure modes you may hit on current Debian/Ubuntu, both handled by
`install.sh` and `make install` automatically — worth knowing about if you're
installing manually instead:

- **`externally-managed-environment` (PEP 668)** — current Debian/Ubuntu
  block a bare `pip install` system-wide. Fix: add `--break-system-packages`.
- **`Cannot uninstall X, RECORD file not found... installed by debian`** —
  happens when a dependency (e.g. `typing_extensions`) is already present as
  an apt package and pip tries to upgrade it. Fix: add
  `--ignore-installed <package-name>` for the specific package pip
  complains about, alongside `--break-system-packages`.

## Local-first AI (optional, no cloud required)

AI Co-Pilot doesn't require a cloud API key — see
[AI_COPILOT.md](AI_COPILOT.md#local-first-ai-no-cloud-required) for wiring
up Ollama or another OpenAI-compatible local server instead.

## Launch

```bash
make gui
# equivalent to: python3 CyberToolkit/ghoststrike.py
```

## Verify the install

```bash
make syntax    # bash -n every module
make lint      # ShellCheck every module
make test      # lib-level unit tests (tests/test_framework.sh)
bash tests/module_smoke_test.sh   # per-module arg-parsing/exit-code smoke test
```

All four are what `.github/workflows/ci.yml` runs on every push — if they pass
locally, CI will too.

See [QUICKSTART.md](QUICKSTART.md) for what to do once it's running.