# GhostStrike — CyberToolkit GUI Launcher

> © 2026 Fouad Ailabouni. All Rights Reserved.

---

## Overview

CyberToolkit is the graphical front-end for GhostStrike v3.0.0 [PHANTOM]. Built on CustomTkinter with a dark void aesthetic, it provides a unified interface for launching all 164 offensive security modules, monitoring live execution output, tracking threat levels, and navigating GhostStrike's 22 attack surface categories without touching a terminal directly. An optional AI Co-Pilot mode lets a specialized agent persona drive modules on your behalf, gated through the identical policy/trust/scope checks a manual run goes through.

The interface runs on a `#05060a` near-black background with neon accent colors — purple for primary actions, red for threat indicators, green for success states — maintaining the operational tone expected of a production offensive security platform.

---

## Files

| File | Description |
|---|---|
| `ghoststrike.py` | Main GUI application. Initializes the CustomTkinter window, renders the ASCII art welcome screen, builds the category navigation sidebar, manages script execution threads, streams live terminal output, controls the threat level indicator, and drives the Manual/AI Co-Pilot toggle. |
| `script_metadata.py` | `SCRIPT_DATABASE` — per-module name, description, parameters, dependencies, and quality rating shown in the GUI. Keys are category-qualified (`"01-Network-Security/system_config_audit.sh"`) for the handful of basenames that exist in more than one category with different behavior; falls back to a bare filename key otherwise. |
| `ai_engine/` | AI Co-Pilot backend: agent personas (Red Team, Blue Team, Web Pentest, CTF Solver, DFIR, and others), guardrails, a pluggable Claude/GPT model provider, and the module runner that enforces `gs_policy_gate` on every AI-initiated call. |
| `cyber_toolkit.py` | Alternate launcher entry point. Handles environment checks and bootstraps `ghoststrike.py`. Useful for shortcut targets and batch launch scenarios. |
| `assets/` | Icons, logo images, and branding assets used by the GUI. Includes the GhostStrike emblem and category icons. |

---

## How to Launch

From the project root:

```bash
python3 CyberToolkit/ghoststrike.py
```

Or via the alternate launcher:

```bash
python3 CyberToolkit/cyber_toolkit.py
```

From within the CyberToolkit directory:

```bash
cd CyberToolkit
python3 ghoststrike.py
```

On Windows, the project root includes `GhostStrike.bat` and `GhostStrike.vbs` wrappers that invoke the GUI without a visible console window.

---

## Requirements

| Dependency | Version | Purpose |
|---|---|---|
| Python | 3.8+ | Runtime |
| customtkinter | Latest stable | Dark-themed UI widgets |
| Pillow (PIL) | Latest stable | Asset/image rendering |
| tkinter | Bundled with Python | Base GUI framework |
| anthropic / openai | Latest stable (optional) | AI Co-Pilot mode only — the GUI runs fine without them, with AI mode disabled and the reason shown |

Install Python dependencies:

```bash
pip3 install customtkinter pillow
pip3 install anthropic openai   # optional, for AI Co-Pilot mode
```

---

## Features

### Attack Categories (22)
The sidebar organizes GhostStrike's 164 modules into 22 numbered attack surface areas (`00-Framework-Core` through `21-Bypass-Techniques`) for rapid navigation — Network Security, Web Application Security, Wireless Security, Database Security, Active Directory, Password Attacks, Social Engineering, System Security, Container Security, Mobile Security, Cloud Security, Exploitation, Post-Exploitation, Reporting Tools, Automation Tools, Specialized Testing, Monitoring & Detection, Application Security, Lab Environment, IoT Security, and Bypass Techniques, plus the Framework Core meta-tools. New category folders and modules are picked up automatically on launch (`discover_scripts()` scans the directory tree directly rather than reading a hardcoded list).

### AI Co-Pilot Mode
A Manual/AI toggle (top-right of the terminal panel) switches between running modules yourself and handing tasks to a specialized agent persona (chosen from the adjacent dropdown). Enabling it prompts for a vault master password to unlock a stored Anthropic/OpenAI API key — or an `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` environment variable if you skip that. Every module call the agent makes is checked against the same `gs_policy_gate` a manual run would hit; a module without confirmed policy-gate wiring is refused, not attempted.

### Live Terminal Output
Script execution output streams into an embedded terminal panel with real-time updates. A live elapsed-time counter displays session duration from the moment a module is launched.

### Threat Level Indicator
A persistent threat level widget reflects the classification of the currently selected or running module, sourced directly from `lib/trust_registry.sh` trust data. Colors shift from green (low) through yellow (medium) to red (critical) as threat level escalates.

### ASCII Art Welcome Screen
On launch, GhostStrike renders a full ASCII art welcome screen with the project name, version, and operator notice before transitioning to the main interface.

### Favorites System
Frequently used scripts can be pinned to a favorites panel (`favorites.json`), reducing navigation time during active engagements.

---

## Theme Reference

| Element | Color |
|---|---|
| Background | `#05060a` |
| Primary accent (purple) | `#7b2fff` |
| Threat indicator (red) | `#ff2d55` |
| Success / safe state (green) | `#00ff88` |
| Secondary text | `#8a8fa8` |
| Panel border | `#1a1d2e` |

---

> © 2026 Fouad Ailabouni. All Rights Reserved.
> GhostStrike v3.0.0 [PHANTOM] — CyberToolkit GUI — For authorized security testing only.
