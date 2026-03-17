# GhostStrike — CyberToolkit GUI Launcher

> © 2026 Fouad Ailabouni. All Rights Reserved.

---

## Overview

CyberToolkit is the graphical front-end for GhostStrike v3.0.0 [PHANTOM]. Built on CustomTkinter with a dark void aesthetic, it provides a unified interface for launching all 103 offensive security modules, monitoring live execution output, tracking threat levels, and navigating GhostStrike's 12 attack surface categories without touching a terminal directly.

The interface runs on a `#05060a` near-black background with neon accent colors — purple for primary actions, red for threat indicators, green for success states — maintaining the operational tone expected of a production offensive security platform.

---

## Files

| File | Description |
|---|---|
| `ghoststrike.py` | Main GUI application. Initializes the CustomTkinter window, renders the ASCII art welcome screen, builds the category navigation sidebar, manages script execution threads, streams live terminal output, and controls the threat level indicator. |
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

Install Python dependencies:

```bash
pip3 install customtkinter pillow
```

---

## Features

### Attack Categories (12)
The sidebar organizes GhostStrike modules into 12 high-level attack surface areas for rapid navigation:

1. Network Security
2. Web Application Security
3. Wireless Security
4. Database Security
5. Active Directory
6. Password Attacks
7. Social Engineering
8. System Security
9. Container and Cloud Security
10. Mobile Security
11. IoT Security
12. Bypass Techniques

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
