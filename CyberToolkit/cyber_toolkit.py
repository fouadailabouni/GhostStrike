#!/usr/bin/env python3
"""
GhostStrike Launcher
Redirects to the main GhostStrike offensive security platform.
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

import os
import sys

def main():
    app_dir = os.path.dirname(os.path.abspath(__file__))
    ghoststrike = os.path.join(app_dir, "ghoststrike.py")

    if os.path.exists(ghoststrike):
        os.execv(sys.executable, [sys.executable, ghoststrike] + sys.argv[1:])
    else:
        print("[!] ghoststrike.py not found. Run from the CyberToolkit directory.")
        sys.exit(1)

if __name__ == "__main__":
    main()
