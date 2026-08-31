#!/usr/bin/env python3
"""Build script to package GhostStrike as a standalone .exe"""

import subprocess
import sys
import os

def main():
    app_dir = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(app_dir, "ghoststrike.py")
    metadata_script = os.path.join(app_dir, "script_metadata.py")
    scripts_dir = os.path.join(app_dir, "..", "bash_scripts_for_pentest")

    print("[*] Installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=app_dir, check=True)

    print("[*] Building GhostStrike executable with PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "GhostStrike",
        "--onefile",
        "--windowed",
        "--icon", "NONE",
        "--add-data", f"{scripts_dir};bash_scripts_for_pentest",
        "--add-data", f"{metadata_script};.",
        "--hidden-import", "customtkinter",
        "--collect-all", "customtkinter",
        main_script,
    ]
    subprocess.run(cmd, cwd=app_dir, check=True)

    print("\n[+] Build complete!")
    print(f"[+] Executable: {os.path.join(app_dir, 'dist', 'GhostStrike.exe')}")


if __name__ == "__main__":
    main()
