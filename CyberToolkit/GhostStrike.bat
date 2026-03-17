@echo off
title GhostStrike - Launching...
cd /d "%~dp0"

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH.
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

:: Check if customtkinter is installed
python -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
)

:: Launch GhostStrike
start "" pythonw ghoststrike.py
