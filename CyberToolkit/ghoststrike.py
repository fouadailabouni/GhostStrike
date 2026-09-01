#!/usr/bin/env python3
"""
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

GhostStrike - Offensive Security Platform
105+ automated pentest modules across 22 attack categories.
For authorized penetration testing engagements only.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

import customtkinter as ctk
import os, sys, subprocess, threading, signal, re, time, json, math, datetime
from pathlib import Path
from tkinter import messagebox, filedialog, Canvas
from script_metadata import SCRIPT_DATABASE, GOOD, PARTIAL, NEEDS_WORK
try:
    import requests as _requests
except ImportError:
    _requests = None
try:
    from ai_engine.agents import AGENT_REGISTRY, NLPRouterAgent
    from ai_engine.model_provider import GhostStrikeModelProvider, ModelBackend
    _AI_ENGINE_AVAILABLE = True
    _AI_ENGINE_IMPORT_ERROR = ""
except ImportError as _ai_import_exc:
    # anthropic/openai SDKs (or the ai_engine package itself) may not be
    # installed -- AI Co-Pilot mode degrades to disabled with a clear reason
    # shown in the UI, rather than the app failing to start.
    AGENT_REGISTRY = {}
    NLPRouterAgent = None
    GhostStrikeModelProvider = None
    ModelBackend = None
    _AI_ENGINE_AVAILABLE = False
    _AI_ENGINE_IMPORT_ERROR = str(_ai_import_exc)

# ═══════════════════════════════════════════════════════════════
# Configuration & Theme
# ═══════════════════════════════════════════════════════════════

APP_NAME    = "GhostStrike"
APP_VERSION = "3.0.0"
APP_CODENAME = "PHANTOM"
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bash_scripts_for_pentest")

# Offensive dark theme - deep blacks, neon accents
C = {
    "void":       "#05060a", "abyss":      "#080a10", "obsidian":   "#0c0e16",
    "slate":      "#12141e", "panel":      "#161925", "card":       "#1a1d2b",
    "hover":      "#1f2338", "selected":   "#1c1640", "border":     "#222640",
    "glow_line":  "#2a2e4a",
    "text":       "#e2e8f0", "text_dim":   "#7c8298", "text_ghost": "#3a3f5a",
    "neon_purple":"#a855f7", "neon_violet":"#8b5cf6", "neon_blue":  "#3b82f6",
    "neon_cyan":  "#06d6a0", "neon_red":   "#ff3e3e", "neon_amber": "#ffb020",
    "neon_green": "#00ff7f", "neon_pink":  "#ff2d8a",
    "terminal":   "#030405", "term_text":  "#00ff41", "term_cmd":   "#a855f7",
    "danger":     "#dc2626", "warning":    "#f59e0b", "success":    "#22c55e",
}

CATEGORY_COLORS = {
    "00-Framework-Core":"#6366f1","01-Network-Security":"#3b82f6",
    "02-Web-Application-Security":"#ff3e3e","03-Wireless-Security":"#a855f7",
    "04-Database-Security":"#ffb020","05-Active-Directory":"#06d6a0",
    "06-Password-Attacks":"#ff6b35","07-Social-Engineering":"#ff2d8a",
    "08-System-Security":"#14b8a6","09-Container-Security":"#06b6d4",
    "10-Mobile-Security":"#84cc16","11-Cloud-Security":"#818cf8",
    "12-Exploitation":"#ff3e3e","13-Post-Exploitation":"#dc2626",
    "14-Reporting-Tools":"#38bdf8","15-Automation-Tools":"#22c55e",
    "16-Specialized-Testing":"#c084fc","17-Monitoring-Detection":"#facc15",
    "18-Application-Security":"#fb7185","19-Lab-Environment":"#2dd4bf",
    "20-IoT-Security":"#fb923c","21-Bypass-Techniques":"#f43f5e",
}

RISK_LEVELS = {
    "12-Exploitation":1.0,"13-Post-Exploitation":0.9,"21-Bypass-Techniques":0.85,
    "06-Password-Attacks":0.8,"05-Active-Directory":0.75,"07-Social-Engineering":0.7,
    "04-Database-Security":0.6,"02-Web-Application-Security":0.55,
    "03-Wireless-Security":0.5,"20-IoT-Security":0.45,
}

# ── Trust Level Registry ──
# Loaded live from MODULE_INVENTORY.csv (the same file tests/generate_module_inventory.sh
# regenerates from the real bash-side policy.yaml + lib/trust_registry.sh) instead of a
# hardcoded copy, so this can no longer silently drift from the authoritative bash-side
# trust levels the way the old static dict did. Keyed primarily by "category/filename"
# (relative path) so that scripts sharing a basename across categories -- e.g. both
# 01-Network-Security/system_config_audit.sh and 08-System-Security/system_config_audit.sh
# exist, with different trust levels -- resolve correctly instead of colliding on a
# single basename key. A basename-only fallback dict is kept for the rare call site that
# doesn't have a category available; that path can still collide and should be migrated
# to pass category when practical.
_MODULE_INVENTORY_CSV = os.path.join(SCRIPTS_DIR, "MODULE_INVENTORY.csv")

def _load_trust_registry():
    by_path, by_basename = {}, {}
    try:
        import csv
        with open(_MODULE_INVENTORY_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                path = (row.get("script_path") or "").strip()
                trust = (row.get("trust_level") or "").strip()
                if not path or not trust or trust == "UNDOCUMENTED":
                    continue
                by_path[path] = trust
                # First writer for a given basename wins; later duplicates are left to
                # the by_path lookup, which is the one that's actually collision-safe.
                by_basename.setdefault(os.path.basename(path), trust)
    except (OSError, csv.Error):
        pass  # Inventory missing/unreadable -- get_trust_level() falls back to VALIDATION.
    return by_path, by_basename

TRUST_REGISTRY_BY_PATH, TRUST_REGISTRY_BY_BASENAME = _load_trust_registry()

def get_trust_level(script):
    """Resolve a script dict's trust level via MODULE_INVENTORY.csv, category-qualified
    first to avoid basename collisions, then falling back to basename-only, then VALIDATION."""
    if not script:
        return "VALIDATION"
    category = script.get("category", "")
    filename = script.get("filename", "")
    if category and filename:
        trust = TRUST_REGISTRY_BY_PATH.get(f"{category}/{filename}")
        if trust:
            return trust
    return TRUST_REGISTRY_BY_BASENAME.get(filename, "VALIDATION")
TRUST_COLORS = {
    "SAFE_ENUM":"#3b82f6","VALIDATION":"#22c55e",
    "HIGH_IMPACT":"#ffb020","LAB_ONLY":"#ff3e3e",
}
TRUST_DISPLAY = {
    "SAFE_ENUM":"◈ SAFE_ENUM","VALIDATION":"◈ VALIDATION",
    "HIGH_IMPACT":"⚠ HIGH_IMPACT","LAB_ONLY":"☠ LAB_ONLY",
}

# ── Tool Health Registry ──────────────────────────────────────
TOOL_REGISTRY = {
    "nmap":       ["nmap","--version"],
    "sqlmap":     ["sqlmap","--version"],
    "hydra":      ["hydra","--version"],
    "hashcat":    ["hashcat","--version"],
    "john":       ["john","--version"],
    "metasploit": ["msfconsole","--version"],
    "aircrack":   ["aircrack-ng","--help"],
    "frida":      ["frida","--version"],
    "trivy":      ["trivy","--version"],
    "binwalk":    ["binwalk","--help"],
    "nuclei":     ["nuclei","--version"],
    "gobuster":   ["gobuster","version"],
    "nikto":      ["nikto","-Version"],
    "wfuzz":      ["wfuzz","--help"],
    "impacket":   ["python3","-c","import impacket"],
}

# ═══════════════════════════════════════════════════════════════
# Script Discovery
# ═══════════════════════════════════════════════════════════════

def discover_scripts(base_dir):
    categories = {}
    base = Path(base_dir)
    if not base.exists():
        return categories
    for cat_dir in sorted(base.iterdir()):
        if not cat_dir.is_dir() or not re.match(r"^\d{2}-", cat_dir.name):
            continue
        scripts = []
        for sf in sorted(cat_dir.iterdir()):
            if sf.suffix == ".sh":
                fname = sf.name
                # A handful of basenames exist in more than one category
                # (e.g. system_config_audit.sh in both 01-Network-Security
                # and 08-System-Security, with different real trust levels
                # and behavior) -- SCRIPT_DATABASE disambiguates those with a
                # "category/filename" key. Try that first, falling back to
                # the bare filename for the ~160 non-colliding entries.
                qualified = f"{cat_dir.name}/{fname}"
                meta = SCRIPT_DATABASE.get(qualified, SCRIPT_DATABASE.get(fname, {
                    "name": sf.stem.replace("_"," ").title(), "category": cat_dir.name,
                    "description": f"Module: {fname}", "params": [], "dependencies": [],
                    "quality": NEEDS_WORK, "expected_output": "",
                })).copy()
                meta["path"] = str(sf)
                meta["filename"] = fname
                scripts.append(meta)
        if scripts:
            categories[cat_dir.name] = scripts
    return categories


# ═══════════════════════════════════════════════════════════════
# Hex Grid Canvas (Welcome Background)
# ═══════════════════════════════════════════════════════════════

class HexGridCanvas(Canvas):
    """Animated hexagonal grid background for the welcome screen."""
    def __init__(self, master, **kwargs):
        super().__init__(master, bg=C["void"], highlightthickness=0, **kwargs)
        self._anim_id = None
        self._tick = 0
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event=None):
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            return
        size = 40
        for row in range(int(h / (size * 1.5)) + 2):
            for col in range(int(w / (size * 1.73)) + 2):
                cx = col * size * 1.73 + (size * 0.866 if row % 2 else 0)
                cy = row * size * 1.5
                # Pulsing opacity based on distance from center
                dx, dy = cx - w/2, cy - h/2
                dist = math.sqrt(dx*dx + dy*dy)
                pulse = math.sin(self._tick * 0.02 + dist * 0.005) * 0.5 + 0.5
                intensity = max(8, int(20 * pulse))
                color = f"#{intensity:02x}{intensity+2:02x}{intensity+8:02x}"
                pts = []
                for i in range(6):
                    angle = math.radians(60 * i + 30)
                    pts.extend([cx + size*0.4*math.cos(angle), cy + size*0.4*math.sin(angle)])
                self.create_polygon(pts, outline=color, fill="", width=1)

    def animate(self):
        self._tick += 1
        self._draw()
        self._anim_id = self.after(80, self.animate)

    def stop(self):
        if self._anim_id:
            self.after_cancel(self._anim_id)
            self._anim_id = None


# ═══════════════════════════════════════════════════════════════
# Main Application
# ═══════════════════════════════════════════════════════════════

class GhostStrikeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(f"\u2620 {APP_NAME} v{APP_VERSION} [{APP_CODENAME}]")
        self.geometry("1650x960")
        self.minsize(1350, 820)
        self.configure(fg_color=C["void"])

        self.categories = discover_scripts(SCRIPTS_DIR)
        self.current_process = None
        self._pty_master = None
        self._sessions = {}  # {id: {process, pty_master, name, target, time, alive}}
        self._session_counter = 0
        self._active_session_id = None  # currently viewed session
        self._terminal_mode = "module"  # "module" or "session"
        self.selected_script = None
        self.script_buttons = {}
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._on_search)
        self.param_widgets = []
        self.start_time = None
        self.welcome_shown = True

        self.favorites_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "favorites.json")
        self.favorites = self._load_json(self.favorites_file, set())
        self.quality_filter = "ALL"

        # Engagement management
        _base = os.path.dirname(os.path.abspath(__file__))
        self.engagements_file = os.path.join(_base, "engagements.json")
        self.settings_file    = os.path.join(_base, "settings.json")
        self._eng_raw = self._load_json_dict(self.engagements_file, {"active": None, "engagements": {}})
        self.active_engagement = self._eng_raw.get("active")
        self.settings = self._load_json_dict(self.settings_file, {"webhook_url": "", "notify_complete": True, "notify_critical": True})

        # Tool health
        self.tool_status: dict = {}
        self.tool_panel_labels: dict = {}
        self.tool_progress_bar = None

        # AI Co-Pilot mode
        self.ai_mode = False
        self.ai_agent_name = "Red Team"
        # GHOSTSTRIKE_AI_BACKEND only sets the *initial* value now -- the
        # backend picker in the terminal header (see _build_terminal_panel)
        # lets the operator switch to Local (Ollama/LM Studio) at runtime.
        # Set GHOSTSTRIKE_LOCAL_AI_URL too if Ollama isn't on the default
        # http://localhost:11434.
        self.ai_backend = os.getenv("GHOSTSTRIKE_AI_BACKEND", "claude").strip().lower()
        if self.ai_backend not in ("claude", "openai", "local"):
            self.ai_backend = "claude"
        self.ai_autonomy_tier = "recommend"   # observe | recommend | operate
        self.vault_master_key = None   # session-only; never written to disk
        self._ai_running = False

        self._build_ui()
        self._populate_categories()
        self._show_welcome_screen()
        threading.Thread(target=self._check_tools, daemon=True).start()

    def _load_json(self, path, default):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except Exception:
            return default

    def _load_json_dict(self, path, default):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default

    # ══════════════════════════════════════════
    # UI Layout
    # ══════════════════════════════════════════

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main_area()

    # ── SIDEBAR ──
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=370, corner_radius=0, fg_color=C["abyss"],
                           border_width=1, border_color=C["border"])
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(5, weight=1)
        sb.grid_columnconfigure(0, weight=1)
        sb.grid_propagate(False)
        self.sidebar = sb

        # Logo
        logo = ctk.CTkFrame(sb, fg_color=C["obsidian"], height=95, corner_radius=0)
        logo.grid(row=0, column=0, sticky="ew")
        logo.grid_propagate(False)

        lr = ctk.CTkFrame(logo, fg_color="transparent")
        lr.pack(pady=(16, 0))
        ctk.CTkLabel(lr, text="\u2620 ", font=ctk.CTkFont(size=32),
                     text_color=C["neon_purple"]).pack(side="left")
        ctk.CTkLabel(lr, text="GHOST", font=ctk.CTkFont(family="Consolas", size=28, weight="bold"),
                     text_color=C["neon_purple"]).pack(side="left")
        ctk.CTkLabel(lr, text="STRIKE", font=ctk.CTkFont(family="Consolas", size=28, weight="bold"),
                     text_color=C["neon_red"]).pack(side="left")
        ctk.CTkLabel(logo, text=f"OFFENSIVE SECURITY PLATFORM  \u2502  v{APP_VERSION} [{APP_CODENAME}]",
                     font=ctk.CTkFont(family="Consolas", size=12),
                     text_color=C["text_ghost"]).pack(pady=(2, 0))

        # Search
        sf = ctk.CTkFrame(sb, fg_color="transparent")
        sf.grid(row=1, column=0, sticky="ew", padx=14, pady=(10, 4))
        self.search_entry = ctk.CTkEntry(sf, placeholder_text="\u2315  Search modules...",
            textvariable=self.search_var, height=36, corner_radius=5,
            fg_color=C["slate"], border_color=C["border"], text_color=C["text"],
            font=ctk.CTkFont(family="Consolas", size=13))
        self.search_entry.pack(fill="x")

        # Filters
        ff = ctk.CTkFrame(sb, fg_color="transparent")
        ff.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 4))
        self.filter_buttons = {}
        for label, val, clr in [("ALL", "ALL", C["text_ghost"]), ("OPERATIONAL", GOOD, C["neon_green"])]:
            b = ctk.CTkButton(ff, text=label, width=85, height=22,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), corner_radius=3,
                fg_color=clr if val == "ALL" else C["slate"],
                hover_color=C["hover"], text_color=C["text"],
                command=lambda v=val: self._set_quality_filter(v))
            b.pack(side="left", padx=2)
            self.filter_buttons[val] = b

        # Stats Dashboard
        total = sum(len(s) for s in self.categories.values())
        cats = len(self.categories)
        good = sum(1 for cat in self.categories.values() for s in cat if s.get("quality") == GOOD)

        dash = ctk.CTkFrame(sb, fg_color=C["slate"], corner_radius=6,
                             border_width=1, border_color=C["border"])
        dash.grid(row=3, column=0, sticky="ew", padx=14, pady=(4, 4))
        di = ctk.CTkFrame(dash, fg_color="transparent")
        di.pack(fill="x", padx=8, pady=8)
        for val, lbl, clr in [(str(total),"MODULES",C["neon_cyan"]),
                               (str(cats),"VECTORS",C["neon_purple"]),
                               (str(good),"ARMED",C["neon_green"])]:
            c = ctk.CTkFrame(di, fg_color="transparent")
            c.pack(side="left", expand=True)
            ctk.CTkLabel(c, text=val, font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
                         text_color=clr).pack()
            ctk.CTkLabel(c, text=lbl, font=ctk.CTkFont(family="Consolas", size=12),
                         text_color=C["text_ghost"]).pack()

        # Threat Level
        thr = ctk.CTkFrame(sb, fg_color="transparent")
        thr.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 3))
        ctk.CTkLabel(thr, text="THREAT LEVEL", font=ctk.CTkFont(family="Consolas", size=12),
                     text_color=C["text_ghost"]).pack(side="left")
        self.threat_bar = ctk.CTkProgressBar(thr, height=5, corner_radius=2,
            fg_color=C["slate"], progress_color=C["neon_green"])
        self.threat_bar.pack(side="right", fill="x", expand=True, padx=(8,0))
        self.threat_bar.set(0)

        # Module List
        self.category_scroll = ctk.CTkScrollableFrame(sb, fg_color="transparent",
            scrollbar_button_color=C["border"], scrollbar_button_hover_color=C["neon_purple"])
        self.category_scroll.grid(row=5, column=0, sticky="nsew", padx=4, pady=0)
        self.category_scroll.grid_columnconfigure(0, weight=1)

        # ── Arsenal Health Panel ──────────────────────────────
        ap = ctk.CTkFrame(sb, fg_color=C["slate"], corner_radius=6,
                           border_width=1, border_color=C["border"])
        ap.grid(row=6, column=0, sticky="ew", padx=14, pady=(2, 2))
        ah = ctk.CTkFrame(ap, fg_color="transparent")
        ah.pack(fill="x", padx=8, pady=(6, 2))
        ctk.CTkLabel(ah, text="⚡ ARSENAL",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["neon_cyan"]).pack(side="left")
        self.arsenal_status_lbl = ctk.CTkLabel(ah, text="checking...",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=C["text_ghost"])
        self.arsenal_status_lbl.pack(side="right")
        self.tool_progress_bar = ctk.CTkProgressBar(ap, height=4, corner_radius=2,
            fg_color=C["border"], progress_color=C["neon_cyan"])
        self.tool_progress_bar.pack(fill="x", padx=8, pady=(2, 4))
        self.tool_progress_bar.set(0)

        # ── Engagement Panel ──────────────────────────────────
        ep = ctk.CTkFrame(sb, fg_color=C["obsidian"], corner_radius=6,
                           border_width=1, border_color=C["border"])
        ep.grid(row=7, column=0, sticky="ew", padx=14, pady=(2, 2))
        ep.grid_columnconfigure(0, weight=1)
        ef = ctk.CTkFrame(ep, fg_color="transparent")
        ef.pack(fill="x", padx=8, pady=6)
        eng_id = self.active_engagement or "NO ENGAGEMENT"
        eng_color = C["neon_green"] if self.active_engagement else C["neon_amber"]
        self.engagement_label = ctk.CTkLabel(ef,
            text=f"⚑ {eng_id[:22]}",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=eng_color)
        self.engagement_label.pack(side="left")
        ebf = ctk.CTkFrame(ef, fg_color="transparent")
        ebf.pack(side="right")
        ctk.CTkButton(ebf, text="+NEW", width=44, height=18,
            font=ctk.CTkFont(family="Consolas", size=12), corner_radius=3,
            fg_color=C["card"], hover_color=C["hover"], border_width=1,
            border_color=C["neon_green"], text_color=C["neon_green"],
            command=self._new_engagement_dialog).pack(side="left", padx=2)
        ctk.CTkButton(ebf, text="LIST", width=38, height=18,
            font=ctk.CTkFont(family="Consolas", size=12), corner_radius=3,
            fg_color=C["card"], hover_color=C["hover"], border_width=1,
            border_color=C["border"], text_color=C["text_dim"],
            command=self._switch_engagement_dialog).pack(side="left", padx=2)
        ctk.CTkButton(ebf, text="DASH", width=42, height=18,
            font=ctk.CTkFont(family="Consolas", size=12), corner_radius=3,
            fg_color=C["card"], hover_color=C["hover"], border_width=1,
            border_color=C["neon_purple"], text_color=C["neon_purple"],
            command=self._show_engagement_dashboard).pack(side="left", padx=2)

        # ── Footer ────────────────────────────────────────────
        ft = ctk.CTkFrame(sb, fg_color=C["obsidian"], height=28, corner_radius=0)
        ft.grid(row=8, column=0, sticky="sew")
        ft.grid_propagate(False)
        fti = ctk.CTkFrame(ft, fg_color="transparent")
        fti.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(fti, text="\u00a9 2026 Fouad Ailabouni  \u2502  All Rights Reserved",
                     font=ctk.CTkFont(family="Consolas", size=12),
                     text_color=C["text_ghost"]).pack(side="left")
        ctk.CTkButton(fti, text="⚙", width=20, height=16,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="transparent", hover_color=C["hover"], text_color=C["text_ghost"],
            command=self._show_settings).pack(side="right")

    # ── MAIN AREA ──
    def _build_main_area(self):
        mf = ctk.CTkFrame(self, fg_color=C["void"], corner_radius=0)
        mf.grid(row=0, column=1, sticky="nsew")
        mf.grid_columnconfigure(0, weight=1)
        mf.grid_rowconfigure(2, weight=1)
        self.main_frame = mf

        # Top bar
        top = ctk.CTkFrame(mf, fg_color=C["obsidian"], height=75, corner_radius=0,
                            border_width=1, border_color=C["border"])
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(1, weight=1)
        top.grid_propagate(False)

        ia = ctk.CTkFrame(top, fg_color="transparent")
        ia.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        self.script_title_label = ctk.CTkLabel(ia,
            text="\u2588\u2588\u2588  SELECT TARGET MODULE",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=C["text_ghost"])
        self.script_title_label.pack(anchor="w")
        self.script_desc_label = ctk.CTkLabel(ia,
            text="// Choose a module from the arsenal to begin engagement",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_ghost"], wraplength=600)
        self.script_desc_label.pack(anchor="w")

        bf = ctk.CTkFrame(top, fg_color="transparent")
        bf.grid(row=0, column=1, padx=20, sticky="e")

        self.quality_badge = ctk.CTkLabel(bf, text="",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            width=90, height=20, corner_radius=3, fg_color=C["card"])
        self.quality_badge.pack(side="left", padx=3)
        self.quality_badge.pack_forget()

        self.trust_badge = ctk.CTkLabel(bf, text="",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            width=110, height=20, corner_radius=3, fg_color=C["card"])
        self.trust_badge.pack(side="left", padx=3)
        self.trust_badge.pack_forget()

        btn_cfg = dict(width=60, height=26, font=ctk.CTkFont(family="Consolas", size=13),
                       fg_color=C["card"], hover_color=C["hover"],
                       border_width=1, border_color=C["border"], corner_radius=3, state="disabled")
        self.doc_btn = ctk.CTkButton(bf, text="DOCS", command=self._show_docs, **btn_cfg)
        self.doc_btn.pack(side="left", padx=2)
        self.fav_btn = ctk.CTkButton(bf, text="\u2606 FAV", command=self._toggle_favorite, **btn_cfg)
        self.fav_btn.pack(side="left", padx=2)
        self.view_src_btn = ctk.CTkButton(bf, text="SRC", command=self._view_source, **btn_cfg)
        self.view_src_btn.pack(side="left", padx=2)

        # Params
        self._build_params_panel()
        # Terminal
        self._build_terminal()

    def _build_params_panel(self):
        po = ctk.CTkFrame(self.main_frame, fg_color=C["obsidian"], corner_radius=6,
                           border_width=1, border_color=C["border"])
        po.grid(row=1, column=0, sticky="ew", padx=14, pady=(8, 4))
        po.grid_columnconfigure(0, weight=1)
        self.params_outer = po

        h = ctk.CTkFrame(po, fg_color="transparent")
        h.grid(row=0, column=0, sticky="ew", padx=14, pady=(8, 4))
        ctk.CTkLabel(h, text="\u2699  PARAMETERS",
                     font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color=C["neon_purple"]).pack(side="left")
        self.deps_label = ctk.CTkLabel(h, text="",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_ghost"])
        self.deps_label.pack(side="right")

        self.params_container = ctk.CTkFrame(po, fg_color="transparent")
        self.params_container.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        self.params_container.grid_columnconfigure(1, weight=1)

        af = ctk.CTkFrame(po, fg_color="transparent")
        af.grid(row=2, column=0, sticky="ew", padx=14, pady=(4, 10))

        self.run_btn = ctk.CTkButton(af, text="\u25b6  EXECUTE",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            fg_color=C["neon_green"], hover_color="#16a34a", text_color="#000",
            height=40, width=170, corner_radius=5, command=self._run_script, state="disabled")
        self.run_btn.pack(side="left", padx=(0, 6))

        self.stop_btn = ctk.CTkButton(af, text="\u25a0  ABORT",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            fg_color=C["neon_red"], hover_color="#991b1b",
            height=40, width=100, corner_radius=5, command=self._stop_script, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 6))

        for txt, cmd in [("CLEAR", self._clear_terminal), ("EXPORT", self._export_log)]:
            ctk.CTkButton(af, text=txt, font=ctk.CTkFont(family="Consolas", size=12),
                fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["border"],
                height=40, width=75, corner_radius=5, command=cmd).pack(side="left", padx=(0, 4))

        ctk.CTkButton(af, text="BENCH", font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["neon_cyan"],
            text_color=C["neon_cyan"],
            height=40, width=75, corner_radius=5,
            command=self._run_benchmarks).pack(side="left", padx=(0, 4))

        ctk.CTkButton(af, text="FINDINGS", font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["neon_purple"],
            text_color=C["neon_purple"],
            height=40, width=85, corner_radius=5,
            command=self._show_findings).pack(side="left", padx=(0, 4))

        ctk.CTkButton(af, text="REPORT", font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["neon_amber"],
            text_color=C["neon_amber"],
            height=40, width=80, corner_radius=5,
            command=self._generate_report).pack(side="left", padx=(0, 4))

        ctk.CTkButton(af, text="GUIDE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["neon_green"], hover_color=C["neon_cyan"], text_color=C["obsidian"],
            height=40, width=70, corner_radius=5,
            command=self._show_roadmap_guide).pack(side="left", padx=(0, 4))

        self._sessions_btn = ctk.CTkButton(af, text="SESSIONS [0]",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["neon_red"],
            text_color=C["neon_red"], height=40, width=105, corner_radius=5,
            command=self._show_sessions_panel)
        self._sessions_btn.pack(side="left", padx=(0, 4))

        sf = ctk.CTkFrame(af, fg_color="transparent")
        sf.pack(side="right", padx=8)
        self.status_dot = ctk.CTkLabel(sf, text="\u25cf", font=ctk.CTkFont(size=13),
                                        text_color=C["neon_green"])
        self.status_dot.pack(side="left", padx=(0, 4))
        self.status_label = ctk.CTkLabel(sf, text="STANDBY",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["neon_green"])
        self.status_label.pack(side="left")

    def _build_terminal(self):
        tf = ctk.CTkFrame(self.main_frame, fg_color=C["terminal"], corner_radius=6,
                           border_width=1, border_color=C["border"])
        tf.grid(row=2, column=0, sticky="nsew", padx=14, pady=(4, 14))
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(1, weight=1)

        th = ctk.CTkFrame(tf, fg_color=C["obsidian"], height=30, corner_radius=0)
        th.grid(row=0, column=0, sticky="ew")
        th.grid_propagate(False)

        dd = ctk.CTkFrame(th, fg_color="transparent")
        dd.pack(side="left", padx=10, pady=7)
        for c in [C["neon_red"], C["neon_amber"], C["neon_green"]]:
            ctk.CTkLabel(dd, text="\u25cf", font=ctk.CTkFont(size=13), text_color=c, width=10).pack(side="left")

        ctk.CTkLabel(th, text="root@ghoststrike:~# ",
                     font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color=C["term_cmd"]).pack(side="left", pady=3)
        self.term_timer = ctk.CTkLabel(th, text="",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_ghost"])
        self.term_timer.pack(side="right", padx=10)

        # Background session button (visible when process running)
        self._bg_btn = ctk.CTkButton(th, text="BG", width=36, height=24,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color="transparent", hover_color=C["slate"],
            border_width=1, border_color=C["neon_amber"], text_color=C["neon_amber"],
            corner_radius=3, command=self._background_session)
        self._bg_btn.pack(side="right", padx=2, pady=4)
        self._term_label = ctk.CTkLabel(th, text="",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=C["neon_red"])
        self._term_label.pack(side="right", padx=4)

        # Agent persona picker -- only meaningful in AI Co-Pilot mode, but kept
        # visible (disabled) rather than hidden so its existence is discoverable.
        self._ai_agent_var = ctk.StringVar(value=self.ai_agent_name)
        self._ai_agent_cb = ctk.CTkComboBox(th, values=list(AGENT_REGISTRY.keys()) or ["Red Team"],
            variable=self._ai_agent_var, state="readonly", width=130, height=24,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["obsidian"], border_color=C["text_dim"],
            button_color=C["slate"], dropdown_fg_color=C["slate"],
            command=lambda v: setattr(self, "ai_agent_name", v))
        self._ai_agent_cb.pack(side="right", padx=(4, 2), pady=4)
        self._ai_agent_cb.configure(state="disabled")

        # Backend picker -- Claude/OpenAI need a vault or env-var API key;
        # Local (Ollama/LM Studio) needs neither, just a server reachable at
        # GHOSTSTRIKE_LOCAL_AI_URL (default http://localhost:11434/v1).
        _BACKEND_DISPLAY = {"claude": "Claude", "openai": "OpenAI", "local": "Local"}
        self._ai_backend_from_display = {v: k for k, v in _BACKEND_DISPLAY.items()}
        self._ai_backend_var = ctk.StringVar(value=_BACKEND_DISPLAY[self.ai_backend])
        self._ai_backend_cb = ctk.CTkComboBox(th, values=["Claude", "OpenAI", "Local"],
            variable=self._ai_backend_var, state="readonly", width=90, height=24,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["obsidian"], border_color=C["text_dim"],
            button_color=C["slate"], dropdown_fg_color=C["slate"],
            command=lambda v: setattr(self, "ai_backend", self._ai_backend_from_display[v]))
        self._ai_backend_cb.pack(side="right", padx=(4, 2), pady=4)
        self._ai_backend_cb.configure(state="disabled")

        # Autonomy tier -- Observe never executes, Recommend asks before every
        # module call, Operate only asks for HIGH_IMPACT/LAB_ONLY or anything
        # policy.yaml flags require_explicit_approval. See
        # ai_engine/tools/module_runner.py for the enforcement side of this.
        self._ai_tier_var = ctk.StringVar(value="Recommend")
        self._ai_tier_cb = ctk.CTkComboBox(th, values=["Observe", "Recommend", "Operate"],
            variable=self._ai_tier_var, state="readonly", width=110, height=24,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["obsidian"], border_color=C["text_dim"],
            button_color=C["slate"], dropdown_fg_color=C["slate"],
            command=lambda v: setattr(self, "ai_autonomy_tier", v.lower()))
        self._ai_tier_cb.pack(side="right", padx=(4, 2), pady=4)
        self._ai_tier_cb.configure(state="disabled")

        # Manual / AI Co-Pilot mode toggle. Disabled (not hidden) when the
        # ai_engine package failed to import, so the reason is discoverable
        # instead of the feature silently not existing.
        self._ai_mode_btn = ctk.CTkButton(th, text="\U0001f916 MANUAL", width=90, height=24,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color="transparent", hover_color=C["slate"],
            border_width=1, border_color=C["text_dim"], text_color=C["text_dim"],
            corner_radius=3, command=self._toggle_ai_mode,
            state="normal" if _AI_ENGINE_AVAILABLE else "disabled")
        self._ai_mode_btn.pack(side="right", padx=(4, 2), pady=4)
        if not _AI_ENGINE_AVAILABLE:
            self._ai_mode_btn.configure(text="AI: N/A")
            def _show_ai_unavailable(_e=None):
                messagebox.showinfo(
                    "AI Co-Pilot unavailable",
                    "The ai_engine package failed to import:\n\n"
                    f"{_AI_ENGINE_IMPORT_ERROR}\n\n"
                    "Install its dependencies (pip install anthropic openai) and restart."
                )
            self._ai_mode_btn.configure(command=_show_ai_unavailable, state="normal")

        self.terminal = ctk.CTkTextbox(tf, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["terminal"], text_color=C["term_text"], corner_radius=0,
            wrap="word", state="disabled")
        self.terminal.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0, 1))

        # Terminal input bar — lets user type and send to running process stdin
        input_frame = ctk.CTkFrame(tf, fg_color=C["obsidian"], height=32, corner_radius=0)
        input_frame.grid(row=2, column=0, sticky="ew")
        ctk.CTkLabel(input_frame, text="$", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_green"], width=20).pack(side="left", padx=(8, 4))
        self.term_input = ctk.CTkEntry(input_frame, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["terminal"], text_color=C["term_text"], border_color=C["border"],
            border_width=1, corner_radius=3, placeholder_text="Type here... (Enter to send)")
        self.term_input.pack(side="left", fill="x", expand=True, padx=(0, 4), pady=4)
        self.term_input.bind("<Return>", self._send_terminal_input)
        ctk.CTkButton(input_frame, text="SEND", width=50, height=24,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=C["neon_green"], text_color=C["obsidian"], hover_color=C["neon_cyan"],
            corner_radius=3, command=lambda: self._send_terminal_input(None)).pack(side="right", padx=6, pady=4)

    # ══════════════════════════════════════════
    # Welcome Screen
    # ══════════════════════════════════════════

    def _show_welcome_screen(self):
        total = sum(len(s) for s in self.categories.values())
        cats = len(self.categories)
        good = sum(1 for c in self.categories.values() for s in c if s.get("quality") == GOOD)

        logo = r"""
    ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗
    ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝
    ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░
    ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░
    ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░
    ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░

    ░██████╗████████╗██████╗░██╗██╗░░██╗███████╗
    ██╔════╝╚══██╔══╝██╔══██╗██║██║░██╔╝██╔════╝
    ╚█████╗░░░░██║░░░██████╔╝██║█████╔╝░█████╗░░
    ░╚═══██╗░░░██║░░░██╔══██╗██║██╔═██╗░██╔══╝░░
    ██████╔╝░░░██║░░░██║░░██║██║██║░╚██╗███████╗
    ╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚═╝░░╚═╝╚══════╝"""

        cap = {
            "NETWORK RECON":       "Port scanning, DNS recon, SSL/TLS, WAF bypass, service discovery",
            "WEB EXPLOITATION":    "SQLi, XSS, CSRF, GraphQL, JWT, WebSocket, OWASP Top 10",
            "WIRELESS ASSAULT":    "WiFi cracking, BLE scanning, Bluetooth enumeration",
            "DATABASE BREACH":     "SQL/NoSQL injection, privilege escalation, data exfiltration",
            "ACTIVE DIRECTORY":    "Kerberos roasting, NTLM relay, delegation abuse, DCSync",
            "CREDENTIAL ATTACKS":  "Hash cracking, password spraying, brute force campaigns",
            "SOCIAL ENGINEERING":  "Phishing automation, email harvesting, OSINT collection",
            "CLOUD PENETRATION":   "AWS/Azure/GCP enumeration, bucket testing, container escape",
            "IoT EXPLOITATION":    "MQTT, CoAP, firmware analysis, BLE, Zigbee, default creds",
            "POST-EXPLOITATION":   "Persistence, data exfiltration simulation, privilege escalation",
            "BYPASS ARSENAL":      "WAF, IDS/IPS, SIEM, sandbox escape, certificate pinning",
            "PURPLE TEAM OPS":     "Detection validation, incident response, security metrics",
        }

        lines = [logo, "",
            f"    \u2588\u2588  OFFENSIVE SECURITY PLATFORM  \u2502  v{APP_VERSION} [{APP_CODENAME}]",
            f"    \u2588\u2588  Copyright (C) 2026 Fouad Ailabouni",
            "",
            f"    \u250c{'─'*56}\u2510",
            f"    \u2502  {total:>3} Attack Modules  \u2502  {cats:>2} Categories  \u2502  {good:>3} Armed   \u2502",
            f"    \u2514{'─'*56}\u2518",
            "",
            "    ══ PLATFORM CAPABILITIES ══", ""]

        for name, desc in cap.items():
            lines.append(f"    \u25b8 {name}")
            lines.append(f"      {desc}")

        lines.extend(["",
            "    ══ FRAMEWORK ARCHITECTURE ══", "",
            "    ◈ POLICY ENGINE        Pre-execution gate — scope, identity, trust level enforcement",
            "    ◈ EVIDENCE PROVENANCE  SHA256-signed artifacts + immutable chain-of-custody log",
            "    ◈ FINDING ONTOLOGY     MITRE ATT&CK aligned JSON schema — SARIF 2.1.0 export",
            "    ◈ REPRO SCORING        Session recording + 0-100 reproducibility score + replay",
            "    ◈ TRUST LEVELS         SAFE_ENUM / VALIDATION / HIGH_IMPACT / LAB_ONLY per module",
            "    ◈ BENCHMARK MODE       DVWA / Juice Shop / Metasploitable — click BENCH above",
            "",
            f"    {'='*58}",
            "    \u26a0  AUTHORIZED PENETRATION TESTING ONLY",
            "    Unauthorized access to computer systems is illegal.",
            "    Always obtain explicit written authorization.",
            f"    {'='*58}",
            "",
            "    >> Select a target module from the arsenal to begin...", ""])

        self._append_terminal("\n".join(lines))

    # ══════════════════════════════════════════
    # Population & Filters
    # ══════════════════════════════════════════

    def _set_quality_filter(self, value):
        self.quality_filter = value
        for v, btn in self.filter_buttons.items():
            btn.configure(fg_color=C["neon_purple"] if v == value and v != "ALL"
                          else C["text_ghost"] if v == value else C["slate"])
        self._populate_categories(self.search_var.get())

    def _populate_categories(self, filter_text=""):
        for w in self.category_scroll.winfo_children():
            w.destroy()
        self.script_buttons.clear()
        fl = filter_text.lower()

        if self.favorites and not filter_text and self.quality_filter == "ALL":
            self._add_section_header("\u2605 FAVORITES")
            for cn, ss in self.categories.items():
                for s in ss:
                    if s["filename"] in self.favorites:
                        self._add_script_button(s, CATEGORY_COLORS.get(cn, "#3b82f6"))

        for cn, ss in self.categories.items():
            dn = cn.split("-", 1)[1].replace("-", " ") if "-" in cn else cn
            color = CATEGORY_COLORS.get(cn, "#3b82f6")
            matched = [s for s in ss if
                       (self.quality_filter == "ALL" or s.get("quality") == self.quality_filter) and
                       (not fl or fl in f"{s['name']} {s['filename']} {s.get('description','')} {dn}".lower())]
            if not matched:
                continue
            self._add_category_header(dn, color, len(matched))
            for s in matched:
                self._add_script_button(s, color)

    def _add_section_header(self, text):
        ctk.CTkLabel(self.category_scroll, text=f"  {text}",
                     font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                     text_color=C["neon_amber"], anchor="w").pack(fill="x", padx=4, pady=(8, 2))

    def _add_category_header(self, name, color, count):
        h = ctk.CTkFrame(self.category_scroll, fg_color="transparent")
        h.pack(fill="x", padx=4, pady=(10, 2))
        ctk.CTkLabel(h, text="\u25c6", font=ctk.CTkFont(size=12), text_color=color, width=18).pack(side="left")
        ctk.CTkLabel(h, text=name.upper(),
                     font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                     text_color="#94a3b8").pack(side="left")
        ctk.CTkLabel(h, text=f"[{count}]",
                     font=ctk.CTkFont(family="Consolas", size=12),
                     text_color=C["text_ghost"]).pack(side="left", padx=4)

    def _add_script_button(self, script, color):
        btn = ctk.CTkButton(self.category_scroll, text=f"  {script['name']}",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="transparent", hover_color=C["selected"],
            text_color="#b0b8cc", anchor="w", height=26, corner_radius=3, border_width=0,
            command=lambda s=script, c=color: self._select_script(s, c))
        btn.pack(fill="x", padx=14, pady=1)
        self.script_buttons[script["filename"]] = btn

    # ══════════════════════════════════════════
    # Script Selection
    # ══════════════════════════════════════════

    def _select_script(self, script, color):
        self.selected_script = script
        self.script_title_label.configure(text=f"\u25b8  {script['name']}", text_color=color)
        self.script_desc_label.configure(text=f"// {script.get('description','')}", text_color=C["text_dim"])

        q = script.get("quality", NEEDS_WORK)
        ql = {GOOD: "ARMED", PARTIAL: "PARTIAL", NEEDS_WORK: "STUB"}.get(q, "???")
        qc = {GOOD: C["neon_green"], PARTIAL: C["neon_amber"], NEEDS_WORK: C["neon_red"]}.get(q, C["neon_red"])
        self.quality_badge.pack(side="left", padx=3)
        self.quality_badge.configure(text=f" {ql} ", text_color=qc, fg_color=C["card"])

        trust = get_trust_level(script)
        tc = TRUST_COLORS.get(trust, C["neon_amber"])
        self.trust_badge.pack(side="left", padx=3)
        self.trust_badge.configure(text=f" {TRUST_DISPLAY.get(trust, trust)} ", text_color=tc, fg_color=C["card"])

        risk = RISK_LEVELS.get(script.get("category", ""), 0.25)
        self.threat_bar.set(risk)
        self.threat_bar.configure(progress_color=C["neon_red"] if risk > 0.7
                                  else C["neon_amber"] if risk > 0.4 else C["neon_green"])

        for btn_name in ["run_btn", "fav_btn", "view_src_btn", "doc_btn"]:
            getattr(self, btn_name).configure(state="normal")

        is_fav = script["filename"] in self.favorites
        self.fav_btn.configure(text="\u2605 UNFAV" if is_fav else "\u2606 FAV",
                               fg_color=C["neon_amber"] if is_fav else C["card"])

        deps = script.get("dependencies", [])
        self.deps_label.configure(text=f"deps: {', '.join(deps[:4])}" if deps else "// standalone")

        self._setup_params(script)
        for fn, btn in self.script_buttons.items():
            btn.configure(fg_color=C["selected"] if fn == script["filename"] else "transparent")
        self.status_dot.configure(text_color=C["neon_green"])
        self.status_label.configure(text="READY", text_color=C["neon_green"])

    def _setup_params(self, script):
        for w in self.params_container.winfo_children():
            w.destroy()
        self.param_widgets = []
        params = script.get("params", [])
        if not params:
            ctk.CTkLabel(self.params_container, text="// No parameters required",
                         font=ctk.CTkFont(family="Consolas", size=12),
                         text_color=C["text_ghost"]).grid(row=0, column=0, columnspan=2, sticky="w", padx=4, pady=4)
            self._add_extra_args_row(1)
            return

        entry_cfg = dict(height=28, corner_radius=3, fg_color=C["void"], border_color=C["border"],
                         font=ctk.CTkFont(family="Consolas", size=12))
        for i, p in enumerate(params):
            name = p.get("name", f"arg{i}")
            ptype = p.get("type", "text")
            req = p.get("required", False)
            opts = p.get("options", [])
            hlp = p.get("help", "")

            ctk.CTkLabel(self.params_container, text=f"{'*' if req else ' '} {name}",
                         font=ctk.CTkFont(family="Consolas", size=13, weight="bold" if req else "normal"),
                         text_color=C["text"] if req else C["text_dim"]
                         ).grid(row=i, column=0, sticky="w", padx=(4, 8), pady=2)

            if ptype == "select" and opts:
                w = ctk.CTkComboBox(self.params_container, values=opts, state="readonly",
                    **{k:v for k,v in entry_cfg.items() if k != "fg_color"},
                    fg_color=C["void"], button_color=C["border"],
                    button_hover_color=C["hover"], dropdown_fg_color=C["slate"])
                w.set(opts[0])
            elif ptype == "flag":
                w = ctk.CTkCheckBox(self.params_container, text=hlp or name,
                    font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"],
                    fg_color=C["neon_purple"], hover_color=C["neon_violet"])
            else:
                w = ctk.CTkEntry(self.params_container, placeholder_text=hlp or f"Enter {name}...", **entry_cfg)
            w.grid(row=i, column=1, sticky="ew", padx=(0, 4), pady=2)
            self.param_widgets.append({"name": name, "type": ptype, "required": req, "widget": w, "options": opts})
        self._add_extra_args_row(len(params))

    def _add_extra_args_row(self, row):
        eh = self.selected_script.get("extra_args_help", "") if self.selected_script else ""
        ctk.CTkLabel(self.params_container, text="  extra",
                     font=ctk.CTkFont(family="Consolas", size=13),
                     text_color=C["text_ghost"]).grid(row=row, column=0, sticky="w", padx=(4, 8), pady=2)
        e = ctk.CTkEntry(self.params_container, height=28, corner_radius=3,
            fg_color=C["void"], border_color=C["border"],
            placeholder_text=eh or "Additional arguments...",
            font=ctk.CTkFont(family="Consolas", size=12))
        e.grid(row=row, column=1, sticky="ew", padx=(0, 4), pady=2)
        self.param_widgets.append({"name": "extra_args", "type": "extra", "required": False, "widget": e, "options": []})

    # ══════════════════════════════════════════
    # Execution Engine
    # ══════════════════════════════════════════

    def _run_script(self):
        if not self.selected_script or self.current_process:
            return
        script = self.selected_script
        cmd_args = []
        for pw in self.param_widgets:
            n, t, r, w = pw["name"], pw["type"], pw["required"], pw["widget"]
            if t == "extra":
                v = w.get().strip()
                if v: cmd_args.extend(v.split())
            elif t == "flag":
                if w.get(): cmd_args.append(n.split("/")[-1] if "/" in n else n)
            elif t == "select":
                v = w.get().strip()
                if v:
                    if n.startswith("-"): cmd_args.extend([n.split("/")[-1], v])
                    else: cmd_args.append(v)
                elif r: messagebox.showwarning("Missing", f"Required: {n}"); return
            else:
                v = w.get().strip()
                if v:
                    if n.startswith("-"): cmd_args.extend([n.split("/")[-1], v])
                    else: cmd_args.append(v)
                elif r: messagebox.showwarning("Missing", f"Required: {n}"); return

        if not self._policy_gate(script, cmd_args):
            return

        self.start_time = time.time()
        self._clear_terminal()
        self._append_terminal(f"\n  \u2588\u2588 GHOSTSTRIKE ENGAGEMENT INITIATED\n")
        self._append_terminal(f"  \u2588\u2588 Module: {script['name']}\n")
        self._append_terminal(f"  \u2588\u2588 Target: {' '.join(cmd_args) or 'N/A'}\n")
        self._append_terminal(f"  \u2588\u2588 Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._append_terminal(f"  {'='*58}\n\n")

        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_dot.configure(text_color=C["neon_amber"])
        self.status_label.configure(text="ENGAGING...", text_color=C["neon_amber"])
        self._update_timer()

        # Clear previous findings for this module before running
        self._clear_module_findings(script["filename"])

        cmd = self._build_shell_command(script["path"], cmd_args)
        threading.Thread(target=self._execute_script, args=(cmd,), daemon=True).start()
        # Track module run in active engagement
        if self.active_engagement:
            eng = self._eng_raw.get("engagements", {}).get(self.active_engagement, {})
            eng["modules_run"] = eng.get("modules_run", 0) + 1
            self._save_engagements()

    def _update_timer(self):
        if self.current_process and self.start_time:
            e = int(time.time() - self.start_time)
            self.term_timer.configure(text=f"[{e//60:02d}:{e%60:02d}]")
            self.after(1000, self._update_timer)

    def _build_shell_command(self, path, args):
        # Delegates to shell_command_builder.find_bash_invocation(), the one
        # shared, safely-quoted (shlex.quote) implementation of the WSL /
        # Git Bash / native-bash resolution chain -- see that module's
        # docstring. This function used to hand-roll its own version with
        # naive f'"{arg}"' wrapping, which did not escape a quote/backtick/`$`
        # inside a value and was a real, confirmed command-injection bug:
        # any GUI-typed module parameter, or any AI-agent-supplied one
        # (parameters flow through this same builder for AI-initiated runs
        # too), could break out of the intended command.
        from shell_command_builder import find_bash_invocation

        env_vars = {}
        if self.active_engagement:
            eng = self._eng_raw.get("engagements", {}).get(self.active_engagement, {})
            env_vars["GS_ENGAGEMENT_ID"] = eng.get("id", self.active_engagement)
            env_vars["GS_ENVIRONMENT"] = eng.get("environment", "lab")
            scope_file = (eng.get("scope_file") or "").strip()
            if scope_file:
                # scope_file is captured from a Windows file-picker in
                # _new_engagement_dialog; needs WSL-path conversion only
                # when the WSL branch is actually used (wsl_path_env_keys
                # below), same as the module/wrapper script path itself.
                env_vars["GS_SCOPE_FILE"] = scope_file

        # Route through repro_runner.sh --no-capture rather than invoking the
        # module directly. Manual GUI runs used to bypass repro_runner.sh
        # entirely, so evidence collection and reproducibility scoring only
        # ever happened for AI-agent-initiated runs (which go through
        # ai_engine/tools/module_runner.py, which always wraps this way) --
        # meaning most real usage got neither.
        #
        # --no-capture specifically: repro_runner.sh's default capture mode
        # pipes the module's stdout/stderr through `tee` to save a transcript
        # artifact. That pipe makes isatty() on the module's own stdout
        # return false even though the *outer* process is still attached to
        # _execute_script's real PTY on Linux -- readline/ncurses-based
        # interactive tools (msfconsole chief among them) can behave
        # differently or lose interactivity once their own stdout isn't a
        # real tty, regardless of what's above them in the process tree.
        # --no-capture skips that pipe entirely, so the module's stdin/stdout
        # stay exactly as directly connected as if repro_runner.sh weren't
        # there at all -- interactivity is unaffected. What's NOT lost:
        # repro_runner.sh's post-execution loop still scans GS_OUTPUT_DIR and
        # hashes/evidences every real file the module writes there, and the
        # repro session itself (tool versions, commands logged, scope
        # documented) still gets scored -- only the raw terminal transcript
        # isn't saved as a separate artifact, which is an acceptable trade
        # for never touching a live interactive session's tty behavior.
        repro_runner = os.path.join(SCRIPTS_DIR, "repro_runner.sh")
        if os.path.exists(repro_runner):
            target_script = repro_runner
            full_args = ["--no-capture", path] + list(args)
            path_arg_indices = {1}  # index of `path` within full_args -- needs WSL/native conversion too
        else:
            target_script = path
            full_args = list(args)
            path_arg_indices = set()

        return find_bash_invocation(
            target_script, full_args, env_vars,
            wsl_path_env_keys={"GS_SCOPE_FILE"},
            path_arg_indices=path_arg_indices,
        )

    def _execute_script(self, cmd):
        try:
            if os.name != "nt":
                # Use PTY on Linux for full interactive terminal (msfconsole, etc.)
                import pty, select
                master_fd, slave_fd = pty.openpty()
                self.current_process = subprocess.Popen(cmd, stdout=slave_fd, stderr=slave_fd,
                    stdin=slave_fd, close_fds=True, preexec_fn=os.setsid)
                os.close(slave_fd)
                self._pty_master = master_fd
                while True:
                    try:
                        r, _, _ = select.select([master_fd], [], [], 0.1)
                        if r:
                            chunk = os.read(master_fd, 4096)
                            if not chunk:
                                break
                            text = chunk.decode("utf-8", errors="replace")
                            self._append_terminal(text)
                        # Check if process has exited
                        if self.current_process.poll() is not None:
                            # Read any remaining output
                            try:
                                while True:
                                    r, _, _ = select.select([master_fd], [], [], 0.1)
                                    if not r:
                                        break
                                    chunk = os.read(master_fd, 4096)
                                    if not chunk:
                                        break
                                    self._append_terminal(chunk.decode("utf-8", errors="replace"))
                            except OSError:
                                pass
                            break
                    except OSError:
                        break
                try:
                    os.close(master_fd)
                except OSError:
                    pass
                self._pty_master = None
                rc = self.current_process.wait()
                self._append_terminal(f"\n  [*] Exit code: {rc}\n")
            else:
                # Windows: use pipe-based approach
                self.current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE, text=False, bufsize=0,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                fd = self.current_process.stdout.fileno()
                while True:
                    try:
                        chunk = os.read(fd, 4096)
                        if not chunk:
                            break
                        self._append_terminal(chunk.decode("utf-8", errors="replace"))
                    except OSError:
                        break
                self.current_process.wait()
                self._append_terminal(f"\n  [*] Exit code: {self.current_process.returncode}\n")
        except FileNotFoundError:
            self._append_terminal("\n  [!] ERROR: No bash shell. Install WSL or Git Bash.\n")
        except Exception as e:
            self._append_terminal(f"\n  [!] ERROR: {e}\n")
        finally:
            self.current_process = None
            self._pty_master = None
            self.after(0, self._on_done)

    def _on_done(self):
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        e = int(time.time() - self.start_time) if self.start_time else 0
        self.status_dot.configure(text_color=C["neon_green"])
        self.status_label.configure(text=f"COMPLETE [{e}s]", text_color=C["neon_green"])
        self.start_time = None
        self._terminal_mode = "module"
        self._active_session_id = None
        self._term_label.configure(text="")
        self._update_sessions_btn()
        self._append_evidence_summary()
        sname = self.selected_script["name"] if self.selected_script else "Module"
        self._notify(f"✓ {sname}", f"Completed in {e}s", "success")

    def _append_evidence_summary(self):
        """Scan evidence/ and findings/ directories and print a post-execution summary."""
        base = Path(SCRIPTS_DIR)
        lines = [f"\n  {'─'*56}", "  ◈ FRAMEWORK SUMMARY", f"  {'─'*56}"]

        # Evidence manifest
        manifest = base / "evidence" / "manifest.json"
        if manifest.exists():
            try:
                with open(manifest) as f:
                    m = json.load(f)
                arts = m.get("artifacts", [])
                lines.append(f"  ◈ Evidence session : {m.get('engagement_id','?')}")
                lines.append(f"  ◈ Artifacts logged : {len(arts)}")
                if arts:
                    lines.append(f"  ◈ Last artifact    : {arts[-1].get('description','?')}")
            except Exception:
                pass

        # Findings
        findings_dir = base / "findings"
        if findings_dir.exists():
            flist = list(findings_dir.glob("*.json"))
            flist = [f for f in flist if f.name != "findings.json"]
            if flist:
                lines.append(f"  ◈ Findings recorded: {len(flist)}")
                crits = 0
                try:
                    for fp in flist:
                        fd = json.loads(fp.read_text())
                        if fd.get("severity") in ("CRITICAL", "HIGH"):
                            crits += 1
                    if crits:
                        lines.append(f"  ◈ Critical/High    : {crits}  ← review findings")
                except Exception:
                    pass

        # Reproducibility sessions
        repro_dir = base / "metrics" / "repro_sessions"
        if repro_dir.exists():
            sessions = sorted(repro_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if sessions:
                try:
                    s = json.loads(sessions[0].read_text())
                    score = s.get("reproducibility_score")
                    if score is not None:
                        bar = "█" * int(score/5) + "░" * (20 - int(score/5))
                        label = "EXCELLENT" if score>=90 else "GOOD" if score>=70 else "FAIR" if score>=50 else "POOR"
                        lines.append(f"  ◈ Repro score      : {score}/100 [{bar}] {label}")
                except Exception:
                    pass

        if len(lines) > 3:
            lines.append(f"  {'─'*56}\n")
            self._append_terminal("\n".join(lines))


    def _policy_gate(self, script, cmd_args):
        """Styled policy gate modal. Returns True if operator confirms authorization."""
        trust = get_trust_level(script)
        tc = TRUST_COLORS.get(trust, C["neon_amber"])
        td = TRUST_DISPLAY.get(trust, trust)

        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — Policy Gate")
        dlg.geometry("580x420")
        dlg.configure(fg_color=C["obsidian"])
        dlg.resizable(False, False)

        result = {"ok": False}

        # Header
        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="⚑  GHOSTSTRIKE POLICY GATE",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=C["neon_red"]).pack(pady=14)

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=12)

        def row(lbl, val, vc=C["text"]):
            f = ctk.CTkFrame(body, fg_color=C["card"], corner_radius=4, height=30)
            f.pack(fill="x", pady=3)
            f.pack_propagate(False)
            ctk.CTkLabel(f, text=f"  {lbl}", width=160, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_dim"]).pack(side="left")
            ctk.CTkLabel(f, text=val, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=vc).pack(side="left", padx=8)

        row("Module", script["filename"])
        row("Category", script.get("category", "?"))
        row("Trust Level", td, tc)
        row("Args", " ".join(cmd_args) if cmd_args else "(none)")
        row("Policy", "ENGAGEMENT_ID + SCOPE_FILE required" if trust in ("HIGH_IMPACT","LAB_ONLY") else "Standard authorization", C["neon_amber"] if trust == "HIGH_IMPACT" else C["neon_red"] if trust == "LAB_ONLY" else C["neon_green"])

        if trust == "LAB_ONLY":
            warn = ctk.CTkFrame(body, fg_color="#1a0505", corner_radius=4, border_width=1, border_color=C["neon_red"])
            warn.pack(fill="x", pady=(8,4))
            ctk.CTkLabel(warn, text="☠  LAB_ONLY — This module is destructive. Run only in an isolated lab environment.",
                font=ctk.CTkFont(family="Consolas", size=13), text_color=C["neon_red"],
                wraplength=500).pack(padx=10, pady=8)
        elif trust == "HIGH_IMPACT":
            warn = ctk.CTkFrame(body, fg_color="#1a0e00", corner_radius=4, border_width=1, border_color=C["neon_amber"])
            warn.pack(fill="x", pady=(8,4))
            ctk.CTkLabel(warn, text="⚠  HIGH_IMPACT — Active exploitation. Written authorization required before proceeding.",
                font=ctk.CTkFont(family="Consolas", size=13), text_color=C["neon_amber"],
                wraplength=500).pack(padx=10, pady=8)

        confirm_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(body, text="I have explicit written authorization to engage this target",
            variable=confirm_var,
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"],
            fg_color=C["neon_purple"], hover_color=C["neon_violet"]).pack(anchor="w", pady=(10,4))

        bf = ctk.CTkFrame(body, fg_color="transparent")
        bf.pack(fill="x", pady=6)

        def _proceed():
            if not confirm_var.get():
                messagebox.showwarning("Authorization Required",
                    "Check the authorization confirmation box to proceed.")
                return
            result["ok"] = True
            dlg.destroy()

        ctk.CTkButton(bf, text="▶  EXECUTE MODULE",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=C["neon_green"], hover_color="#16a34a", text_color="#000",
            height=36, width=180, corner_radius=5, command=_proceed).pack(side="left", padx=(0,8))
        ctk.CTkButton(bf, text="■  ABORT",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["border"],
            height=36, width=100, corner_radius=5,
            command=dlg.destroy).pack(side="left")

        dlg.update_idletasks()
        dlg.lift()
        dlg.focus_force()
        dlg.grab_set()
        dlg.wait_window()
        return result["ok"]

    def _run_benchmarks(self):
        """Launch the benchmark runner in the terminal."""
        bench_script = str(Path(SCRIPTS_DIR) / "benchmarks" / "run_benchmarks.sh")
        if not os.path.exists(bench_script):
            messagebox.showerror("Not Found", f"Benchmark runner not found:\n{bench_script}")
            return
        self._clear_terminal()
        self._append_terminal("\n  ◈ GHOSTSTRIKE BENCHMARK MODE\n")
        self._append_terminal("  Running: benchmarks/run_benchmarks.sh --target all --report\n")
        self._append_terminal(f"  {'='*56}\n\n")
        self.start_time = time.time()
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_dot.configure(text_color=C["neon_cyan"])
        self.status_label.configure(text="BENCHMARKING...", text_color=C["neon_cyan"])
        self._update_timer()
        cmd = self._build_shell_command(bench_script, ["--target", "all", "--report"])
        threading.Thread(target=self._execute_script, args=(cmd,), daemon=True).start()

    def _clear_module_findings(self, script_filename):
        """Delete all findings from the central DB that belong to this module."""
        import os as _os
        module_name = script_filename.replace(".sh", "")
        findings_dir = Path(SCRIPTS_DIR) / "findings"
        if not findings_dir.exists():
            return
        removed = 0
        for fp in list(findings_dir.glob("*.json")):
            if fp.name in ("findings.json", "findings.sarif.json"):
                continue
            try:
                d = json.loads(fp.read_text())
                if d.get("module","") == module_name:
                    fp.unlink()
                    removed += 1
            except Exception:
                pass

    def _open_attack_graph(self):
        """Builds and opens the attack graph for the active engagement.

        Pure Python (lib/attack_graph_builder.py) -- invoked directly via
        sys.executable, not through the WSL/git-bash routing _build_shell_command
        uses for bash modules. It never shells out to bash itself, so there is
        no cross-environment path translation to do here.
        """
        eid = self.active_engagement
        if not eid:
            messagebox.showinfo("No Active Engagement",
                "Select or create an engagement first — the attack graph is built "
                "from one engagement's findings.")
            return
        eng = self._eng_raw.get("engagements", {}).get(eid, {})
        real_id = eng.get("id", eid)
        builder = os.path.join(SCRIPTS_DIR, "lib", "attack_graph_builder.py")
        if not os.path.exists(builder):
            messagebox.showerror("Attack Graph", f"Builder script not found:\n{builder}")
            return
        try:
            result = subprocess.run(
                [sys.executable, builder, "render", "--engagement", real_id, "--open"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                messagebox.showerror("Attack Graph",
                    f"Failed to build attack graph:\n{result.stderr[-800:] or result.stdout[-800:]}")
        except Exception as e:
            messagebox.showerror("Attack Graph", f"Failed to build attack graph:\n{e}")

    def _open_dedup_review(self, parent):
        """
        Operator-override panel for lib/finding_dedup.py's proposed merge
        groups. Replaces the findings viewer's old crude title-match dedup
        (see _show_findings) with the real tiered dedup engine's output:
        HIGH/MEDIUM-confidence groups are usually already auto-merged by
        gs_finding_dedup_auto at write time (see lib/common.sh's
        gs_auto_record_findings), so what mainly shows up here is the
        LOW-confidence "same host + same MITRE technique" suggestions that
        are deliberately never auto-merged -- exactly the case the plan
        called out (Nmap found the port, Nikto found the vuln on it, no
        textual title overlap at all).
        """
        dedup_py = os.path.join(SCRIPTS_DIR, "lib", "finding_dedup.py")
        if not os.path.exists(dedup_py):
            messagebox.showerror("Review Duplicates", f"finding_dedup.py not found:\n{dedup_py}")
            return

        eid = None
        if self.active_engagement:
            eng = self._eng_raw.get("engagements", {}).get(self.active_engagement, {})
            eid = eng.get("id", self.active_engagement)

        def _scan():
            cmd = [sys.executable, dedup_py, "scan"]
            if eid:
                cmd += ["--engagement", eid]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return json.loads(r.stdout) if r.returncode == 0 else []
            except Exception:
                return []

        groups = _scan()

        dlg = ctk.CTkToplevel(parent)
        dlg.title("GhostStrike — Review Duplicate Findings")
        dlg.geometry("760x560")
        dlg.configure(fg_color=C["obsidian"])
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force()))

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], corner_radius=0, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"⌘  PROPOSED MERGES  [{len(groups)} group(s)]",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_amber"]).pack(side="left", padx=16, pady=11)

        if not groups:
            ctk.CTkLabel(dlg, text="No proposed duplicate groups right now.\n"
                "(High/medium-confidence duplicates are usually auto-merged already —\n"
                "this list is mainly for lower-confidence suggestions that need a human call.)",
                font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"],
                justify="center").pack(expand=True)
            return

        sf = ctk.CTkScrollableFrame(dlg, fg_color="transparent")
        sf.pack(fill="both", expand=True, padx=12, pady=12)

        findings_dir = Path(SCRIPTS_DIR) / "findings"

        def _title_of(finding_id):
            try:
                d = json.loads((findings_dir / f"{finding_id}.json").read_text())
                return f"[{d.get('severity','?')}] {d.get('title','?')}"
            except Exception:
                return finding_id

        def _refresh():
            dlg.destroy()
            self._open_dedup_review(parent)

        for g in groups:
            members = g.get("members", [])
            card = ctk.CTkFrame(sf, fg_color=C["card"], corner_radius=6, border_width=1,
                border_color=C["border"])
            card.pack(fill="x", pady=5)

            conf = g.get("confidence", "?")
            conf_color = {"HIGH": C["neon_green"], "MEDIUM": C["neon_amber"], "LOW": C["neon_cyan"]}.get(conf, C["text_dim"])
            ctk.CTkLabel(card, text=f"{conf} confidence" + ("  ·  auto-mergeable" if g.get("auto_mergeable") else "  ·  needs review"),
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=conf_color, anchor="w").pack(fill="x", padx=12, pady=(10, 2))

            for m in members:
                ctk.CTkLabel(card, text=f"  • {_title_of(m)}  ({m[:8]}…)",
                    font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text"],
                    anchor="w").pack(fill="x", padx=12)

            for reason in g.get("reasons", []):
                ctk.CTkLabel(card, text=f"  reason: {reason}",
                    font=ctk.CTkFont(family="Consolas", size=11), text_color=C["text_ghost"],
                    anchor="w").pack(fill="x", padx=12)

            def _apply(members=members, conf=conf):
                cmd = [sys.executable, dedup_py, "apply"] + members + ["--confidence", conf]
                if eid:
                    cmd += ["--engagement", eid]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    messagebox.showerror("Merge Failed", r.stderr or r.stdout)
                    return
                _refresh()

            def _reject(members=members):
                if len(members) != 2:
                    messagebox.showinfo("Reject", "Reject only applies to 2-finding groups right now — "
                        "larger groups need a manual look at which pair is actually wrong.")
                    return
                cmd = [sys.executable, dedup_py, "reject"] + members
                subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                _refresh()

            bf = ctk.CTkFrame(card, fg_color="transparent")
            bf.pack(fill="x", padx=12, pady=(6, 10))
            ctk.CTkButton(bf, text="MERGE", width=90, height=26,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                fg_color=C["neon_green"], hover_color=C["neon_purple"],
                command=_apply).pack(side="left", padx=(0, 6))
            ctk.CTkButton(bf, text="NOT A DUPLICATE", width=140, height=26,
                font=ctk.CTkFont(family="Consolas", size=11),
                fg_color=C["card"], hover_color=C["hover"], border_width=1, border_color=C["text_dim"],
                command=_reject).pack(side="left")

    def _show_findings(self):
        """Open findings viewer filtered to the currently selected module."""
        import re as _re

        # Determine active module name from selected script
        active_module = None
        module_label = "ALL MODULES"
        if self.selected_script:
            active_module = self.selected_script["filename"].replace(".sh", "")
            module_label = self.selected_script["name"].upper()

        findings_dir = Path(SCRIPTS_DIR) / "findings"
        findings_raw = []
        if findings_dir.exists():
            for fp in sorted(findings_dir.glob("*.json")):
                if fp.name in ("findings.json", "findings.sarif.json"):
                    continue
                try:
                    d = json.loads(fp.read_text())
                    # Filter to current module only
                    if active_module and d.get("module","") != active_module:
                        continue
                    findings_raw.append(d)
                except Exception:
                    pass

        # Default view excludes findings the dedup engine (lib/finding_dedup.py)
        # has already merged into another finding -- superseded_by is set on
        # the absorbed record, never on the surviving primary. This replaces
        # the old crude title-string-match dedup that lived here (which had
        # no concept of merge groups, evidence, or confidence, and could
        # silently hide a *different* finding that happened to share a
        # title). Merged-away records are never deleted -- see
        # _open_dedup_review for reviewing/undoing a merge.
        findings = [f for f in findings_raw if not f.get("superseded_by")]

        # Port → CVE / Metasploit exploit mapping (auto-enrich legacy findings)
        PORT_INFO = {
            21:    ("CVE-2010-4221", "exploit/unix/ftp/vsftpd_234_backdoor"),
            22:    ("N/A",           "auxiliary/scanner/ssh/ssh_login"),
            23:    ("N/A",           "auxiliary/scanner/telnet/telnet_login"),
            25:    ("CVE-2010-4344", "auxiliary/scanner/smtp/smtp_enum"),
            80:    ("N/A",           "auxiliary/scanner/http/http_version"),
            110:   ("N/A",           "auxiliary/scanner/pop3/pop3_login"),
            135:   ("CVE-2003-0352", "exploit/windows/dcerpc/ms03_026_dcom"),
            139:   ("CVE-2017-0143", "exploit/windows/smb/ms17_010_eternalblue"),
            443:   ("CVE-2014-0160", "auxiliary/scanner/http/http_version"),
            445:   ("CVE-2017-0144", "exploit/windows/smb/ms17_010_eternalblue"),
            1433:  ("CVE-2020-0618", "exploit/windows/mssql/ms09_004_sp_replwritetovarbin"),
            3306:  ("CVE-2012-2122", "exploit/multi/mysql/mysql_udf_payload"),
            3389:  ("CVE-2019-0708", "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"),
            5432:  ("N/A",           "auxiliary/scanner/postgres/postgres_login"),
            5900:  ("N/A",           "auxiliary/scanner/vnc/vnc_login"),
            6379:  ("N/A",           "auxiliary/scanner/redis/redis_server"),
            8080:  ("N/A",           "auxiliary/scanner/http/http_version"),
            27017: ("N/A",           "auxiliary/scanner/mongodb/mongodb_login"),
        }
        for f in findings:
            if not f.get("cve") and not f.get("exploit"):
                port = None
                m = _re.search(r'(\d+)/tcp', f.get("title",""))
                if m:
                    port = int(m.group(1))
                if port is None:
                    try: port = int(f.get("target",{}).get("port",0))
                    except: pass
                if port and port in PORT_INFO:
                    f["cve"], f["exploit"] = PORT_INFO[port]

        win = ctk.CTkToplevel(self)
        win.title("GhostStrike — Findings Viewer")
        win.geometry("1400x720")
        win.configure(fg_color=C["obsidian"])
        win.after(100, lambda w=win: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

        hdr = ctk.CTkFrame(win, fg_color=C["abyss"], corner_radius=0, height=46)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"◈  FINDINGS — {module_label}  [{len(findings)} results]",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_purple"]).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(hdr, text="click any row for details",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_ghost"]).pack(side="left", padx=4)
        ctk.CTkButton(hdr, text="\U0001F578  Attack Graph", width=140, height=28,
            fg_color=C["abyss"], hover_color=C["neon_purple"], border_width=1,
            border_color=C["neon_purple"], text_color=C["neon_purple"],
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            command=self._open_attack_graph).pack(side="right", padx=16, pady=9)
        ctk.CTkButton(hdr, text="⌘  Review Duplicates", width=170, height=28,
            fg_color=C["abyss"], hover_color=C["neon_amber"], border_width=1,
            border_color=C["neon_amber"], text_color=C["neon_amber"],
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            command=lambda: self._open_dedup_review(win)).pack(side="right", padx=(4, 0), pady=9)

        if not findings:
            msg = f"No findings for [{module_label}] yet.\nRun the module first to populate findings." \
                  if active_module else "No findings recorded yet.\nRun a module to populate findings."
            ctk.CTkLabel(win, text=msg,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(expand=True)
            return

        SEV_COLOR = {"CRITICAL":C["neon_red"],"HIGH":C["neon_red"],
                     "MEDIUM":C["neon_amber"],"LOW":C["neon_cyan"],"INFO":C["text_dim"]}

        sf = ctk.CTkScrollableFrame(win, fg_color="transparent")
        sf.pack(fill="both", expand=True, padx=12, pady=12)

        # Column headers
        cols = [("SEVERITY",80),("TITLE",250),("CVE",130),("METASPLOIT EXPLOIT",250),("MITRE",80),("MODULE",120)]
        hf = ctk.CTkFrame(sf, fg_color=C["slate"], corner_radius=4, height=26)
        hf.pack(fill="x", pady=(0,4))
        for txt, w in cols:
            ctk.CTkLabel(hf, text=txt, width=w, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["text_ghost"]).pack(side="left", padx=6)

        SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity","INFO"),5))

        def _copy_to_clip(widget, text, btn):
            widget.clipboard_clear()
            widget.clipboard_append(text)
            btn.configure(text="✓ COPIED", text_color=C["neon_green"])
            btn.after(1500, lambda: btn.configure(text="COPY", text_color=C["text_ghost"]))

        def _show_detail(fd):
            d = ctk.CTkToplevel(win)
            d.title("Finding Detail")
            d.geometry("760x540")
            d.configure(fg_color=C["obsidian"])
            d.after(100, lambda: (d.update_idletasks(), d.lift(), d.focus_force()))

            # Build ready-to-use commands for copyable fields
            exploit   = fd.get("exploit","") or ""
            cve       = fd.get("cve","") or ""
            target    = fd.get("target",{})
            host      = target.get("host","") if isinstance(target, dict) else ""
            port      = str(target.get("port","")) if isinstance(target, dict) else ""

            msf_cmd = ""
            if exploit and exploit != "N/A":
                msf_cmd = f"use {exploit}\nset RHOSTS {host}\nset RPORT {port}\ncheck\nexploit"

            searchsploit_cmd = f"searchsploit {cve}" if cve and cve != "N/A" else ""

            sf2 = ctk.CTkScrollableFrame(d, fg_color="transparent")
            sf2.pack(fill="both", expand=True, padx=16, pady=16)
            sev = fd.get("severity","?")
            sc = SEV_COLOR.get(sev, C["text_dim"])

            # Copyable fields: label, value, color, copy_text (None = no copy btn)
            rows_data = [
                ("SEVERITY",    sev,                                                    sc,                 None),
                ("TITLE",       fd.get("title","?"),                                    C["text"],          fd.get("title","?")),
                ("DESCRIPTION", fd.get("description","N/A"),                            C["text_dim"],      None),
                ("CVE",         cve or "N/A",                                           C["neon_amber"],    cve if cve and cve != "N/A" else None),
                ("EXPLOIT",     exploit or "N/A",                                       C["neon_green"],    exploit if exploit and exploit != "N/A" else None),
                ("MSF COMMAND", msf_cmd or "N/A",                                       C["neon_green"],    msf_cmd if msf_cmd else None),
                ("SEARCHSPLOIT",searchsploit_cmd or "N/A",                              C["neon_cyan"],     searchsploit_cmd if searchsploit_cmd else None),
                ("REMEDIATION", fd.get("remediation","N/A"),                            C["text_dim"],      None),
                ("MITRE",       fd.get("mitre_attack",{}).get("technique_id","N/A"),    C["neon_purple"],   None),
                ("TARGET",      f"{host}:{port}" if host else "N/A",                   C["text_dim"],      f"{host}:{port}" if host else None),
                ("DISCOVERED",  fd.get("discovered_at",""),                             C["text_dim"],      None),
            ]
            for label, value, color, copy_text in rows_data:
                rf = ctk.CTkFrame(sf2, fg_color=C["card"], corner_radius=4)
                rf.pack(fill="x", pady=2)
                ctk.CTkLabel(rf, text=label, width=110, anchor="nw",
                    font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                    text_color=C["text_ghost"]).pack(side="left", padx=8, pady=6)
                ctk.CTkLabel(rf, text=str(value), anchor="nw", wraplength=480,
                    font=ctk.CTkFont(family="Consolas", size=13),
                    text_color=color).pack(side="left", padx=4, pady=6, fill="x", expand=True)
                if copy_text:
                    btn = ctk.CTkButton(rf, text="COPY", width=55, height=22,
                        font=ctk.CTkFont(family="Consolas", size=12),
                        fg_color="transparent", hover_color=C["slate"],
                        border_width=1, border_color=C["border"],
                        text_color=C["text_ghost"], corner_radius=3)
                    btn.configure(command=lambda w=d, t=copy_text, b=btn: _copy_to_clip(w, t, b))
                    btn.pack(side="right", padx=6, pady=4)

        for fd in findings:
            sev = fd.get("severity","?")
            sc = SEV_COLOR.get(sev, C["text_dim"])
            row = ctk.CTkFrame(sf, fg_color=C["card"], corner_radius=4, height=30)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)
            ctk.CTkLabel(row, text=sev, width=80, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=sc).pack(side="left", padx=6)
            ctk.CTkLabel(row, text=fd.get("title","?")[:42], width=250, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text"]).pack(side="left")
            cve = fd.get("cve","") or ""
            ctk.CTkLabel(row, text=cve[:20], width=130, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["neon_amber"] if cve and cve != "N/A" else C["text_dim"]).pack(side="left")
            exploit = fd.get("exploit","") or ""
            ctk.CTkLabel(row, text=(exploit[:36] if exploit and exploit != "N/A" else "—"), width=250, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["neon_green"] if exploit and exploit != "N/A" else C["text_dim"]).pack(side="left")
            mitre = fd.get("mitre_attack",{}).get("technique_id","") or ""
            ctk.CTkLabel(row, text=mitre, width=80, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["neon_purple"]).pack(side="left")
            ctk.CTkLabel(row, text=fd.get("module","")[:20], width=120, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(side="left")
            # Click any part of the row to see full detail
            _fd = fd
            row.bind("<Button-1>", lambda e, f=_fd: _show_detail(f))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, f=_fd: _show_detail(f))

    # ══════════════════════════════════════════
    # Tool Health Check
    # ══════════════════════════════════════════

    # ══════════════════════════════════════════
    # Pentest Roadmap Guide (GUI Assistant)
    # ══════════════════════════════════════════

    ROADMAPS = {
        "network": [
            ("Network Device Discovery", "netdiscover_automation", "Discover all live hosts on the network.\nLeave range empty for auto-detect."),
            ("Nmap Advanced Scanner", "nmap_automation", "Scan discovered hosts for open ports.\nLeave Ports empty for top 1000. Use T4 timing."),
            ("Nmap Vuln & Exploit Scanner", "nmap_vulnerability_scanner", "Scan for known CVEs and vulnerabilities\non discovered services."),
            ("SearchSploit Exploit Finder", "searchsploit_automation", "Search Exploit-DB for public exploits\nmatching your discovered services and CVEs."),
            ("MITM Attack Suite", "mitm_attack_suite", "Test for MITM vulnerabilities:\nARP spoofing, traffic interception."),
            ("Metasploit Automation", "metasploit_automation", "Exploit confirmed vulnerabilities.\nUse exploit info from SearchSploit findings."),
            ("Password Attack Suite", "password_attack_suite", "Test login services for weak credentials:\nSSH, FTP, SMB, RDP."),
            ("Lateral Movement Toolkit", "lateral_movement", "Map lateral movement paths:\nSMB, WinRM, SSH pivoting, Pass-the-Hash."),
            ("Pentest Report Generator", "pentest_report_generator", "Generate your final penetration test report\nwith all findings and remediation."),
        ],
        "webapp": [
            ("DNS Reconnaissance", "dns_recon", "Discover subdomains and DNS records.\nMap the full web attack surface."),
            ("Nmap Advanced Scanner", "nmap_automation", "Scan for web ports: 80, 443, 8080, 8443.\nPorts field: 80,443,8080,8443,3000"),
            ("HTTP Security Headers Analyzer", "http_security_headers", "Check HSTS, CSP, CORS, cookies,\nserver version disclosure."),
            ("CMS Scanner", "cms_scanner", "Detect WordPress, Joomla, Drupal.\nAuto-runs wpscan if WordPress found."),
            ("Directory & File Bruteforce", "directory_bruteforce", "Find hidden directories and files\nusing gobuster/dirb/ffuf."),
            ("OWASP Top 10 Scanner", "owasp_top10_scanner", "Test for OWASP Top 10 vulnerabilities:\nSQLi, XSS, CSRF, broken auth."),
            ("SQLMap Automated Pentest", "sqlmap_automated_pentest", "Test input parameters for SQL injection.\nProvide URL with parameters."),
            ("SSRF Vulnerability Tester", "ssrf_tester", "Test for Server-Side Request Forgery:\ninternal service & cloud metadata access."),
            ("File Upload Tester", "file_upload_tester", "Test upload endpoints for bypass:\nextension, content-type manipulation."),
            ("API Security Tester", "api_security_tester", "Test REST/GraphQL APIs for auth bypass,\nIDOR, rate limiting."),
            ("SSL/TLS Analyzer", "ssl_tls_analyzer", "Check SSL/TLS for weak ciphers,\nexpired certs, known vulns."),
            ("Pentest Report Generator", "pentest_report_generator", "Compile all findings into a\nprofessional web app security report."),
        ],
        "wireless": [
            ("WiFi Penetration Tester", "wifi_penetration_tester", "Scan for wireless networks,\ncapture handshakes, check encryption."),
            ("Rogue AP & Evil Twin Detector", "rogue_ap_detector", "Detect rogue access points\nand evil twin attacks."),
            ("WiFi Deauth Tester", "deauth_tester", "Test AP resilience to\ndeauthentication frame attacks."),
            ("Bluetooth Scanner", "bluetooth_scanner", "Scan for Bluetooth/BLE devices\nand check for vulnerabilities."),
            ("Password Attack Suite", "password_attack_suite", "Crack captured WPA handshakes\nwith wordlists."),
            ("Pentest Report Generator", "pentest_report_generator", "Generate wireless security report."),
        ],
        "activedir": [
            ("Network Device Discovery", "netdiscover_automation", "Discover domain controllers,\nservers, and workstations."),
            ("Nmap Advanced Scanner", "nmap_automation", "Scan for AD services.\nPorts: 53,88,135,139,389,445,636,3268,3389"),
            ("Active Directory Tester", "active_directory_tester", "Enumerate users, groups, GPOs,\ntrusts, and shares."),
            ("BloodHound AD Mapper", "bloodhound_ad_mapper", "Collect AD data for attack path\nanalysis. Add -d for domain name."),
            ("Responder LLMNR Poisoner", "responder_poisoner", "Detect LLMNR/NBT-NS traffic and\ncapture NTLM hashes."),
            ("Kerberos Attack Suite", "kerberos_attack_suite", "Kerberoasting, AS-REP roasting,\npass-the-ticket attacks."),
            ("NTLM Relay Tester", "ntlm_relay_tester", "Test for NTLM relay and\npass-the-hash attacks."),
            ("Password Spraying Campaign", "password_spraying_campaign", "Spray passwords against\ndiscovered AD accounts."),
            ("Pentest Report Generator", "pentest_report_generator", "Generate AD pentest report."),
        ],
        "cloud": [
            ("AWS Security Scanner", "aws_security_scanner", "Enumerate AWS resources,\nIAM, S3 buckets, security groups."),
            ("Azure/GCP Enumeration", "azure_gcp_enumeration", "Enumerate Azure AD, GCP projects,\nmisconfigurations."),
            ("Cloud IAM PrivEsc Scanner", "iam_privesc_scanner", "Scan IAM for privilege escalation\npaths and wildcard policies."),
            ("Cloud Storage Bucket Tester", "cloud_storage_bucket_tester", "Test for public S3/Blob/GCS\nbuckets and data exposure."),
            ("Serverless Security Tester", "serverless_tester", "Test Lambda/Functions for secrets\nin env vars, VPC gaps."),
            ("Container Orchestration Security", "container_orchestration_security", "Test Docker/K8s for\nmisconfigurations and escapes."),
            ("Pentest Report Generator", "pentest_report_generator", "Generate cloud assessment report."),
        ],
        "iot": [
            ("Network Device Discovery", "netdiscover_automation", "Discover all IoT devices\non the network."),
            ("IoT Default Credentials Scanner", "iot_default_creds_scanner", "Check IoT devices for\ndefault/weak credentials."),
            ("IoT Firmware Analyzer", "iot_firmware_analyzer", "Extract and analyze firmware\nfor vulnerabilities."),
            ("MQTT Protocol Tester", "iot_mqtt_tester", "Test MQTT broker for auth bypass,\ninjection, information leak."),
            ("CoAP Protocol Tester", "iot_coap_tester", "Test CoAP endpoints for\nsecurity issues."),
            ("IoT Protocol Fuzzer", "iot_fuzz_coap_mqtt", "Fuzz IoT protocols to find\ncrashes and vulnerabilities."),
            ("Pentest Report Generator", "pentest_report_generator", "Generate IoT assessment report."),
        ],
    }

    def _show_roadmap_guide(self):
        """Show the interactive pentest roadmap assistant panel."""
        win = ctk.CTkToplevel(self)
        win.title("GhostStrike -- Pentest Guide")
        win.geometry("680x700")
        win.configure(fg_color=C["obsidian"])
        win.after(100, lambda w=win: (w.update_idletasks(), w.lift(), w.focus_force()))

        # Header
        hdr = ctk.CTkFrame(win, fg_color=C["abyss"], corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="PENTEST GUIDE",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=C["neon_green"]).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(hdr, text="Select a pentest type to start",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_ghost"]).pack(side="left", padx=4)

        content = ctk.CTkFrame(win, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=12, pady=12)

        # Step display area (will be populated after type selection)
        self._guide_content = content
        self._guide_win = win
        self._guide_step = 0

        # Type selection buttons
        type_frame = ctk.CTkFrame(content, fg_color=C["card"], corner_radius=6)
        type_frame.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(type_frame, text="SELECT PENTEST TYPE:",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["neon_purple"]).pack(anchor="w", padx=12, pady=(10, 6))

        btn_frame = ctk.CTkFrame(type_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 10))
        types = [
            ("NETWORK", "network", C["neon_green"]),
            ("WEB APP", "webapp", C["neon_amber"]),
            ("WIRELESS", "wireless", C["neon_cyan"]),
            ("ACTIVE DIR", "activedir", C["neon_purple"]),
            ("CLOUD", "cloud", C["neon_red"]),
            ("IoT", "iot", C["text"]),
        ]
        for label, key, color in types:
            ctk.CTkButton(btn_frame, text=label, width=95, height=32,
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                fg_color="transparent", hover_color=C["hover"],
                border_width=2, border_color=color, text_color=color,
                corner_radius=4,
                command=lambda k=key: self._load_roadmap_steps(k)
            ).pack(side="left", padx=3)

        # Steps container
        self._steps_frame = ctk.CTkScrollableFrame(content, fg_color="transparent")
        self._steps_frame.pack(fill="both", expand=True)

    def _check_module_done(self, module_name):
        """Check if a module has findings recorded."""
        return self._count_module_findings(module_name) > 0

    def _count_module_findings(self, module_name):
        """Count findings for a specific module."""
        findings_dir = Path(SCRIPTS_DIR) / "findings"
        if not findings_dir.exists():
            return 0
        count = 0
        for fp in findings_dir.glob("*.json"):
            try:
                d = json.loads(fp.read_text())
                if d.get("module", "") == module_name:
                    count += 1
            except Exception:
                pass
        return count

    def _get_module_findings(self, module_name):
        """Get all findings for a module as list of dicts."""
        findings_dir = Path(SCRIPTS_DIR) / "findings"
        results = []
        if not findings_dir.exists():
            return results
        for fp in findings_dir.glob("*.json"):
            try:
                d = json.loads(fp.read_text())
                if d.get("module", "") == module_name:
                    results.append(d)
            except Exception:
                pass
        return results

    def _find_script_by_module(self, module_name):
        """Find a script entry by its module (filename without .sh)."""
        for cat_scripts in self.categories.values():
            for s in cat_scripts:
                if s["filename"].replace(".sh", "") == module_name:
                    return s
        return None

    def _load_roadmap_steps(self, pentest_type):
        """Load the interactive step-by-step guide for a pentest type."""
        steps = self.ROADMAPS.get(pentest_type, [])
        if not steps:
            return
        self._active_roadmap_type = pentest_type
        self._expanded_step = None

        # Clear old steps
        for w in self._steps_frame.winfo_children():
            w.destroy()

        # Progress calculation
        done_count = sum(1 for _, mod, _ in steps if self._check_module_done(mod))
        total = len(steps)
        pct = int(done_count / total * 100) if total else 0
        all_done = done_count == total

        # Progress header
        prog_frame = ctk.CTkFrame(self._steps_frame, fg_color=C["card"], corner_radius=6)
        prog_frame.pack(fill="x", pady=(0, 8))
        prog_hdr = ctk.CTkFrame(prog_frame, fg_color="transparent")
        prog_hdr.pack(fill="x", padx=8, pady=(6, 2))
        ctk.CTkLabel(prog_hdr, text=f"  {pentest_type.upper()} PENTEST  --  {done_count}/{total} steps ({pct}%)",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_green"] if all_done else C["neon_amber"]).pack(side="left")
        # Refresh button
        ctk.CTkButton(prog_hdr, text="REFRESH", width=70, height=22,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["slate"], hover_color=C["hover"], text_color=C["neon_cyan"],
            corner_radius=3, command=lambda: self._load_roadmap_steps(pentest_type)).pack(side="right", padx=4)
        pbar = ctk.CTkProgressBar(prog_frame, height=10, corner_radius=4,
            progress_color=C["neon_green"] if all_done else C["neon_amber"])
        pbar.set(done_count / total if total else 0)
        pbar.pack(fill="x", padx=12, pady=(2, 8))

        if all_done:
            ctk.CTkLabel(prog_frame, text="ALL STEPS COMPLETE! Generate your report.",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["neon_green"]).pack(pady=(0, 6))

        # Severity color map
        SEV_C = {"CRITICAL": C["neon_red"], "HIGH": C["neon_red"], "MEDIUM": C["neon_amber"],
                 "LOW": C["neon_cyan"], "INFO": C["text_dim"]}

        # Render each step
        current_found = False
        for i, (name, module, desc) in enumerate(steps, 1):
            is_done = self._check_module_done(module)
            is_current = not is_done and not current_found
            finding_count = self._count_module_findings(module)

            if is_current:
                current_found = True

            # Step container
            if is_current:
                fg, border_c, bw = C["slate"], C["neon_green"], 2
            elif is_done:
                fg, border_c, bw = C["card"], C["neon_green"], 1
            else:
                fg, border_c, bw = C["card"], C["border"], 1

            step_frame = ctk.CTkFrame(self._steps_frame, fg_color=fg,
                corner_radius=6, border_width=bw, border_color=border_c)
            step_frame.pack(fill="x", pady=3)

            # ── Clickable header row ──
            hdr_row = ctk.CTkFrame(step_frame, fg_color="transparent", cursor="hand2")
            hdr_row.pack(fill="x", padx=8, pady=(6, 2))

            # Step number badge
            badge_color = C["neon_green"] if is_done else (C["neon_amber"] if is_current else C["text_ghost"])
            badge_text = "✓" if is_done else str(i)
            ctk.CTkLabel(hdr_row, text=badge_text, width=24, height=24,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["obsidian"], fg_color=badge_color,
                corner_radius=12).pack(side="left", padx=(0, 6))

            ctk.CTkLabel(hdr_row, text=name,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["text"]).pack(side="left")

            # Status + findings count on right
            status_frame = ctk.CTkFrame(hdr_row, fg_color="transparent")
            status_frame.pack(side="right")

            if finding_count > 0:
                ctk.CTkLabel(status_frame, text=f"{finding_count} findings",
                    font=ctk.CTkFont(family="Consolas", size=12),
                    text_color=C["neon_purple"]).pack(side="left", padx=(0, 8))

            status_text = "DONE" if is_done else ("CURRENT" if is_current else "PENDING")
            status_color = C["neon_green"] if is_done else (C["neon_amber"] if is_current else C["text_ghost"])
            ctk.CTkLabel(status_frame, text=status_text,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=status_color).pack(side="left")

            # ── Expandable detail area (shown for current step or when clicked) ──
            detail_frame = ctk.CTkFrame(step_frame, fg_color="transparent")
            if is_current:
                detail_frame.pack(fill="x", padx=12, pady=(2, 6))
            else:
                # Make clickable to expand
                def toggle_detail(df=detail_frame, sf=step_frame):
                    if df.winfo_manager():
                        df.pack_forget()
                    else:
                        df.pack(fill="x", padx=12, pady=(2, 6))
                hdr_row.bind("<Button-1>", lambda e, df=detail_frame, sf=step_frame: toggle_detail(df, sf))
                for child in hdr_row.winfo_children():
                    child.bind("<Button-1>", lambda e, df=detail_frame, sf=step_frame: toggle_detail(df, sf))

            # Description
            ctk.CTkLabel(detail_frame, text=desc,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"], anchor="w", justify="left").pack(anchor="w", pady=(2, 4))

            # Findings preview (if module has findings)
            if finding_count > 0:
                findings_list = self._get_module_findings(module)
                findings_preview = ctk.CTkFrame(detail_frame, fg_color=C["terminal"], corner_radius=4)
                findings_preview.pack(fill="x", pady=(2, 4))
                ctk.CTkLabel(findings_preview, text=f"  FINDINGS ({finding_count}):",
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    text_color=C["neon_purple"]).pack(anchor="w", padx=6, pady=(4, 2))
                for fd in findings_list[:6]:  # Show max 6
                    sev = fd.get("severity", "INFO")
                    title = fd.get("title", "?")[:55]
                    sc = SEV_C.get(sev, C["text_dim"])
                    row = ctk.CTkFrame(findings_preview, fg_color="transparent", height=18)
                    row.pack(fill="x", padx=8)
                    row.pack_propagate(False)
                    ctk.CTkLabel(row, text=sev, width=60,
                        font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                        text_color=sc, anchor="w").pack(side="left")
                    ctk.CTkLabel(row, text=title,
                        font=ctk.CTkFont(family="Consolas", size=12),
                        text_color=C["text_dim"], anchor="w").pack(side="left", fill="x")
                if finding_count > 6:
                    ctk.CTkLabel(findings_preview, text=f"  ... and {finding_count - 6} more",
                        font=ctk.CTkFont(family="Consolas", size=12),
                        text_color=C["text_ghost"]).pack(anchor="w", padx=8, pady=(0, 4))
                ctk.CTkLabel(findings_preview, text="",height=2).pack()  # spacer

            # Action buttons
            btn_row = ctk.CTkFrame(detail_frame, fg_color="transparent")
            btn_row.pack(fill="x", pady=(2, 2))

            script = self._find_script_by_module(module)
            if script:
                if is_current:
                    ctk.CTkButton(btn_row, text=">> GO TO MODULE", width=140, height=28,
                        font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                        fg_color=C["neon_green"], text_color=C["obsidian"],
                        hover_color=C["neon_cyan"], corner_radius=4,
                        command=lambda s=script: self._go_to_module(s)).pack(side="left", padx=(0, 4))
                elif is_done:
                    ctk.CTkButton(btn_row, text="RE-RUN", width=80, height=26,
                        font=ctk.CTkFont(family="Consolas", size=12),
                        fg_color=C["slate"], text_color=C["text"],
                        hover_color=C["hover"], corner_radius=4,
                        command=lambda s=script: self._go_to_module(s)).pack(side="left", padx=(0, 4))
                    ctk.CTkButton(btn_row, text="VIEW FINDINGS", width=110, height=26,
                        font=ctk.CTkFont(family="Consolas", size=12),
                        fg_color=C["slate"], text_color=C["neon_purple"],
                        hover_color=C["hover"], corner_radius=4,
                        command=lambda s=script: self._go_to_findings(s)).pack(side="left")
                else:
                    ctk.CTkLabel(btn_row, text="Complete previous steps first",
                        font=ctk.CTkFont(family="Consolas", size=12),
                        text_color=C["text_ghost"]).pack(side="left")

    def _go_to_module(self, script):
        """Navigate to a specific module in the sidebar and select it."""
        self.selected_script = script
        self._on_script_select(script)
        if hasattr(self, '_guide_win') and self._guide_win.winfo_exists():
            self._guide_win.destroy()

    def _go_to_findings(self, script):
        """Navigate to module and open its findings."""
        self.selected_script = script
        self._on_script_select(script)
        if hasattr(self, '_guide_win') and self._guide_win.winfo_exists():
            self._guide_win.destroy()
        self.after(200, self._show_findings)

    # ══════════════════════════════════════════
    # Session Management
    # ══════════════════════════════════════════

    def _background_session(self):
        """Move the current running process to a background session."""
        if not self.current_process:
            self._append_terminal("\n  [!] No active process to background\n")
            return

        self._session_counter += 1
        sid = self._session_counter
        name = self.selected_script["name"] if self.selected_script else "Shell"
        target = ""
        # Try to extract target from the command args display
        term_text = self.terminal.get("1.0", "end")
        import re as _re
        m = _re.search(r'Target:.*?(\d+\.\d+\.\d+\.\d+)', term_text)
        if m:
            target = m.group(1)

        self._sessions[sid] = {
            "process": self.current_process,
            "pty_master": getattr(self, '_pty_master', None),
            "name": name,
            "target": target,
            "time": time.strftime("%H:%M:%S"),
            "output_buffer": self.terminal.get("1.0", "end")[-2000:],  # Keep last 2000 chars
        }

        # Detach from current terminal but keep process alive
        self.current_process = None
        self._pty_master = None
        self._terminal_mode = "module"

        self._update_sessions_btn()
        self._append_terminal(f"\n  [*] Session {sid} backgrounded: {name} ({target})\n")
        self._append_terminal(f"  [*] Use SESSIONS button to switch back\n")
        self.after(0, self._on_done)

    def _switch_to_session(self, sid):
        """Switch the terminal to an active background session."""
        if sid not in self._sessions:
            return

        sess = self._sessions[sid]
        proc = sess["process"]

        # Check if session is still alive
        if proc.poll() is not None:
            self._append_terminal(f"\n  [!] Session {sid} has died (exit: {proc.returncode})\n")
            del self._sessions[sid]
            self._update_sessions_btn()
            return

        # If there's a current process running, background it first
        if self.current_process:
            self._background_session()

        # Switch to this session
        self.current_process = proc
        self._pty_master = sess.get("pty_master")
        self._terminal_mode = "session"
        self._active_session_id = sid

        # Clear terminal and show session buffer
        self._clear_terminal()
        self._append_terminal(f"  [*] Switched to Session {sid}: {sess['name']} ({sess['target']})\n")
        self._append_terminal(f"  [*] Type commands below. Click BG to background again.\n")
        self._append_terminal(f"  {'='*50}\n")
        self._term_label.configure(text=f"SESSION {sid}")

        # Start reading output from this session's PTY
        if self._pty_master is not None:
            self.run_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.status_dot.configure(text_color=C["neon_red"])
            self.status_label.configure(text=f"SESSION {sid}", text_color=C["neon_red"])
            threading.Thread(target=self._read_session_output, args=(sid,), daemon=True).start()

        # Remove from sessions dict since it's now active
        del self._sessions[sid]
        self._update_sessions_btn()

    def _read_session_output(self, sid):
        """Read output from a session's PTY in background thread."""
        import select
        master_fd = self._pty_master
        if master_fd is None:
            return
        while self.current_process and self._pty_master == master_fd:
            try:
                r, _, _ = select.select([master_fd], [], [], 0.2)
                if r:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    self._append_terminal(chunk.decode("utf-8", errors="replace"))
                if self.current_process and self.current_process.poll() is not None:
                    break
            except OSError:
                break

    def _kill_session(self, sid):
        """Kill a background session."""
        if sid not in self._sessions:
            return
        sess = self._sessions[sid]
        proc = sess["process"]
        pty_fd = sess.get("pty_master")
        try:
            proc.kill()
        except Exception:
            pass
        try:
            if pty_fd is not None:
                os.close(pty_fd)
        except Exception:
            pass
        del self._sessions[sid]
        self._update_sessions_btn()

    def _update_sessions_btn(self):
        """Update the SESSIONS button with count."""
        # Clean dead sessions
        dead = [sid for sid, s in self._sessions.items() if s["process"].poll() is not None]
        for sid in dead:
            try:
                pty_fd = self._sessions[sid].get("pty_master")
                if pty_fd:
                    os.close(pty_fd)
            except Exception:
                pass
            del self._sessions[sid]

        count = len(self._sessions)
        self._sessions_btn.configure(
            text=f"SESSIONS [{count}]",
            text_color=C["neon_red"] if count > 0 else C["text_ghost"],
            border_color=C["neon_red"] if count > 0 else C["border"]
        )

    def _show_sessions_panel(self):
        """Show the sessions management panel."""
        self._update_sessions_btn()

        win = ctk.CTkToplevel(self)
        win.title("GhostStrike -- Active Sessions")
        win.geometry("650x450")
        win.configure(fg_color=C["obsidian"])
        win.after(100, lambda w=win: (w.update_idletasks(), w.lift(), w.focus_force()))

        hdr = ctk.CTkFrame(win, fg_color=C["abyss"], corner_radius=0, height=46)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"ACTIVE SESSIONS  [{len(self._sessions)}]",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=C["neon_red"]).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(hdr, text="click SWITCH to interact, KILL to terminate",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_ghost"]).pack(side="left", padx=4)

        sf = ctk.CTkScrollableFrame(win, fg_color="transparent")
        sf.pack(fill="both", expand=True, padx=12, pady=12)

        if not self._sessions:
            ctk.CTkLabel(sf, text="No active sessions.\n\nRun an exploit, get a shell, then click BG to background it.\nThe session stays alive while you run other modules.",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(expand=True, pady=40)
            return

        # Column headers
        hf = ctk.CTkFrame(sf, fg_color=C["slate"], corner_radius=4, height=28)
        hf.pack(fill="x", pady=(0, 4))
        for txt, w in [("ID", 40), ("TYPE", 180), ("TARGET", 120), ("TIME", 70), ("STATUS", 70), ("ACTIONS", 140)]:
            ctk.CTkLabel(hf, text=txt, width=w, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["text_ghost"]).pack(side="left", padx=4)

        for sid, sess in self._sessions.items():
            alive = sess["process"].poll() is None
            row = ctk.CTkFrame(sf, fg_color=C["card"], corner_radius=4, height=36)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            ctk.CTkLabel(row, text=str(sid), width=40,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=C["neon_red"]).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=sess["name"][:25], width=180,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text"]).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=sess["target"], width=120,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["neon_cyan"]).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=sess["time"], width=70,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(side="left", padx=4)
            ctk.CTkLabel(row, text="ALIVE" if alive else "DEAD", width=70,
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=C["neon_green"] if alive else C["neon_red"]).pack(side="left", padx=4)

            btn_frame = ctk.CTkFrame(row, fg_color="transparent")
            btn_frame.pack(side="left", padx=4)
            if alive:
                ctk.CTkButton(btn_frame, text="SWITCH", width=60, height=24,
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    fg_color=C["neon_green"], text_color=C["obsidian"],
                    hover_color=C["neon_cyan"], corner_radius=3,
                    command=lambda s=sid, w=win: (self._switch_to_session(s), w.destroy())
                ).pack(side="left", padx=2)
            ctk.CTkButton(btn_frame, text="KILL", width=50, height=24,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                fg_color=C["neon_red"], text_color=C["obsidian"],
                hover_color="#991b1b", corner_radius=3,
                command=lambda s=sid, w=win, sf2=sf: (self._kill_session(s), w.destroy(), self._show_sessions_panel())
            ).pack(side="left", padx=2)

    def _check_tools(self):
        for tool, cmd in TOOL_REGISTRY.items():
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=4)
                self.tool_status[tool] = (r.returncode == 0)
            except Exception:
                self.tool_status[tool] = False
        self.after(0, self._update_tool_panel)

    def _update_tool_panel(self):
        if not self.tool_status:
            return
        total = len(self.tool_status)
        found = sum(1 for v in self.tool_status.values() if v)
        if self.tool_progress_bar:
            self.tool_progress_bar.set(found / total)
            color = C["neon_green"] if found == total else C["neon_amber"] if found >= total * 0.6 else C["neon_red"]
            self.tool_progress_bar.configure(progress_color=color)
        if hasattr(self, "arsenal_status_lbl"):
            self.arsenal_status_lbl.configure(
                text=f"{found}/{total} ready",
                text_color=C["neon_green"] if found == total else C["neon_amber"])

    # ══════════════════════════════════════════
    # Engagement Management
    # ══════════════════════════════════════════

    def _save_engagements(self):
        self._eng_raw["active"] = self.active_engagement
        try:
            with open(self.engagements_file, "w") as f:
                json.dump(self._eng_raw, f, indent=2)
        except Exception:
            pass

    def _set_active_engagement(self, eid):
        self.active_engagement = eid
        self._eng_raw["active"] = eid
        self._save_engagements()
        eng = self._eng_raw.get("engagements", {}).get(eid, {})
        label = eng.get("id", eid)
        if hasattr(self, "engagement_label"):
            self.engagement_label.configure(
                text=f"⚑ {label[:22]}", text_color=C["neon_green"])

    def _show_engagement_dashboard(self):
        """Roadmap item 22: an engagement-centric home screen -- exposure
        counts, attack graph summary, and an operator-suggested next
        action -- built entirely from data that already exists
        (EngagementRepository, attack_graph_builder, ghost_score), the
        same derived-not-duplicated principle the attack graph itself
        already follows. Additive: opened from a button, doesn't replace
        the existing module-driven flow (see item 23 -- Operator Mode
        stays exactly as it is)."""
        if not self.active_engagement:
            messagebox.showinfo("Engagement Dashboard", "No active engagement. Create or open one first (+NEW / LIST).")
            return

        eid = self.active_engagement
        eng = self._eng_raw.get("engagements", {}).get(eid, {})

        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from engagement_repository import EngagementRepository
            sys.path.insert(0, os.path.join(SCRIPTS_DIR, "lib"))
            import attack_graph_builder as agb
            import ghost_score as gscore
        except Exception as exc:
            messagebox.showerror("Engagement Dashboard", f"Could not load engagement data layer:\n{exc}")
            return

        repo = EngagementRepository(eid)
        try:
            summary = repo.summary()
            assets = repo.get_assets()
            crown_jewels = repo.get_crown_jewels()
            findings = repo.get_findings()
        finally:
            repo.close()

        try:
            graph = agb.build_graph(eid)
        except Exception:
            graph = {"nodes": [], "edges": []}

        scored = []
        if findings:
            try:
                scored = gscore.score_engagement(eid, crown_jewels)
            except Exception:
                scored = []

        dlg = ctk.CTkToplevel(self)
        dlg.title(f"GhostStrike — Dashboard — {eid}")
        dlg.geometry("760x560")
        dlg.configure(fg_color=C["obsidian"])
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=54, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"⚑  {eid}   ·   {eng.get('client', 'no client set')}",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=C["neon_green"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(hdr, text=f"[{eng.get('environment', '?')}]",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["neon_amber"]).pack(side="left", pady=14)

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(1, weight=1)

        # ── Exposure panel ──────────────────────────────────────────
        exp = ctk.CTkFrame(body, fg_color=C["slate"], corner_radius=6, border_width=1, border_color=C["border"])
        exp.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 8))
        ctk.CTkLabel(exp, text="EXPOSURE", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color=C["neon_cyan"]).pack(anchor="w", padx=12, pady=(10, 4))
        by_sev = summary.get("findings_by_severity", {})
        stats = [
            (f"Assets {len(assets)}", C["text"]),
            (f"Crown Jewels {len(crown_jewels)}", C["neon_purple"] if crown_jewels else C["text_ghost"]),
            (f"Findings {summary.get('finding_count', 0)}", C["text"]),
        ]
        for sev, clr in [("CRITICAL", C["neon_red"]), ("HIGH", "#e74c3c"), ("MEDIUM", C["neon_amber"])]:
            if by_sev.get(sev):
                stats.append((f"{sev} {by_sev[sev]}", clr))
        for label, clr in stats:
            ctk.CTkLabel(exp, text=f"  {label}", font=ctk.CTkFont(family="Consolas", size=13),
                         text_color=clr).pack(anchor="w", padx=12, pady=1)
        ctk.CTkLabel(exp, text="", height=6).pack()

        # ── Attack Graph panel ──────────────────────────────────────
        ag = ctk.CTkFrame(body, fg_color=C["slate"], corner_radius=6, border_width=1, border_color=C["border"])
        ag.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 8))
        ctk.CTkLabel(ag, text="ATTACK GRAPH", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color=C["neon_cyan"]).pack(anchor="w", padx=12, pady=(10, 4))
        ctk.CTkLabel(ag, text=f"  {len(graph['nodes'])} nodes / {len(graph['edges'])} edges",
                     font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text"]).pack(anchor="w", padx=12, pady=1)

        def _open_graph():
            try:
                import webbrowser
                html_path = agb.save_html(eid, graph)
                webbrowser.open(html_path.as_uri())
            except Exception as exc:
                messagebox.showerror("Attack Graph", str(exc))

        ctk.CTkButton(ag, text="OPEN FULL GRAPH →", height=26, corner_radius=3,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["card"], hover_color=C["hover"], border_width=1,
            border_color=C["neon_cyan"], text_color=C["neon_cyan"],
            command=_open_graph).pack(anchor="w", padx=12, pady=(6, 10))

        # ── Operator suggestion panel ────────────────────────────────
        op = ctk.CTkFrame(body, fg_color=C["obsidian"], corner_radius=6, border_width=1, border_color=C["neon_purple"])
        op.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        ctk.CTkLabel(op, text="OPERATOR — SUGGESTED NEXT VALIDATION",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=C["neon_purple"]).pack(anchor="w", padx=12, pady=(10, 4))

        open_findings = [f for f in findings if f.get("status", "open") not in ("fixed", "accepted_risk")]
        if scored:
            top = max((s for s in scored if s["finding_id"] in
                       {f.get("finding_id", f.get("id")) for f in open_findings}),
                      key=lambda s: s["ghost_score"], default=None)
        else:
            top = None

        if top:
            ctk.CTkLabel(op, text=f"  {top['title']}",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=C["text"]).pack(anchor="w", padx=12)
            reasons = []
            if top["factors"].get("crown_jewel_reachable"):
                reasons.append("reaches a crown jewel")
            if top["factors"].get("confidence", 1.0) > 1.0:
                reasons.append("multi-source confirmed")
            if top["factors"].get("credential_exposure", 1.0) > 1.0:
                reasons.append("credential exposure")
            reason_text = ", ".join(reasons) if reasons else "highest GhostScore among open findings"
            ctk.CTkLabel(op, text=f"  GhostScore {top['ghost_score']} [{top['ghost_score_band']}] — {reason_text}",
                font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_dim"]).pack(anchor="w", padx=12, pady=(0, 10))
        elif open_findings:
            f = open_findings[0]
            ctk.CTkLabel(op, text=f"  {f.get('title', 'Untitled finding')}",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=C["text"]).pack(anchor="w", padx=12)
            ctk.CTkLabel(op, text=f"  [{f.get('severity', 'INFO')}] — mark crown jewels for GhostScore-ranked suggestions",
                font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_dim"]).pack(anchor="w", padx=12, pady=(0, 10))
        else:
            ctk.CTkLabel(op, text="  No open findings. Run modules or import scanner output to begin.",
                font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_ghost"]).pack(anchor="w", padx=12, pady=(0, 10))

        # ── Quick nav ────────────────────────────────────────────────
        nav = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=40, corner_radius=0)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)
        nf = ctk.CTkFrame(nav, fg_color="transparent")
        nf.pack(pady=6)
        for label, cmd in [("FINDINGS", self._show_findings), ("CLOSE", dlg.destroy)]:
            ctk.CTkButton(nf, text=label, width=100, height=26, corner_radius=3,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                fg_color=C["card"], hover_color=C["hover"], border_width=1,
                border_color=C["border"], text_color=C["text_dim"],
                command=cmd).pack(side="left", padx=4)

    def _delete_engagement(self, eid, dlg):
        """
        Removes an engagement's *registry entry* only (engagements.json).
        Deliberately does NOT touch findings/evidence/repro-sessions/attack
        graphs/reports for that engagement_id -- those are real pentest data,
        keyed by engagement_id in their own stores (findings/, evidence/,
        metrics/), independent of this registry entry, and this codebase's
        own dedup/evidence design never silently deletes real data (a merged
        finding gets superseded_by, never removed; see lib/finding_dedup.py).
        Deleting the registry entry just means the id no longer shows up as
        a selectable engagement -- its historical data is still on disk and
        still queryable directly via engagement_query.py if you know the id.
        """
        eng = self._eng_raw.get("engagements", {}).get(eid, {})
        label = eng.get("id", eid)
        if not messagebox.askyesno(
            "Delete Engagement",
            f"Delete engagement '{label}' from the registry?\n\n"
            "This removes it from the engagement list only. Its findings, "
            "evidence, reproducibility sessions, and reports are NOT deleted "
            "-- they stay on disk under this engagement_id.\n\n"
            "This cannot be undone from this dialog."
        ):
            return
        self._eng_raw.get("engagements", {}).pop(eid, None)
        if self.active_engagement == eid:
            self.active_engagement = None
            self._eng_raw["active"] = None
            if hasattr(self, "engagement_label"):
                self.engagement_label.configure(text="⚑ NO ENGAGEMENT", text_color=C["neon_amber"])
        self._save_engagements()
        dlg.destroy()
        self._switch_engagement_dialog()

    def _new_engagement_dialog(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — New Engagement")
        dlg.geometry("520x440")
        dlg.configure(fg_color=C["obsidian"])
        dlg.resizable(False, False)
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=46, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="⚑  NEW ENGAGEMENT",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_green"]).pack(pady=12)

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=12)

        ts = datetime.datetime.now().strftime("%Y%m%d")
        auto_id = f"GS-{ts}-001"
        fields = {}

        def _field(lbl, placeholder, default=""):
            f = ctk.CTkFrame(body, fg_color="transparent")
            f.pack(fill="x", pady=3)
            ctk.CTkLabel(f, text=lbl, width=120, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(side="left")
            e = ctk.CTkEntry(f, height=26, corner_radius=3,
                fg_color=C["void"], border_color=C["border"],
                placeholder_text=placeholder,
                font=ctk.CTkFont(family="Consolas", size=12))
            if default:
                e.insert(0, default)
            e.pack(side="left", fill="x", expand=True)
            return e

        fields["id"]       = _field("Engagement ID", "GS-YYYY-NNN", auto_id)
        fields["client"]   = _field("Client Name",   "ACME Corporation")
        fields["operator"] = _field("Operator",       os.environ.get("USERNAME", ""))
        fields["auth_ref"] = _field("Auth Reference", "SOW-2026-001")

        ef = ctk.CTkFrame(body, fg_color="transparent")
        ef.pack(fill="x", pady=3)
        ctk.CTkLabel(ef, text="Environment", width=120, anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"]).pack(side="left")
        env_var = ctk.StringVar(value="lab")
        env_cb = ctk.CTkComboBox(ef, values=["lab", "staging", "production"],
            variable=env_var, state="readonly", height=26, width=180,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["void"], border_color=C["border"],
            button_color=C["border"], dropdown_fg_color=C["slate"])
        env_cb.pack(side="left")

        sf = ctk.CTkFrame(body, fg_color="transparent")
        sf.pack(fill="x", pady=3)
        ctk.CTkLabel(sf, text="Scope File", width=120, anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"]).pack(side="left")
        scope_var = ctk.StringVar()
        scope_e = ctk.CTkEntry(sf, textvariable=scope_var, height=26,
            corner_radius=3, fg_color=C["void"], border_color=C["border"],
            placeholder_text="path/to/scope.yml",
            font=ctk.CTkFont(family="Consolas", size=12))
        scope_e.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(sf, text="BROWSE", width=60, height=26,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            command=lambda: scope_var.set(
                filedialog.askopenfilename(filetypes=[("YAML", "*.yml *.yaml"), ("All", "*.*")])
                or scope_var.get())).pack(side="left")

        def _create():
            eid = fields["id"].get().strip() or auto_id
            eng = {
                "id": eid,
                "client": fields["client"].get().strip(),
                "operator": fields["operator"].get().strip(),
                "environment": env_var.get(),
                "auth_ref": fields["auth_ref"].get().strip(),
                "scope_file": scope_var.get().strip(),
                "created": datetime.datetime.now().isoformat(),
                "status": "active",
                "modules_run": 0,
            }
            self._eng_raw.setdefault("engagements", {})[eid] = eng
            self._set_active_engagement(eid)
            dlg.destroy()
            self._notify("Engagement Created", eid, "success")

        bf = ctk.CTkFrame(body, fg_color="transparent")
        bf.pack(fill="x", pady=(10, 0))
        ctk.CTkButton(bf, text="▶  CREATE ENGAGEMENT",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=C["neon_green"], hover_color="#16a34a", text_color="#000",
            height=36, corner_radius=5, command=_create).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bf, text="CANCEL", height=36, width=80,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            corner_radius=5, command=dlg.destroy).pack(side="left")

    def _switch_engagement_dialog(self):
        engs = self._eng_raw.get("engagements", {})
        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — Engagements")
        dlg.geometry("560x400")
        dlg.configure(fg_color=C["obsidian"])
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=46, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f"⚑  ENGAGEMENTS  [{len(engs)} total]",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_green"]).pack(pady=12)

        sf = ctk.CTkScrollableFrame(dlg, fg_color="transparent")
        sf.pack(fill="both", expand=True, padx=12, pady=12)

        if not engs:
            ctk.CTkLabel(sf, text="No engagements yet. Click +NEW to create one.",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(pady=20)
        else:
            for eid, eng in sorted(engs.items(), key=lambda x: x[1].get("created",""), reverse=True):
                is_active = (eid == self.active_engagement)
                row = ctk.CTkFrame(sf,
                    fg_color=C["selected"] if is_active else C["card"],
                    corner_radius=4, height=46)
                row.pack(fill="x", pady=3)
                row.pack_propagate(False)
                ctk.CTkLabel(row, text=f"  ⚑ {eng.get('id', eid)}", anchor="w",
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    text_color=C["neon_green"] if is_active else C["text"]).pack(side="left")
                ctk.CTkLabel(row,
                    text=f"  {eng.get('client','?')}  |  {eng.get('environment','?')}  |  {eng.get('modules_run',0)} runs",
                    font=ctk.CTkFont(family="Consolas", size=12),
                    text_color=C["text_dim"]).pack(side="left")
                ctk.CTkButton(row, text="DELETE", width=60, height=24,
                    font=ctk.CTkFont(family="Consolas", size=11),
                    fg_color=C["card"], hover_color=C["neon_red"],
                    border_width=1, border_color=C["neon_red"],
                    text_color=C["neon_red"],
                    command=lambda e=eid, d=dlg: self._delete_engagement(e, d)
                ).pack(side="right", padx=8)
                if not is_active:
                    ctk.CTkButton(row, text="ACTIVATE", width=70, height=24,
                        font=ctk.CTkFont(family="Consolas", size=12),
                        fg_color=C["card"], hover_color=C["hover"],
                        border_width=1, border_color=C["neon_green"],
                        text_color=C["neon_green"],
                        command=lambda e=eid, d=dlg: (self._set_active_engagement(e), d.destroy())
                    ).pack(side="right", padx=8)
                else:
                    ctk.CTkLabel(row, text="ACTIVE",
                        font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                        text_color=C["neon_green"]).pack(side="right", padx=12)

        ctk.CTkButton(dlg, text="+  NEW ENGAGEMENT",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            border_width=1, border_color=C["neon_green"], text_color=C["neon_green"],
            height=32, corner_radius=5,
            command=lambda: (dlg.destroy(), self._new_engagement_dialog())).pack(pady=(0, 12))

    # ══════════════════════════════════════════
    # Report Generation
    # ══════════════════════════════════════════

    def _generate_report(self):
        eng = self._eng_raw.get("engagements", {}).get(self.active_engagement or "", {})
        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — Generate Report")
        dlg.geometry("580x500")
        dlg.configure(fg_color=C["obsidian"])
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))
        dlg.resizable(False, False)

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=46, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="⬛  GENERATE REPORT",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_amber"]).pack(pady=12)

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=12)

        # Template
        ctk.CTkLabel(body, text="Template", anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w")
        tmpl_var = ctk.StringVar(value="Technical Report")
        for t in ["Technical Report", "Executive Summary", "Developer Remediation"]:
            ctk.CTkRadioButton(body, text=t, variable=tmpl_var, value=t,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text"], fg_color=C["neon_amber"],
                hover_color=C["neon_amber"]).pack(anchor="w", pady=1)

        ctk.CTkLabel(body, text="", height=6).pack()

        def _field(lbl, default=""):
            f = ctk.CTkFrame(body, fg_color="transparent")
            f.pack(fill="x", pady=2)
            ctk.CTkLabel(f, text=lbl, width=130, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=C["text_dim"]).pack(side="left")
            e = ctk.CTkEntry(f, height=26, corner_radius=3,
                fg_color=C["void"], border_color=C["border"],
                font=ctk.CTkFont(family="Consolas", size=12))
            if default:
                e.insert(0, default)
            e.pack(side="left", fill="x", expand=True)
            return e

        fld_client  = _field("Client Name",    eng.get("client", ""))
        fld_eng_id  = _field("Engagement ID",  eng.get("id", self.active_engagement or ""))
        fld_date    = _field("Report Date",    datetime.datetime.now().strftime("%Y-%m-%d"))

        ctk.CTkLabel(body, text="Format", anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", pady=(8, 2))
        fmt_html = ctk.BooleanVar(value=True)
        fmt_md   = ctk.BooleanVar(value=True)
        fmt_json = ctk.BooleanVar(value=False)
        ff = ctk.CTkFrame(body, fg_color="transparent")
        ff.pack(anchor="w")
        for var, lbl in [(fmt_html, "HTML"), (fmt_md, "Markdown"), (fmt_json, "JSON/SARIF")]:
            ctk.CTkCheckBox(ff, text=lbl, variable=var,
                font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text"],
                fg_color=C["neon_amber"], hover_color=C["neon_amber"]).pack(side="left", padx=8)

        # Output dir
        of = ctk.CTkFrame(body, fg_color="transparent")
        of.pack(fill="x", pady=6)
        ctk.CTkLabel(of, text="Output Directory", width=130, anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"]).pack(side="left")
        outdir_var = ctk.StringVar(value=str(Path.home() / "GhostStrike-Reports"))
        ctk.CTkEntry(of, textvariable=outdir_var, height=26, corner_radius=3,
            fg_color=C["void"], border_color=C["border"],
            font=ctk.CTkFont(family="Consolas", size=12)).pack(side="left", fill="x", expand=True, padx=(0,4))
        ctk.CTkButton(of, text="BROWSE", width=60, height=26,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            command=lambda: outdir_var.set(
                filedialog.askdirectory() or outdir_var.get())).pack(side="left")

        status_lbl = ctk.CTkLabel(body, text="",
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"])
        status_lbl.pack(anchor="w", pady=4)

        def _do_generate():
            fmts = []
            if fmt_html.get(): fmts.append("html")
            if fmt_md.get():   fmts.append("md")
            if fmt_json.get(): fmts += ["json", "sarif"]
            if not fmts:
                messagebox.showwarning("Format", "Select at least one output format.")
                return
            out = outdir_var.get().strip()
            Path(out).mkdir(parents=True, exist_ok=True)
            eid = fld_eng_id.get().strip()
            if not eid:
                messagebox.showwarning("Engagement", "Report Studio generates a report for one "
                    "engagement's findings — set an Engagement ID (or select an active engagement).")
                return
            status_lbl.configure(text="⟳ Generating...", text_color=C["neon_amber"])
            dlg.update()
            # Report Studio (CyberToolkit/report_studio/) actually ingests this
            # engagement's real findings/evidence/repro data -- replaces the old
            # pentest_report_generator.sh, which was a static Markdown template
            # filler that never read real scan output at all.
            variant_map = {"Technical Report": "technical", "Executive Summary": "executive",
                           "Developer Remediation": "developer"}
            variant = variant_map.get(tmpl_var.get(), "technical")
            cmd = [sys.executable, "-m", "report_studio.cli",
                   "--engagement", eid, "--variant", variant,
                   "--format", ",".join(fmts), "--out", out]
            try:
                cyber_toolkit_dir = os.path.dirname(os.path.abspath(__file__))
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                    cwd=cyber_toolkit_dir)
                if r.returncode == 0:
                    status_lbl.configure(text=f"✓ Report saved to: {out}", text_color=C["neon_green"])
                    self._notify("Report Ready", f"Saved to {out}", "success")
                else:
                    status_lbl.configure(text="✗ Report failed — check terminal", text_color=C["neon_red"])
                    self._append_terminal(f"\n[Report Studio] {r.stderr or r.stdout}\n")
            except Exception as e:
                status_lbl.configure(text=f"Error: {e}", text_color=C["neon_red"])

        bf = ctk.CTkFrame(body, fg_color="transparent")
        bf.pack(fill="x", pady=(6, 0))
        ctk.CTkButton(bf, text="⬛  GENERATE",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=C["neon_amber"], hover_color="#d97706", text_color="#000",
            height=36, corner_radius=5, command=_do_generate).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bf, text="CLOSE", height=36, width=70,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            corner_radius=5, command=dlg.destroy).pack(side="left")

    # ══════════════════════════════════════════
    # Notifications
    # ══════════════════════════════════════════

    def _notify(self, title, message, level="info"):
        if not self.settings.get("notify_complete", True) and level == "success":
            return
        if not self.settings.get("notify_critical", True) and level == "critical":
            return
        colors = {"info": C["neon_cyan"], "success": C["neon_green"],
                  "warning": C["neon_amber"], "critical": C["neon_red"]}
        clr = colors.get(level, C["neon_cyan"])

        toast = ctk.CTkToplevel(self)
        toast.withdraw()
        toast.overrideredirect(True)
        toast.configure(fg_color=C["obsidian"])
        toast.attributes("-topmost", True)

        tf = ctk.CTkFrame(toast, fg_color=C["card"], corner_radius=6,
                           border_width=1, border_color=clr)
        tf.pack(padx=2, pady=2)
        ctk.CTkLabel(tf, text=title,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=clr).pack(padx=14, pady=(8, 2), anchor="w")
        ctk.CTkLabel(tf, text=message[:72],
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"], wraplength=300).pack(padx=14, pady=(0, 8), anchor="w")

        toast.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        tw = toast.winfo_reqwidth() + 4
        th = toast.winfo_reqheight() + 4
        toast.geometry(f"{tw}x{th}+{sw - tw - 24}+{sh - th - 60}")
        toast.deiconify()
        toast.after(4500, toast.destroy)

        # Send webhook if configured
        if self.settings.get("webhook_url"):
            threading.Thread(
                target=self._send_webhook,
                args=(level, {"title": title, "message": message}),
                daemon=True
            ).start()

    def _send_webhook(self, event_type, data):
        if not _requests:
            return
        url = self.settings.get("webhook_url", "")
        if not url:
            return
        try:
            payload = {
                "text": f"*GhostStrike [{event_type.upper()}]* — {data.get('title','')}: {data.get('message','')}",
                "attachments": [{"color": "danger" if event_type == "critical" else "good",
                                  "text": data.get("message", "")}]
            }
            _requests.post(url, json=payload, timeout=5)
        except Exception:
            pass

    def _show_settings(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — Settings")
        dlg.geometry("480x320")
        dlg.configure(fg_color=C["obsidian"])
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))
        dlg.resizable(False, False)

        hdr = ctk.CTkFrame(dlg, fg_color=C["abyss"], height=46, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="⚙  SETTINGS",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["text"]).pack(pady=12)

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=14)

        ctk.CTkLabel(body, text="Webhook URL (Slack / Teams / Discord)",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"]).pack(anchor="w")
        wh_entry = ctk.CTkEntry(body, height=28, corner_radius=3,
            fg_color=C["void"], border_color=C["border"],
            placeholder_text="https://hooks.slack.com/...",
            font=ctk.CTkFont(family="Consolas", size=12))
        wh_entry.pack(fill="x", pady=(2, 8))
        if self.settings.get("webhook_url"):
            wh_entry.insert(0, self.settings["webhook_url"])

        ctk.CTkLabel(body, text="Send notifications for:",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["text_dim"]).pack(anchor="w")
        nc_var = ctk.BooleanVar(value=self.settings.get("notify_complete", True))
        nf_var = ctk.BooleanVar(value=self.settings.get("notify_critical", True))
        ctk.CTkCheckBox(body, text="Module complete", variable=nc_var,
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text"],
            fg_color=C["neon_cyan"], hover_color=C["neon_cyan"]).pack(anchor="w", pady=2)
        ctk.CTkCheckBox(body, text="Critical/High findings detected", variable=nf_var,
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text"],
            fg_color=C["neon_red"], hover_color=C["neon_red"]).pack(anchor="w", pady=2)

        test_lbl = ctk.CTkLabel(body, text="",
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"])
        test_lbl.pack(anchor="w", pady=4)

        def _test_webhook():
            url = wh_entry.get().strip()
            if not url:
                test_lbl.configure(text="Enter a webhook URL first.", text_color=C["neon_red"])
                return
            test_lbl.configure(text="Sending test...", text_color=C["neon_amber"])
            dlg.update()
            threading.Thread(target=lambda: self._send_webhook(
                "info", {"title": "GhostStrike Test", "message": "Webhook connection test"}),
                daemon=True).start()
            test_lbl.configure(text="Test sent (check your channel)", text_color=C["neon_green"])

        def _save():
            self.settings["webhook_url"]      = wh_entry.get().strip()
            self.settings["notify_complete"]  = nc_var.get()
            self.settings["notify_critical"]  = nf_var.get()
            try:
                with open(self.settings_file, "w") as f:
                    json.dump(self.settings, f, indent=2)
            except Exception:
                pass
            dlg.destroy()

        bf = ctk.CTkFrame(body, fg_color="transparent")
        bf.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(bf, text="SAVE", height=32, width=80,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["neon_cyan"], hover_color="#0891b2", text_color="#000",
            corner_radius=5, command=_save).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bf, text="TEST WEBHOOK", height=32, width=120,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["card"], hover_color=C["hover"],
            border_width=1, border_color=C["border"],
            corner_radius=5, command=_test_webhook).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bf, text="CANCEL", height=32, width=70,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["card"], hover_color=C["hover"],
            corner_radius=5, command=dlg.destroy).pack(side="left")

    def _stop_script(self):
        if not self.current_process: return
        try:
            if os.name == "nt": self.current_process.send_signal(signal.CTRL_BREAK_EVENT)
            else: self.current_process.terminate()
            self._append_terminal("\n  [!] ENGAGEMENT ABORTED by operator.\n")
        except Exception: self.current_process.kill()
        self.current_process = None
        self._on_done()
        self.status_dot.configure(text_color=C["neon_red"])
        self.status_label.configure(text="ABORTED", text_color=C["neon_red"])

    # ══════════════════════════════════════════
    # Terminal & Utils
    # ══════════════════════════════════════════

    def _send_terminal_input(self, event=None):
        """Send user input to running process stdin, or execute as shell command."""
        text = self.term_input.get().strip()
        if not text:
            return
        self.term_input.delete(0, "end")

        # If a script is running, send input via PTY or stdin
        if self.current_process:
            try:
                if hasattr(self, '_pty_master') and self._pty_master is not None:
                    os.write(self._pty_master, (text + "\n").encode("utf-8"))
                elif self.current_process.stdin:
                    self.current_process.stdin.write((text + "\n").encode("utf-8"))
                    self.current_process.stdin.flush()
            except (BrokenPipeError, OSError):
                self._append_terminal(f"  [!] Process not accepting input\n")
        elif self.ai_mode:
            if self._ai_running:
                self._append_terminal("  [!] AI agent is still working — wait for it to finish.\n")
                return
            self._append_terminal(f"\n  \U0001f916 {text}\n")
            threading.Thread(target=self._run_ai_agent, args=(text,), daemon=True).start()
        else:
            # No script running — act as a real shell
            self._append_terminal(f"  $ {text}\n")
            threading.Thread(target=self._run_shell_cmd, args=(text,), daemon=True).start()

    def _run_shell_cmd(self, cmd):
        """Execute a shell command and display output in terminal. Every
        command is recorded to the engagement's run ledger and given its
        own timestamped output directory holding the full captured
        output/exit code/metadata -- the same evidence trail a
        GhostStrike module run gets, so a manually-typed `nmap ...` here
        is just as tracked as one run through a module. See roadmap item
        14 ("GhostStrike + terminal", not "GhostStrike OR terminal")."""
        started_at = datetime.datetime.now(datetime.timezone.utc)
        cwd = os.getcwd()
        output_chunks = []
        returncode = None
        try:
            shell_cmd = ["sudo", "bash", "-c", cmd] if os.name != "nt" else ["bash", "-c", cmd]
            proc = subprocess.Popen(shell_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE, text=False, bufsize=0)
            self.current_process = proc
            fd = proc.stdout.fileno()
            while True:
                try:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        break
                    output_chunks.append(chunk)
                    self._append_terminal(chunk.decode("utf-8", errors="replace"))
                except OSError:
                    break
            proc.wait()
            returncode = proc.returncode
            if returncode != 0:
                self._append_terminal(f"  [exit: {returncode}]\n")
        except Exception as e:
            self._append_terminal(f"  [!] {e}\n")
        finally:
            self.current_process = None

        try:
            self._record_terminal_run(cmd, b"".join(output_chunks), returncode, started_at, cwd)
        except Exception:
            pass  # Recording must never break the terminal itself.

    def _record_terminal_run(self, cmd, output_bytes, returncode, started_at, cwd):
        base = os.path.abspath(SCRIPTS_DIR)
        verb = (cmd.strip().split() or ["cmd"])[0]
        ts_dirname = f"terminal_{re.sub(r'[^a-zA-Z0-9_-]', '_', verb)}_{started_at.strftime('%Y%m%d_%H%M%S')}"
        output_dir = os.path.join(base, ts_dirname)
        os.makedirs(output_dir, exist_ok=True)

        output_text = output_bytes.decode("utf-8", errors="replace")
        output_log_path = os.path.join(output_dir, "output.log")
        with open(output_log_path, "w", encoding="utf-8") as f:
            f.write(output_text)

        target_match = re.search(
            r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", cmd)
        with open(os.path.join(output_dir, "command.json"), "w", encoding="utf-8") as f:
            json.dump({
                "command": cmd, "exit_code": returncode,
                "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "working_directory": cwd,
                "target": target_match.group(1) if target_match else "",
            }, f, indent=2)

        # Run ledger entry -- same shape lib/common.sh's
        # _gs_runs_ledger_append writes for module runs, so
        # `gs timeline` / EngagementRepository.get_runs() see a
        # terminal-typed command the same way they see a module run.
        runs_index = os.path.join(base, "runs", "index.jsonl")
        os.makedirs(os.path.dirname(runs_index), exist_ok=True)
        eng_env = self._eng_raw.get("engagements", {}).get(self.active_engagement or "", {}).get("environment", "")
        entry = {
            "timestamp": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "module": f"terminal:{verb}",
            "engagement_id": self.active_engagement or "",
            "environment": eng_env,
            "output_dir": ts_dirname,
            "operator": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        }
        with open(runs_index, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        self._suggest_import_if_recognized(verb, output_text, output_log_path)

    def _suggest_import_if_recognized(self, verb, output_text, output_path):
        """Detects compatible scanner output and suggests the exact
        `gs import` command to run -- an explicit suggestion, never a
        silent auto-write of findings the operator didn't ask for
        (matching the same no-silent-assumptions principle
        resolve_retest() and the fail-closed policy checks apply
        elsewhere in this codebase)."""
        stripped = output_text.strip()
        tool = None
        if verb == "nmap" and "<nmaprun" in stripped:
            tool = "nmap"
        elif verb == "nikto" and "<niktoscan" in stripped:
            tool = "nikto"
        elif "<issues" in stripped and "burpVersion" in stripped:
            tool = "burp"
        elif "<OWASPZAPReport" in stripped:
            tool = "zap"
        elif "<NessusClientData_v2" in stripped:
            tool = "nessus"
        elif verb == "nuclei" and stripped.startswith("{"):
            tool = "nuclei"
        elif verb == "masscan" and stripped.startswith("["):
            tool = "masscan"

        if tool:
            self._append_terminal(
                f"\n  [i] Output looks like {tool} format. Import it as findings with:\n"
                f"      gs import {tool} \"{output_path}\"\n"
            )

    # ══════════════════════════════════════════
    # AI Co-Pilot
    # ══════════════════════════════════════════

    def _toggle_ai_mode(self):
        if not _AI_ENGINE_AVAILABLE:
            return
        self.ai_mode = not self.ai_mode
        if self.ai_mode:
            self._ai_mode_btn.configure(text="🤖 AI CO-PILOT",
                border_color=C["neon_purple"], text_color=C["neon_purple"])
            self._ai_agent_cb.configure(state="readonly")
            self._ai_tier_cb.configure(state="readonly")
            self._ai_backend_cb.configure(state="readonly")
            try:
                self.term_input.configure(
                    placeholder_text="Describe the task for the AI agent... (Enter to send)")
            except Exception:
                pass
            self._append_terminal(
                f"\n  🤖 AI CO-PILOT ENABLED — agent: {self.ai_agent_name}, "
                f"backend: {self.ai_backend}\n"
                f"  Every module call the agent makes still passes through the same "
                f"policy/trust/scope gate as a manual run. Modules without confirmed "
                f"gs_policy_gate wiring are refused, not attempted.\n"
            )
            # Local (Ollama/LM Studio) needs no API key -- skip the
            # vault-unlock dialog for a credential it will never use.
            if self.ai_backend != "local":
                self._ensure_vault_key(prompt_if_missing=True)
        else:
            self._ai_mode_btn.configure(text="🤖 MANUAL",
                border_color=C["text_dim"], text_color=C["text_dim"])
            self._ai_agent_cb.configure(state="disabled")
            self._ai_tier_cb.configure(state="disabled")
            self._ai_backend_cb.configure(state="disabled")
            try:
                self.term_input.configure(placeholder_text="Type here... (Enter to send)")
            except Exception:
                pass
            self._append_terminal("\n  🤖 AI CO-PILOT DISABLED — back to manual mode.\n")

    def _ensure_vault_key(self, prompt_if_missing: bool = False) -> bool:
        """
        Make sure a vault master key is cached for this session so
        GhostStrikeModelProvider can resolve an API key from lib/vault.sh.
        Returns True if a key is cached (or the operator explicitly chose to
        rely on the ANTHROPIC_API_KEY/OPENAI_API_KEY env var fallback instead).
        """
        if self.vault_master_key is not None:
            return True
        if not prompt_if_missing:
            return False

        dlg = ctk.CTkToplevel(self)
        dlg.title("GhostStrike — Vault Unlock")
        dlg.geometry("440x220")
        dlg.configure(fg_color=C["obsidian"])
        dlg.resizable(False, False)
        dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

        ctk.CTkLabel(dlg, text="⚡  Vault Master Password",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=C["neon_purple"]).pack(pady=(16, 4))
        ctk.CTkLabel(dlg,
            text="Unlocks lib/vault.sh to fetch the LLM API key.\n"
                 "Leave blank to use ANTHROPIC_API_KEY / OPENAI_API_KEY instead.\n"
                 "Never written to disk — held in memory for this session only.",
            font=ctk.CTkFont(family="Consolas", size=13), text_color=C["text_dim"],
            justify="left").pack(pady=(0, 10), padx=16)

        pw_var = ctk.StringVar()
        entry = ctk.CTkEntry(dlg, textvariable=pw_var, show="*", width=380, height=30,
            fg_color=C["void"], border_color=C["border"],
            font=ctk.CTkFont(family="Consolas", size=13))
        entry.pack(padx=16)
        entry.focus_set()

        result = {"key": ""}

        def _submit(_e=None):
            result["key"] = pw_var.get()
            dlg.destroy()

        entry.bind("<Return>", _submit)
        bf = ctk.CTkFrame(dlg, fg_color="transparent")
        bf.pack(pady=16)
        ctk.CTkButton(bf, text="UNLOCK", width=110, height=30,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=C["neon_purple"], hover_color=C["neon_violet"],
            command=_submit).pack(side="left", padx=(0, 8))
        ctk.CTkButton(bf, text="USE ENV VAR", width=110, height=30,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["card"], hover_color=C["hover"],
            command=lambda: (pw_var.set(""), _submit())).pack(side="left")

        dlg.wait_window()
        self.vault_master_key = result["key"] or ""  # "" means "use env var fallback"
        return True

    def _request_module_approval(self, request: dict) -> bool:
        """
        approval_callback passed down to GhostStrikeRunner (via each agent's
        autonomy_tier/approval_callback). Called from the AI agent's
        background thread (see _run_ai_agent), but Tkinter widgets can only
        be created/touched on the main thread -- so the dialog itself is
        scheduled via self.after(0, ...) exactly like _append_terminal does,
        and this method blocks the calling (background) thread on a
        threading.Event until the operator answers.
        """
        import threading as _threading
        done = _threading.Event()
        result = {"approved": False}

        def _build_dialog():
            dlg = ctk.CTkToplevel(self)
            dlg.title("GhostStrike — AI Module Approval")
            dlg.geometry("480x300")
            dlg.configure(fg_color=C["obsidian"])
            dlg.resizable(False, False)
            dlg.after(100, lambda w=dlg: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))

            ctk.CTkLabel(dlg, text="⚡  AI wants to run a module",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=C["neon_purple"]).pack(pady=(16, 4))

            body = (
                f"Module:   {request.get('module_name', '?')}\n"
                f"Trust:    {request.get('trust', '?')}\n"
                f"Params:   {request.get('params', {})}\n"
            )
            if request.get("reason"):
                body += f"\nWhy approval is required:\n{request['reason']}"
            ctk.CTkLabel(dlg, text=body,
                font=ctk.CTkFont(family="Consolas", size=12), text_color=C["text_dim"],
                justify="left", wraplength=440).pack(pady=(0, 12), padx=16, anchor="w")

            def _answer(approved: bool, remember: bool = False):
                result["approved"] = approved
                if approved and remember:
                    mod = request.get("module_name", "")
                    current = os.environ.get("GS_APPROVED_MODULES", "")
                    modules = set(m for m in current.split(",") if m)
                    modules.add(mod)
                    os.environ["GS_APPROVED_MODULES"] = ",".join(sorted(modules))
                dlg.destroy()
                done.set()

            bf = ctk.CTkFrame(dlg, fg_color="transparent")
            bf.pack(pady=16)
            ctk.CTkButton(bf, text="APPROVE", width=100, height=30,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                fg_color=C["neon_green"], hover_color=C["neon_purple"],
                command=lambda: _answer(True, False)).pack(side="left", padx=(0, 6))
            ctk.CTkButton(bf, text="APPROVE SESSION", width=140, height=30,
                font=ctk.CTkFont(family="Consolas", size=11),
                fg_color=C["card"], hover_color=C["hover"],
                command=lambda: _answer(True, True)).pack(side="left", padx=(0, 6))
            ctk.CTkButton(bf, text="DENY", width=100, height=30,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                fg_color=C["neon_red"], hover_color=C["slate"],
                command=lambda: _answer(False, False)).pack(side="left")

            dlg.protocol("WM_DELETE_WINDOW", lambda: _answer(False, False))

        self.after(0, _build_dialog)
        done.wait()
        return result["approved"]

    def _run_ai_agent(self, prompt: str):
        if not _AI_ENGINE_AVAILABLE:
            self._append_terminal("  [!] ai_engine is not available.\n")
            return

        self._ai_running = True
        self.status_dot.configure(text_color=C["neon_purple"])
        self.status_label.configure(text="AI THINKING...", text_color=C["neon_purple"])

        # Export engagement context onto THIS process's environment so that
        # GhostStrikeRunner's fallback command builder -- which is what every
        # agent actually gets, since each agent constructs its own runner
        # internally with no hook to inject the GUI's _build_shell_command --
        # can re-export it across the WSL boundary. This is what makes an
        # AI-initiated module call carry the same authorization context
        # (GS_ENGAGEMENT_ID / GS_ENVIRONMENT / GS_SCOPE_FILE) as a manual run.
        if self.active_engagement:
            eng = self._eng_raw.get("engagements", {}).get(self.active_engagement, {})
            os.environ["GS_ENGAGEMENT_ID"] = eng.get("id", self.active_engagement)
            os.environ["GS_ENVIRONMENT"] = eng.get("environment", "lab")
            scope_file = (eng.get("scope_file") or "").strip()
            if scope_file:
                os.environ["GS_SCOPE_FILE"] = scope_file
            else:
                os.environ.pop("GS_SCOPE_FILE", None)
        else:
            os.environ.pop("GS_ENGAGEMENT_ID", None)
            os.environ["GS_ENVIRONMENT"] = "lab"
            os.environ.pop("GS_SCOPE_FILE", None)

        try:
            agent_cls = AGENT_REGISTRY.get(self.ai_agent_name)
            if not agent_cls:
                self._append_terminal(f"  [!] Unknown agent '{self.ai_agent_name}'.\n")
                return

            try:
                backend = ModelBackend(self.ai_backend)
            except ValueError:
                backend = ModelBackend.CLAUDE

            try:
                provider = GhostStrikeModelProvider(
                    backend=backend, vault_master_key=self.vault_master_key or None,
                )
            except RuntimeError as exc:
                self._append_terminal(
                    f"  [!] Could not start AI agent: {exc}\n"
                    f"  Set up a key via the vault (lib/vault.sh gs_vault_store) or the "
                    f"ANTHROPIC_API_KEY / OPENAI_API_KEY environment variable.\n"
                )
                return

            agent = agent_cls(
                model_provider=provider,
                output_callback=self._append_terminal,
                max_iterations=30,
                engagement_id=self.active_engagement or "",
                autonomy_tier=self.ai_autonomy_tier,
                approval_callback=self._request_module_approval,
            )

            self._append_terminal(f"  [key source: {provider.key_source}]\n")
            result = agent.run(prompt)

            self._append_terminal(
                f"\n  {'=' * 56}\n"
                f"  AGENT RESULT — {result.agent_name}\n"
                f"  Iterations: {result.iterations}   Success: {result.success}\n"
                f"  {'=' * 56}\n"
            )
            if result.error:
                self._append_terminal(f"  Error: {result.error}\n")
            self._append_evidence_summary()

        except Exception as exc:
            self._append_terminal(f"  [!] AI agent crashed: {exc}\n")
        finally:
            self._ai_running = False
            self.status_dot.configure(text_color=C["neon_green"])
            self.status_label.configure(text="STANDBY", text_color=C["neon_green"])

    def _append_terminal(self, text):
        text = re.sub(r'\x1b\[[0-9;]*[mKHFABCDJsu]|\x1b\[[0-9;]*m|\x0f|\x1b\(B', '', text)
        def _u():
            self.terminal.configure(state="normal")
            self.terminal.insert("end", text)
            self.terminal.see("end")
            self.terminal.configure(state="disabled")
        self.after(0, _u)
        # Scan for critical findings during live execution
        if self.current_process and re.search(
                r'\b(CRITICAL|VULNERABLE|EXPLOIT|PWNED|ROOTED)\b', text, re.I):
            trust = get_trust_level(self.selected_script)
            if trust in ("HIGH_IMPACT", "LAB_ONLY"):
                self.after(100, lambda t=text: self._notify(
                    "⚠ Finding Detected", t.strip()[:80], "critical"))

    def _clear_terminal(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")
        self.term_timer.configure(text="")

    def _export_log(self):
        c = self.terminal.get("1.0", "end").strip()
        if not c: return
        fp = filedialog.asksaveasfilename(defaultextension=".log",
            filetypes=[("Log", "*.log"), ("Text", "*.txt"), ("All", "*.*")])
        if fp:
            with open(fp, "w", encoding="utf-8") as f: f.write(c)
            messagebox.showinfo("Exported", f"Evidence saved:\n{fp}")

    def _toggle_favorite(self):
        if not self.selected_script: return
        fn = self.selected_script["filename"]
        if fn in self.favorites:
            self.favorites.discard(fn)
            self.fav_btn.configure(text="\u2606 FAV", fg_color=C["card"])
        else:
            self.favorites.add(fn)
            self.fav_btn.configure(text="\u2605 UNFAV", fg_color=C["neon_amber"])
        try:
            with open(self.favorites_file, "w") as f: json.dump(list(self.favorites), f)
        except Exception: pass

    def _view_source(self):
        if not self.selected_script: return
        try:
            with open(self.selected_script["path"], "r", encoding="utf-8", errors="ignore") as f: content = f.read()
        except Exception as e: messagebox.showerror("Error", str(e)); return
        win = ctk.CTkToplevel(self)
        win.title(f"// SOURCE: {self.selected_script['filename']}")
        win.geometry("1050x720")
        win.after(100, lambda w=win: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))
        tb = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["terminal"], text_color=C["term_text"], wrap="none")
        tb.pack(fill="both", expand=True, padx=8, pady=8)
        tb.insert("1.0", content); tb.configure(state="disabled")

    def _show_docs(self):
        if not self.selected_script: return
        s = self.selected_script
        win = ctk.CTkToplevel(self)
        win.title(f"// DOCS: {s['name']}")
        win.geometry("850x680")
        win.after(100, lambda w=win: (w.update_idletasks(), w.lift(), w.focus_force(), w.grab_set()))
        tb = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=C["terminal"], text_color=C["text"], wrap="word")
        tb.pack(fill="both", expand=True, padx=8, pady=8)

        ql = {GOOD:"ARMED",PARTIAL:"PARTIAL",NEEDS_WORK:"STUB"}.get(s.get("quality"), "?")
        trust = get_trust_level(s)
        td = TRUST_DISPLAY.get(trust, trust)
        doc = [f"{'='*60}", f"  {s['name']}", f"  {s['filename']}", f"{'='*60}", "",
               f"  STATUS:      {ql}", f"  CATEGORY:    {s.get('category','?')}",
               f"  TRUST LEVEL: {td}", "",
               "  DESCRIPTION:", f"    {s.get('description','N/A')}", "", "  PARAMETERS:"]
        for p in s.get("params", []) or [{"name": "None", "type": "-", "help": "No parameters"}]:
            r = "[REQ]" if p.get("required") else "[OPT]"
            doc.append(f"    {r} {p.get('name','')}  ({p.get('type','text')})")
            if p.get("help"): doc.append(f"        {p['help']}")
            if p.get("options"): doc.append(f"        Options: {', '.join(p['options'])}")
        eh = s.get("extra_args_help", "")
        if eh: doc.append(f"\n    Extra: {eh}")
        doc.extend(["", "  DEPENDENCIES:"])
        doc.extend([f"    - {d}" for d in s.get("dependencies", [])] or ["    None"])
        doc.extend(["", "  EXPECTED OUTPUT:"])
        doc.extend([f"    {l}" for l in s.get("expected_output", "").split("\n")])
        doc.extend(["", f"{'='*60}"])
        tb.insert("1.0", "\n".join(doc)); tb.configure(state="disabled")

    def _on_search(self, *args):
        self._populate_categories(self.search_var.get())


# ═══════════════════════════════════════════════════════════════
# Launch
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = GhostStrikeApp()
    app.mainloop()
