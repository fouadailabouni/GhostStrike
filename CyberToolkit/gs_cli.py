#!/usr/bin/env python3
"""
GhostStrike CLI (CyberToolkit/gs_cli.py) -- `gs`

Items 11-13 of the roadmap: a first-class Linux CLI alongside the GUI,
with a `gs run` module command, and pipeable JSON output
(`gs findings --json | jq`, `cat scan.xml | gs import nmap -`).

Everything here is glue over already-real, already-tested modules --
EngagementRepository, finding_dedup.py, attack_graph_builder.py,
ghost_score.py, report_studio, import_engine.py -- not a second
implementation of any of them. The one new piece of logic is `gs run`,
which invokes a module through repro_runner.sh via the same centralized
shell_command_builder every other module invocation in this codebase
uses, so a CLI-initiated run is evidence-tracked exactly like a GUI or
AI-agent-initiated one.

Engagement state (the active engagement, and the registry of known
engagements) is read from and written to CyberToolkit/engagements.json --
the same file the GUI uses -- so `gs open acme` in a terminal and the GUI's
engagement switcher agree on what's active.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

_CYBERTOOLKIT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _CYBERTOOLKIT_DIR.parent
_SCRIPTS_DIR = _REPO_ROOT / "bash_scripts_for_pentest"
_LIB_DIR = _SCRIPTS_DIR / "lib"

for p in (str(_CYBERTOOLKIT_DIR), str(_LIB_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from engagement_repository import EngagementRepository, EngagementRepositoryError  # noqa: E402
from shell_command_builder import find_bash_invocation  # noqa: E402
import engagement_query as eq  # noqa: E402
import finding_dedup  # noqa: E402
import attack_graph_builder as agb  # noqa: E402
import ghost_score as gscore  # noqa: E402

_ENGAGEMENTS_FILE = _CYBERTOOLKIT_DIR / "engagements.json"
_REGISTRY_FILE = _SCRIPTS_DIR / "registry.json"


def _err(msg: str) -> None:
    print(f"gs: {msg}", file=sys.stderr)


def _load_engagements() -> dict:
    try:
        with open(_ENGAGEMENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"active": None, "engagements": {}}


def _save_engagements(data: dict) -> None:
    with open(_ENGAGEMENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _active_engagement_id(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    data = _load_engagements()
    active = data.get("active")
    if not active:
        _err("no active engagement -- run `gs open <id>` first, or pass -e/--engagement")
        sys.exit(1)
    return active


def _print(data: Any, as_json: bool) -> None:
    if as_json:
        json.dump(data, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return
    if isinstance(data, list):
        for item in data:
            print(item if isinstance(item, str) else json.dumps(item, default=str))
    else:
        print(data if isinstance(data, str) else json.dumps(data, indent=2, default=str))


def _repo(args) -> EngagementRepository:
    return EngagementRepository(_active_engagement_id(getattr(args, "engagement", None)),
                                 backend=getattr(args, "backend", "json"))


# ── Engagement lifecycle ────────────────────────────────────────────────

def cmd_new(args) -> int:
    data = _load_engagements()
    eid = args.id
    if eid in data.setdefault("engagements", {}):
        _err(f"engagement '{eid}' already exists -- use `gs open {eid}` to switch to it")
        return 1
    data["engagements"][eid] = {
        "id": eid, "client": args.client or "", "operator": args.operator or os.environ.get("USER", ""),
        "environment": args.environment, "auth_ref": args.auth_ref or "", "scope_file": args.scope_file or "",
        "created": datetime.datetime.now().isoformat(), "status": "active", "modules_run": 0,
    }
    data["active"] = eid
    _save_engagements(data)
    print(f"Engagement '{eid}' created and active.")
    return 0


def cmd_open(args) -> int:
    data = _load_engagements()
    if args.id not in data.get("engagements", {}):
        _err(f"no such engagement '{args.id}' -- run `gs list` to see known engagements")
        return 1
    data["active"] = args.id
    _save_engagements(data)
    print(f"Active engagement: {args.id}")
    return 0


def cmd_list(args) -> int:
    data = _load_engagements()
    engs = data.get("engagements", {})
    active = data.get("active")
    if args.json:
        _print({"active": active, "engagements": engs}, True)
        return 0
    if not engs:
        print("No engagements yet. Run `gs new <id>` to create one.")
        return 0
    for eid, e in engs.items():
        marker = "*" if eid == active else " "
        print(f"{marker} {eid}  [{e.get('environment', '?')}]  {e.get('client', '')}")
    return 0


def cmd_scope_add(args) -> int:
    data = _load_engagements()
    eid = _active_engagement_id(args.engagement)
    eng = data.get("engagements", {}).get(eid)
    if eng is None:
        _err(f"engagement '{eid}' not found in registry")
        return 1
    scope_file = eng.get("scope_file") or str(_scope_file_default(eid))
    eng["scope_file"] = scope_file
    scope_path = Path(scope_file)
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if scope_path.exists():
        existing = {line.strip() for line in scope_path.read_text(encoding="utf-8").splitlines() if line.strip()}
    existing.add(args.target)
    scope_path.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
    _save_engagements(data)
    print(f"Added '{args.target}' to scope ({scope_path}).")
    return 0


def _scope_file_default(eid: str) -> Path:
    return _REPO_ROOT / "config" / f"scope_{eid}.txt"


# ── Read-only views (pipeable) ──────────────────────────────────────────

def cmd_assets(args) -> int:
    repo = _repo(args)
    try:
        _print(repo.get_assets(), args.json)
    finally:
        repo.close()
    return 0


def cmd_findings(args) -> int:
    repo = _repo(args)
    try:
        findings = repo.get_findings(severity=args.severity)
        if args.status:
            findings = [f for f in findings if f.get("status", "open") == args.status]
        if args.json:
            _print(findings, True)
        else:
            for f in findings:
                print(f"{f.get('finding_id', f.get('id', '?'))}  [{f.get('severity', '?'):8}] "
                      f"{f.get('status', 'open'):20} {f.get('title', '')}")
    finally:
        repo.close()
    return 0


def cmd_evidence(args) -> int:
    repo = _repo(args)
    try:
        _print(repo.get_evidence(), args.json)
    finally:
        repo.close()
    return 0


def cmd_timeline(args) -> int:
    repo = _repo(args)
    try:
        events = repo.get_timeline()
        if args.json:
            _print(events, True)
        else:
            for e in events:
                print(f"{e['timestamp']}  [{e['type']:20}] {e['summary']}")
    finally:
        repo.close()
    return 0


def cmd_summary(args) -> int:
    repo = _repo(args)
    try:
        _print(repo.summary(), args.json)
    finally:
        repo.close()
    return 0


# ── Dedup ────────────────────────────────────────────────────────────────

def cmd_dedup_scan(args) -> int:
    eid = _active_engagement_id(args.engagement)
    groups = finding_dedup.find_duplicate_groups(finding_dedup.findings_dir_path(), eid)
    _print(groups, args.json)
    return 0


def cmd_dedup_apply(args) -> int:
    eid = _active_engagement_id(args.engagement)
    result = finding_dedup.apply_merge(finding_dedup.findings_dir_path(), args.members, eid, args.confidence)
    _print(result, args.json)
    return 0 if "error" not in result else 1


# ── Crown Jewels / GhostScore ───────────────────────────────────────────

def cmd_crown_jewel(args) -> int:
    repo = _repo(args)
    try:
        repo.mark_crown_jewel(args.host, is_crown_jewel=not args.unmark)
        verb = "Unmarked" if args.unmark else "Marked"
        print(f"{verb} '{args.host}' as a crown jewel.")
    finally:
        repo.close()
    return 0


def cmd_ghostscore(args) -> int:
    eid = _active_engagement_id(args.engagement)
    repo = _repo(args)
    try:
        crown_jewels = repo.get_crown_jewels()
    finally:
        repo.close()
    results = gscore.score_engagement(eid, crown_jewels)
    if args.json:
        _print(results, True)
    else:
        for r in results:
            print(f"{r['ghost_score']:6.1f} {r['ghost_score_band']:8} {r['finding_id']}  {r['title']}")
    return 0


# ── Attack Graph ─────────────────────────────────────────────────────────

def cmd_graph(args) -> int:
    eid = _active_engagement_id(args.engagement)
    graph = agb.build_graph(eid)
    agb.save_graph(eid, graph)
    if args.open or args.render:
        html_path = agb.save_html(eid, graph)
        print(str(html_path))
        if args.open:
            import webbrowser
            webbrowser.open(html_path.as_uri())
    elif args.json:
        _print(graph, True)
    else:
        print(f"{len(graph['nodes'])} nodes, {len(graph['edges'])} edges. "
              f"Use --render for an HTML file or --open to view it now.")
    return 0


# ── Retest ───────────────────────────────────────────────────────────────

def cmd_retest_start(args) -> int:
    repo = _repo(args)
    try:
        info = repo.start_retest(args.finding_id)
        _print(info, args.json)
    except EngagementRepositoryError as exc:
        _err(str(exc))
        return 1
    finally:
        repo.close()
    return 0


def cmd_retest_resolve(args) -> int:
    repo = _repo(args)
    try:
        repo.resolve_retest(args.finding_id, args.outcome, notes=args.notes or "")
        print(f"{args.finding_id} -> {args.outcome}")
    except EngagementRepositoryError as exc:
        _err(str(exc))
        return 1
    finally:
        repo.close()
    return 0


# ── Modules (reads the canonical registry.json -- item 6) ──────────────

def _load_registry() -> list:
    try:
        with open(_REGISTRY_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("modules", [])
    except (OSError, json.JSONDecodeError):
        return []


def cmd_modules(args) -> int:
    modules = _load_registry()
    if args.category:
        modules = [m for m in modules if m.get("category") == args.category]
    if args.json:
        _print(modules, True)
    else:
        for m in modules:
            print(f"{m['id']:55} [{m.get('status', '?'):12}] [{m.get('trust', '?')}]")
    return 0


def cmd_module_info(args) -> int:
    modules = _load_registry()
    match = next((m for m in modules if m["id"] == args.module_id), None)
    if match is None:
        _err(f"module '{args.module_id}' not found in registry.json")
        return 1
    _print(match, True)
    return 0


def cmd_module_init(args) -> int:
    """Wires up tools/gs_module_init.py's own stated intent ('the CLI
    subcommand should just import and call create_module() below rather
    than reimplementing this') -- not a second scaffolding implementation."""
    tools_dir = _REPO_ROOT / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    import gs_module_init

    mitre = [t.strip() for t in args.mitre.split(",") if t.strip()] if args.mitre else None
    try:
        path = gs_module_init.create_module(
            args.module_id, name=args.name, trust=args.trust, status=args.status, mitre=mitre,
            network=args.network, root=args.root, credentials=args.credentials,
            filesystem=args.filesystem, force=args.force,
        )
    except ValueError as exc:
        _err(str(exc))
        return 1
    print(f"Created {path}")
    return 0


def cmd_module_validate(args) -> int:
    """Same wiring principle as cmd_module_init: import and call
    tools/gs_module_validate.py's validate_module(), don't reimplement it."""
    tools_dir = _REPO_ROOT / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    import gs_module_validate

    findings = gs_module_validate.validate_module(Path(args.script))
    errors = [f for f in findings if f.level == "ERROR"]
    if args.json:
        _print([{"level": f.level, "message": f.message} for f in findings], True)
    else:
        for f in findings:
            print(str(f))
        if not findings:
            print(f"{args.script}: no issues found")
    return 1 if errors else 0


# ── Run a module (item 12), evidence-tracked via repro_runner.sh ───────

def cmd_run(args) -> int:
    modules = _load_registry()
    match = next((m for m in modules if m["id"] == args.module), None)
    module_path = _SCRIPTS_DIR / (match["script_path"] if match else args.module)
    if not module_path.exists():
        _err(f"module script not found: {module_path}")
        return 1

    eid = _active_engagement_id(args.engagement)
    repro_runner = _SCRIPTS_DIR / "repro_runner.sh"
    module_args = [args.target] if args.target else []

    cmd = find_bash_invocation(
        str(repro_runner),
        args=[str(module_path)] + module_args,
        env_vars={"GS_ENGAGEMENT_ID": eid, "GS_ENVIRONMENT": args.environment or ""},
        wsl_path_env_keys=set(),
        path_arg_indices={0},
    )
    result = subprocess.run(cmd)
    return result.returncode


# ── Import engine (item 15) ─────────────────────────────────────────────

def cmd_import(args) -> int:
    import import_engine

    _active_engagement_id(args.engagement)  # validates an engagement is active/specified
    raw = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")

    parser_fn = import_engine.PARSERS.get(args.tool)
    if parser_fn is None:
        _err(f"unsupported import tool: {args.tool}")
        return 2
    parsed = parser_fn(raw)

    repo = _repo(args)
    try:
        summary = import_engine.import_findings(repo, parsed)
    finally:
        repo.close()
    _print(summary, args.json)
    return 0


# ── Report (delegates to report_studio) ─────────────────────────────────

def cmd_report(args) -> int:
    from report_studio.cli import main as report_main
    eid = _active_engagement_id(args.engagement)
    argv = ["--engagement", eid, "--variant", args.variant, "--format", args.format, "--out", args.out]
    return report_main(argv)


def cmd_report_template_fill(args) -> int:
    from report_studio.data_sources import load_report_data
    from report_studio.templates import fill_template

    eid = _active_engagement_id(args.engagement)
    data = load_report_data(eid)
    repo = _repo(args)
    try:
        crown_jewels = repo.get_crown_jewels()
    finally:
        repo.close()

    out_path = Path(args.out) if args.out else Path(args.template).with_name(
        f"{eid}_{Path(args.template).stem}_filled.docx")
    try:
        result = fill_template(Path(args.template), data, out_path, crown_jewel_hosts=crown_jewels)
    except Exception as exc:
        _err(f"template fill failed: {exc}")
        return 1
    print(str(result))
    return 0


def cmd_report_template_placeholders(args) -> int:
    from report_studio.templates import known_placeholders
    for name in known_placeholders():
        print("{{" + name + "}}")
    return 0


# ── argparse wiring ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gs", description="GhostStrike CLI")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("-e", "--engagement", default=None, help="Engagement id (default: active engagement)")
        sp.add_argument("--backend", default="json", choices=["json", "sqlite"])

    sp = sub.add_parser("new", help="Create a new engagement")
    sp.add_argument("id")
    sp.add_argument("--client", default="")
    sp.add_argument("--operator", default="")
    sp.add_argument("--environment", default="lab", choices=["lab", "staging", "production"])
    sp.add_argument("--auth-ref", default="")
    sp.add_argument("--scope-file", default="")
    sp.set_defaults(func=cmd_new)

    sp = sub.add_parser("open", help="Set the active engagement")
    sp.add_argument("id")
    sp.set_defaults(func=cmd_open)

    sp = sub.add_parser("list", help="List known engagements")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("scope", help="Scope management")
    scope_sub = sp.add_subparsers(dest="scope_command", required=True)
    sp2 = scope_sub.add_parser("add", help="Add a target to the active engagement's scope")
    sp2.add_argument("target")
    add_common(sp2)
    sp2.set_defaults(func=cmd_scope_add)

    sp = sub.add_parser("assets", help="List assets")
    add_common(sp); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_assets)

    sp = sub.add_parser("findings", help="List findings")
    add_common(sp)
    sp.add_argument("--severity", default=None, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    sp.add_argument("--status", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_findings)

    sp = sub.add_parser("evidence", help="List evidence artifacts")
    add_common(sp); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_evidence)

    sp = sub.add_parser("timeline", help="Chronological engagement timeline")
    add_common(sp); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_timeline)

    sp = sub.add_parser("summary", help="Engagement summary counts")
    add_common(sp); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_summary)

    sp = sub.add_parser("graph", help="Build/render the attack graph")
    add_common(sp)
    sp.add_argument("--render", action="store_true", help="Write an HTML file")
    sp.add_argument("--open", action="store_true", help="Write and open the HTML file")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_graph)

    sp = sub.add_parser("crown-jewel", help="Mark/unmark an asset as a crown jewel")
    add_common(sp)
    sp.add_argument("host")
    sp.add_argument("--unmark", action="store_true")
    sp.set_defaults(func=cmd_crown_jewel)

    sp = sub.add_parser("ghostscore", help="Business-risk-adjusted score per finding")
    add_common(sp); sp.add_argument("--json", action="store_true"); sp.set_defaults(func=cmd_ghostscore)

    sp = sub.add_parser("dedup", help="Deduplication engine")
    dedup_sub = sp.add_subparsers(dest="dedup_command", required=True)
    sp2 = dedup_sub.add_parser("scan"); add_common(sp2); sp2.add_argument("--json", action="store_true"); sp2.set_defaults(func=cmd_dedup_scan)
    sp2 = dedup_sub.add_parser("apply"); add_common(sp2); sp2.add_argument("members", nargs="+")
    sp2.add_argument("--confidence", default="MEDIUM", choices=["HIGH", "MEDIUM", "LOW"])
    sp2.add_argument("--json", action="store_true"); sp2.set_defaults(func=cmd_dedup_apply)

    sp = sub.add_parser("retest", help="Retest workflow")
    retest_sub = sp.add_subparsers(dest="retest_command", required=True)
    sp2 = retest_sub.add_parser("start"); add_common(sp2); sp2.add_argument("finding_id")
    sp2.add_argument("--json", action="store_true"); sp2.set_defaults(func=cmd_retest_start)
    sp2 = retest_sub.add_parser("resolve"); add_common(sp2); sp2.add_argument("finding_id")
    sp2.add_argument("outcome", choices=["fixed", "still_vulnerable"])
    sp2.add_argument("--notes", default=""); sp2.set_defaults(func=cmd_retest_resolve)

    sp = sub.add_parser("modules", help="List modules from the canonical registry")
    sp.add_argument("--category", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_modules)

    sp = sub.add_parser("module", help="Module info")
    mod_sub = sp.add_subparsers(dest="module_command", required=True)
    sp2 = mod_sub.add_parser("info"); sp2.add_argument("module_id"); sp2.set_defaults(func=cmd_module_info)

    sp2 = mod_sub.add_parser("init", help="Scaffold a new module (tools/gs_module_init.py)")
    sp2.add_argument("module_id", help="<category-slug>/<module-slug>, e.g. web/example-scanner")
    sp2.add_argument("--name", required=True)
    sp2.add_argument("--trust", required=True, choices=["SAFE_ENUM", "VALIDATION", "HIGH_IMPACT", "LAB_ONLY"])
    sp2.add_argument("--status", default="EXPERIMENTAL",
                      choices=["PRODUCTION", "BETA", "EXPERIMENTAL", "LAB_ONLY", "DEPRECATED"])
    sp2.add_argument("--mitre", default="")
    sp2.add_argument("--network", action="store_true")
    sp2.add_argument("--root", action="store_true")
    sp2.add_argument("--credentials", action="store_true")
    sp2.add_argument("--filesystem", default="none", choices=["none", "limited", "full"])
    sp2.add_argument("--force", action="store_true")
    sp2.set_defaults(func=cmd_module_init)

    sp2 = mod_sub.add_parser("validate", help="Validate a module (tools/gs_module_validate.py)")
    sp2.add_argument("script", help="Path to the module .sh file")
    sp2.add_argument("--json", action="store_true")
    sp2.set_defaults(func=cmd_module_validate)

    sp = sub.add_parser("run", help="Run a module, evidence-tracked")
    add_common(sp)
    sp.add_argument("module", help="Module id (from `gs modules`) or script path")
    sp.add_argument("--target", default=None)
    sp.add_argument("--environment", default=None)
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("import", help="Import external scanner output")
    add_common(sp)
    sp.add_argument("tool", choices=["nmap", "nuclei", "burp", "zap", "nessus", "masscan", "nikto", "metasploit"])
    sp.add_argument("file", help="Path to the scanner output file, or '-' for stdin")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("report", help="Generate a report via Report Studio")
    add_common(sp)
    sp.add_argument("--variant", default="technical",
                     choices=["executive", "technical", "developer", "remediation", "retest"])
    sp.add_argument("--format", default="md")
    sp.add_argument("--out", default=".")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("template", help="Custom company report templates (item 29)")
    tmpl_sub = sp.add_subparsers(dest="template_command", required=True)
    sp2 = tmpl_sub.add_parser("fill", help="Fill a .docx template's {{placeholders}} with engagement data")
    add_common(sp2)
    sp2.add_argument("template", help="Path to the company .docx template")
    sp2.add_argument("--out", default=None, help="Output path (default: <template>_filled.docx next to it)")
    sp2.set_defaults(func=cmd_report_template_fill)
    sp2 = tmpl_sub.add_parser("placeholders", help="List placeholders GhostStrike knows how to fill")
    sp2.set_defaults(func=cmd_report_template_placeholders)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())