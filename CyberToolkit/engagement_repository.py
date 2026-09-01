"""
GhostStrike - Engagement Repository (CyberToolkit/engagement_repository.py)

Storage abstraction over one engagement's data. Callers use
get_assets()/get_findings()/get_evidence()/add_finding()/update_finding()
etc. without knowing (or caring) whether the data underneath is the
existing flat-JSON stores (findings/*.json, evidence/manifest.json, the
run ledger -- all real, populated, in production use today) or the new
SQLite schema (bash_scripts_for_pentest/lib/engagement_schema.sql --
real and tested, but empty; nothing has migrated into it yet).

Migration plan, stated explicitly rather than left implicit: this class
defaults to backend="json" because that is where real engagement data
actually lives right now -- switching the default before any real
migration tooling exists would just make the tool report empty results
against real engagements. backend="sqlite" is fully implemented and
tested (see the test suite this module ships with), not a stub, so a
future migration can populate it and flip the default without inventing
the write paths at that point. Every caller that adopts this repository
now, instead of reading engagement_query.py or the JSON stores directly,
gets that migration for free later -- it only has to happen once, here,
rather than once per call site.

JSON backend: read paths delegate to
bash_scripts_for_pentest/lib/engagement_query.py, the engagement-scoped
read layer the dedup engine/attack-graph builder/Report Studio/MCP server
already share -- not a second implementation of "how to load a finding."
Write paths (add_finding/update_finding) go through
lib/finding_ontology.sh's gs_finding_new (via a small bash shim), the
same schema-validated path every bash module already uses, so a finding
created through this repository is indistinguishable from one a module
created directly.

SQLite backend: a real sqlite3-backed implementation against
engagement_schema.sql, useful today for testing the schema and for any
new caller that wants a queryable local database now rather than waiting
for a full migration decision.

`assets`/`services`/`credentials` have no dedicated JSON store yet (only
findings/evidence/runs/repro-sessions do) -- the JSON backend derives them
from findings' target.host/port fields and the vault's credential index,
the same best-effort approach lib/attack_graph_builder.py already uses,
rather than inventing a JSON store this pass doesn't otherwise need.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_CYBERTOOLKIT_DIR = str(Path(__file__).resolve().parent)
if _CYBERTOOLKIT_DIR not in sys.path:
    sys.path.insert(0, _CYBERTOOLKIT_DIR)
_SCRIPTS_LIB_DIR = str(Path(__file__).resolve().parent.parent / "bash_scripts_for_pentest" / "lib")
if _SCRIPTS_LIB_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_LIB_DIR)
import engagement_query as _eq  # noqa: E402
from shell_command_builder import find_bash_invocation as _find_bash_invocation  # noqa: E402

_SCHEMA_PATH = Path(_SCRIPTS_LIB_DIR) / "engagement_schema.sql"
_CALL_LIB_FUNCTION_SHIM = Path(_SCRIPTS_LIB_DIR) / "_call_lib_function.sh"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4()}" if prefix else str(uuid.uuid4())


class EngagementRepositoryError(Exception):
    pass


class EngagementRepository:
    def __init__(self, engagement_id: str, backend: str = "json", db_path: Optional[str] = None):
        if backend not in ("json", "sqlite"):
            raise ValueError(f"unknown backend: {backend!r} (expected 'json' or 'sqlite')")
        self.engagement_id = engagement_id
        self.backend = backend
        self._conn: Optional[sqlite3.Connection] = None
        if backend == "sqlite":
            self._db_path = Path(db_path) if db_path else self._default_db_path(engagement_id)
            self._open_sqlite()

    # ── Path/setup helpers ──────────────────────────────────────────────

    @staticmethod
    def _default_db_path(engagement_id: str) -> Path:
        home = Path(os.environ.get("HOME", os.path.expanduser("~")))
        d = home / ".ghoststrike" / "engagements" / engagement_id
        d.mkdir(parents=True, exist_ok=True)
        return d / "engagement.db"

    def _open_sqlite(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self._db_path.exists()
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if is_new or not self._has_tables():
            with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
                self._conn.executescript(f.read())
        self._ensure_engagement_row()

    def _has_tables(self) -> bool:
        cur = self._conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='engagements'")
        return cur.fetchone() is not None

    def _ensure_engagement_row(self) -> None:
        cur = self._conn.execute("SELECT id FROM engagements WHERE id = ?", (self.engagement_id,))
        if cur.fetchone() is None:
            now = _now_iso()
            self._conn.execute(
                "INSERT INTO engagements (id, environment, status, created_at, updated_at) VALUES (?, 'lab', 'active', ?, ?)",
                (self.engagement_id, now, now),
            )
            self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "EngagementRepository":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Findings ─────────────────────────────────────────────────────────

    def get_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.backend == "json":
            findings = _eq.get_findings(self.engagement_id)
            if severity:
                findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]
            return findings

        query = "SELECT * FROM findings WHERE engagement_id = ? AND superseded_by IS NULL"
        params: List[Any] = [self.engagement_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        rows = self._conn.execute(query, params).fetchall()
        return [self._normalize_finding_row(dict(r)) for r in rows]

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        if self.backend == "json":
            return _eq.get_finding(finding_id)
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._normalize_finding_row(dict(row)) if row else None

    @staticmethod
    def _normalize_finding_row(row: Dict[str, Any]) -> Dict[str, Any]:
        """SQLite's primary key column is `id`; every JSON finding uses
        `finding_id` for the same concept (an established, high-blast-radius
        convention across finding_ontology.sh/finding_dedup.py/the schema --
        not worth changing). Aliasing here, once, is what lets every other
        caller (the CLI, the timeline, GhostScore) treat both backends'
        finding dicts the same way instead of branching on self.backend."""
        row.setdefault("finding_id", row.get("id"))
        return row

    def add_finding(
        self, title: str, severity: str, description: str = "",
        target_host: str = "", target_port: Optional[int] = None,
        remediation: str = "", module: str = "",
    ) -> str:
        """Returns the new finding's id."""
        if self.backend == "json":
            return self._add_finding_json(title, severity, description, remediation, module,
                                           target_host, target_port)

        asset_id = self._get_or_create_asset(target_host) if target_host else None
        service_id = self._get_or_create_service(asset_id, target_port) if asset_id and target_port else None

        fid = _new_id()
        now = _now_iso()
        self._conn.execute(
            """INSERT INTO findings
               (id, engagement_id, asset_id, service_id, title, description, severity, module,
                remediation, status, source_count, discovered_at, discovered_by,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, ?, ?)""",
            (fid, self.engagement_id, asset_id, service_id, title, description, severity.upper(), module,
             remediation, now, os.environ.get("USER", "unknown"), now, now),
        )
        self._conn.commit()
        return fid

    def _get_or_create_asset(self, host: str) -> str:
        row = self._conn.execute(
            "SELECT id FROM assets WHERE engagement_id = ? AND (hostname = ? OR ip_address = ?)",
            (self.engagement_id, host, host),
        ).fetchone()
        if row:
            return row["id"]
        aid = _new_id()
        now = _now_iso()
        self._conn.execute(
            """INSERT INTO assets (id, engagement_id, type, hostname, ip_address, created_at, updated_at)
               VALUES (?, ?, 'host', ?, ?, ?, ?)""",
            (aid, self.engagement_id, host, host, now, now),
        )
        return aid

    def _get_or_create_service(self, asset_id: str, port: int) -> str:
        row = self._conn.execute(
            "SELECT id FROM services WHERE asset_id = ? AND port = ?", (asset_id, port),
        ).fetchone()
        if row:
            return row["id"]
        sid = _new_id()
        now = _now_iso()
        self._conn.execute(
            """INSERT INTO services (id, engagement_id, asset_id, port, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (sid, self.engagement_id, asset_id, port, now, now),
        )
        return sid

    def _add_finding_json(self, title: str, severity: str, description: str,
                           remediation: str, module: str,
                           target_host: str = "", target_port: Optional[int] = None) -> str:
        """Shells out to gs_finding_new (lib/finding_ontology.sh) through
        the same centralized WSL/Git-Bash/native resolver
        (shell_command_builder.find_bash_invocation) every other process
        invocation in this codebase uses -- not a second, bespoke
        WSL-detection implementation. finding_ontology.sh is meant to be
        sourced rather than executed, so the call goes through
        lib/_call_lib_function.sh, a small generic sourcing shim."""
        finding_ontology = Path(_SCRIPTS_LIB_DIR) / "finding_ontology.sh"
        if not finding_ontology.exists():
            raise EngagementRepositoryError(f"lib/finding_ontology.sh not found at {finding_ontology}")
        if not _CALL_LIB_FUNCTION_SHIM.exists():
            raise EngagementRepositoryError(f"shim not found at {_CALL_LIB_FUNCTION_SHIM}")

        title_arg = title if len(title) >= 10 else f"{title} ({module or 'repository'})"
        env_vars = {"GS_ENGAGEMENT_ID": self.engagement_id}
        if os.environ.get("GS_FINDINGS_DIR"):
            env_vars["GS_FINDINGS_DIR"] = os.environ["GS_FINDINGS_DIR"]

        cmd = _find_bash_invocation(
            str(_CALL_LIB_FUNCTION_SHIM),
            args=[str(finding_ontology), "gs_finding_new", title_arg, severity.upper(),
                  description or "No description provided."],
            env_vars=env_vars,
            wsl_path_env_keys={"GS_FINDINGS_DIR"},
            path_arg_indices={0},
            use_sudo=False,  # a finding-metadata write never needs root
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception as exc:
            raise EngagementRepositoryError(f"could not invoke gs_finding_new: {exc}") from exc

        if result.returncode != 0 or not result.stdout.strip():
            raise EngagementRepositoryError(f"gs_finding_new failed: {result.stderr or result.stdout}")

        fid = result.stdout.strip().splitlines()[-1]
        patch = {}
        if remediation:
            patch["remediation"] = remediation
        if module:
            patch["module"] = module
        if target_host:
            target = {"host": target_host}
            if target_port is not None:
                target["port"] = target_port
            patch["target"] = target
        if patch:
            self.update_finding(fid, **patch)
        return fid

    # Columns update_finding() is actually allowed to write -- every
    # real column in the findings table except the primary key,
    # engagement_id (never reassigned after creation), and the two
    # timestamps this method manages itself. fields is **kwargs today
    # (only ever called with fixed literal keyword arguments, e.g.
    # update_finding(fid, status=status)), so nothing untrusted reaches
    # it yet -- but the SQL below built the column list straight from
    # fields.keys() with no check at all, which is one call site away
    # from a real SQL injection the moment anything passes fields
    # through from less trusted input (a REST API, an import path, an
    # AI tool argument). Reject anything outside this list outright
    # rather than trust every future caller to keep doing the right
    # thing.
    _UPDATABLE_FINDING_COLUMNS = frozenset({
        "asset_id", "service_id", "title", "description", "severity",
        "confidence", "cve_ids", "cwe_ids", "cvss_score", "cvss_vector",
        "mitre_technique_id", "module", "remediation", "status",
        "source_count", "merged_from", "superseded_by", "discovered_at",
        "discovered_by",
    })

    def update_finding(self, finding_id: str, **fields) -> None:
        if self.backend == "json":
            # No SQL involved on this path -- data.update() on a plain
            # dict accepts any key harmlessly, including ones (like
            # "target", a nested object -- see the caller below) that
            # exist in finding.schema.json but have no matching SQLite
            # column. The allow-list below is specifically about the raw
            # SQL string built from fields.keys() further down, so it
            # doesn't apply here.
            findings_dir = _eq.findings_dir()
            path = findings_dir / f"{finding_id}.json"
            if not path.exists():
                raise EngagementRepositoryError(f"finding {finding_id!r} not found")
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.update({k: v for k, v in fields.items() if v is not None})
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            return

        if not fields:
            return

        # Column names below are interpolated directly into the SQL string
        # (values are correctly parameterized, but SQL has no placeholder
        # syntax for a column name) -- fields is always fixed literal
        # keyword arguments from trusted internal callers today, but there
        # is no guard preventing a future caller from passing fields
        # through from less trusted input. Reject anything that isn't a
        # real, known-updatable column outright rather than trust every
        # future caller to keep doing the right thing.
        unknown = set(fields) - self._UPDATABLE_FINDING_COLUMNS
        if unknown:
            raise EngagementRepositoryError(
                f"update_finding() got unknown field(s) {sorted(unknown)!r} -- "
                f"only {sorted(self._UPDATABLE_FINDING_COLUMNS)!r} may be updated "
                f"on the sqlite backend."
            )
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        params = list(fields.values()) + [_now_iso(), finding_id]
        self._conn.execute(
            f"UPDATE findings SET {set_clause}, updated_at = ? WHERE id = ?", params,
        )
        self._conn.commit()

    # ── Evidence ─────────────────────────────────────────────────────────

    def get_evidence(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.backend == "json":
            manifests = _eq.get_evidence_manifests(self.engagement_id)
            artifacts = [a for m in manifests for a in m.get("artifacts", [])]
            return artifacts
        query = "SELECT * FROM evidence WHERE engagement_id = ?"
        params: List[Any] = [self.engagement_id]
        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Assets / services (derived from findings for the JSON backend --
    # no dedicated asset store exists yet; see module docstring) ─────────

    def get_assets(self) -> List[Dict[str, Any]]:
        if self.backend == "json":
            hosts: Dict[str, Dict[str, Any]] = {}
            for f in _eq.get_findings(self.engagement_id):
                host = (f.get("target") or {}).get("host")
                if not host:
                    continue
                hosts.setdefault(host, {"id": host, "type": "host", "hostname": host,
                                         "ip_address": host, "finding_count": 0})
                hosts[host]["finding_count"] += 1
            return list(hosts.values())
        rows = self._conn.execute("SELECT * FROM assets WHERE engagement_id = ?", (self.engagement_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_services(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.backend == "json":
            services: Dict[str, Dict[str, Any]] = {}
            for f in _eq.get_findings(self.engagement_id):
                target = f.get("target") or {}
                host, port = target.get("host"), target.get("port")
                if not host or port is None:
                    continue
                if asset_id and host != asset_id:
                    continue
                key = f"{host}:{port}"
                services.setdefault(key, {"id": key, "asset_id": host, "port": port,
                                           "service_name": target.get("service", "")})
            return list(services.values())
        query = "SELECT * FROM services WHERE engagement_id = ?"
        params: List[Any] = [self.engagement_id]
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Crown Jewels (item 20) ──────────────────────────────────────────
    # JSON backend: a sidecar crown_jewels.json (list of host strings) next
    # to the findings dir, the same lightweight-sidecar pattern
    # finding_dedup.py already uses for dedup_overrides.json -- no need to
    # invent a heavier store for one boolean flag per host. SQLite backend:
    # the real column, assets.criticality, which the schema already
    # supports (CHECK includes 'crown_jewel').

    def _crown_jewels_path(self) -> Path:
        return _eq.findings_dir().parent / "crown_jewels.json"

    def _load_crown_jewels_json(self) -> List[str]:
        try:
            with open(self._crown_jewels_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            return list(data.get(self.engagement_id, []))
        except (OSError, json.JSONDecodeError):
            return []

    def mark_crown_jewel(self, host: str, is_crown_jewel: bool = True) -> None:
        if self.backend == "json":
            path = self._crown_jewels_path()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                data = {}
            hosts = set(data.get(self.engagement_id, []))
            if is_crown_jewel:
                hosts.add(host)
            else:
                hosts.discard(host)
            data[self.engagement_id] = sorted(hosts)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            return

        asset_id = self._get_or_create_asset(host)
        now = _now_iso()
        self._conn.execute(
            "UPDATE assets SET criticality = ?, updated_at = ? WHERE id = ?",
            ("crown_jewel" if is_crown_jewel else "unknown", now, asset_id),
        )
        self._conn.commit()

    def get_crown_jewels(self) -> List[str]:
        """Returns the list of host identifiers marked as crown jewels."""
        if self.backend == "json":
            return self._load_crown_jewels_json()
        rows = self._conn.execute(
            "SELECT hostname, ip_address FROM assets WHERE engagement_id = ? AND criticality = 'crown_jewel'",
            (self.engagement_id,),
        ).fetchall()
        return [r["hostname"] or r["ip_address"] for r in rows]

    # ── Retest workflow (item 27) ───────────────────────────────────────
    # Status lifecycle: open -> confirmed -> reported -> remediation_submitted
    # -> retesting -> fixed | still_vulnerable (or accepted_risk at any
    # point) -- see schemas/finding.schema.json's status enum and
    # engagement_schema.sql's matching CHECK constraint.

    _RETEST_STATUSES = ("open", "confirmed", "reported", "remediation_submitted",
                         "retesting", "fixed", "still_vulnerable", "accepted_risk")

    def set_finding_status(self, finding_id: str, status: str) -> None:
        if status not in self._RETEST_STATUSES:
            raise EngagementRepositoryError(
                f"invalid status {status!r}; must be one of {self._RETEST_STATUSES}")
        self.update_finding(finding_id, status=status)

    def _retests_path(self) -> Path:
        return _eq.findings_dir().parent / "retests.json"

    def start_retest(self, finding_id: str) -> Dict[str, Any]:
        """Marks a finding as being retested and returns what an operator
        (or the CLI) needs to actually re-run the original check: the
        module that originally produced it and the target it was found on.
        Does not itself re-invoke the module -- GhostStrike has ~130
        modules with varying argument conventions, and guessing the wrong
        invocation for one would be worse than not automating it. The `gs`
        CLI's `retest run` command performs the actual re-run, reusing the
        same module-invocation path (shell_command_builder) every other
        run does, then calls resolve_retest() with the real outcome."""
        finding = self.get_finding(finding_id)
        if finding is None:
            raise EngagementRepositoryError(f"finding {finding_id!r} not found")
        original_status = finding.get("status", "open")
        self.set_finding_status(finding_id, "retesting")

        retest_id = _new_id()
        now = _now_iso()
        if self.backend == "json":
            path = self._retests_path()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                data = {}
            records = data.setdefault(self.engagement_id, [])
            records.append({"id": retest_id, "finding_id": finding_id,
                             "original_status": original_status, "retested_at": now,
                             "result": None, "notes": ""})
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        else:
            self._conn.execute(
                """INSERT INTO retests (id, engagement_id, finding_id, original_status,
                   retested_at, created_at) VALUES (?, ?, ?, ?, ?, ?)""",
                (retest_id, self.engagement_id, finding_id, original_status, now, now),
            )
            self._conn.commit()

        return {
            "retest_id": retest_id,
            "finding_id": finding_id,
            "module": finding.get("module", ""),
            "target": finding.get("target", {}),
            "original_evidence": finding.get("evidence"),
        }

    def resolve_retest(self, finding_id: str, outcome: str, notes: str = "",
                        retest_id: Optional[str] = None) -> None:
        """Records the operator's (or a re-run module's) verdict. `outcome`
        is never inferred automatically -- a clean re-scan doesn't always
        mean truly fixed (timing, scope, or environment differences can all
        produce a false negative), so this always reflects an explicit
        decision, matching the fail-closed/no-silent-assumptions principle
        applied throughout this codebase's other authorization paths."""
        if outcome not in ("fixed", "still_vulnerable"):
            raise EngagementRepositoryError("outcome must be 'fixed' or 'still_vulnerable'")
        self.set_finding_status(finding_id, outcome)
        result = "remediated" if outcome == "fixed" else "still_vulnerable"
        now = _now_iso()

        if self.backend == "json":
            path = self._retests_path()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                data = {}
            records = data.setdefault(self.engagement_id, [])
            target = None
            if retest_id:
                target = next((r for r in records if r["id"] == retest_id), None)
            if target is None:
                open_ones = [r for r in records if r["finding_id"] == finding_id and r["result"] is None]
                target = open_ones[-1] if open_ones else None
            if target is not None:
                target["result"] = result
                target["notes"] = notes
                target["retested_at"] = now
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        else:
            if retest_id:
                self._conn.execute(
                    "UPDATE retests SET result = ?, notes = ?, retested_at = ? WHERE id = ?",
                    (result, notes, now, retest_id),
                )
            else:
                # Plain SQLite doesn't support ORDER BY/LIMIT directly in
                # UPDATE, hence the id lookup via subquery.
                self._conn.execute(
                    """UPDATE retests SET result = ?, notes = ?, retested_at = ?
                       WHERE id = (SELECT id FROM retests
                                   WHERE finding_id = ? AND result IS NULL
                                   ORDER BY created_at DESC LIMIT 1)""",
                    (result, notes, now, finding_id),
                )
            self._conn.commit()

    def get_retests(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.backend == "json":
            try:
                with open(self._retests_path(), "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                return []
            records = data.get(self.engagement_id, [])
            if finding_id:
                records = [r for r in records if r["finding_id"] == finding_id]
            return records
        query = "SELECT * FROM retests WHERE engagement_id = ?"
        params: List[Any] = [self.engagement_id]
        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)
        rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Timeline (item 26) ──────────────────────────────────────────────

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Chronological merge of run-ledger entries, evidence artifacts,
        and finding-discovery events -- no separate timeline store; this is
        a derived view over data that already exists, the same principle
        the attack graph is built on."""
        events: List[Dict[str, Any]] = []

        for run in self.get_runs():
            ts = run.get("timestamp")
            if not ts:
                continue
            events.append({
                "timestamp": ts, "type": "run",
                "summary": f"{run.get('module', 'unknown module')} executed",
                "detail": run,
            })

        for f in self.get_findings():
            ts = f.get("discovered_at")
            if ts:
                events.append({
                    "timestamp": ts, "type": "finding_discovered",
                    "summary": f"{f.get('finding_id', '?')} discovered: {f.get('title', '')}",
                    "detail": {"finding_id": f.get("finding_id"), "severity": f.get("severity")},
                })

        if self.backend == "json":
            for manifest in _eq.get_evidence_manifests(self.engagement_id):
                for artifact in manifest.get("artifacts", []):
                    ts = artifact.get("collected_at") or artifact.get("timestamp")
                    if not ts:
                        continue
                    events.append({
                        "timestamp": ts, "type": "evidence_collected",
                        "summary": f"Evidence collected: {artifact.get('description', artifact.get('artifact_id', ''))}",
                        "detail": {"artifact_id": artifact.get("artifact_id")},
                    })

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ── Credentials (references only -- see lib/vault_crypto.py; never
    # the secret itself, matching the vault release-blocker fix) ─────────

    def get_credentials(self) -> List[Dict[str, Any]]:
        if self.backend == "json":
            home = Path(os.environ.get("HOME", os.path.expanduser("~")))
            index_path = Path(os.environ.get("GS_VAULT_DIR", str(home / ".ghoststrike" / "vault"))) / "index.json"
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    idx = json.load(f)
            except (OSError, json.JSONDecodeError):
                return []
            return [{"id": cid, "vault_ref": cid, **meta} for cid, meta in idx.get("credentials", {}).items()]
        rows = self._conn.execute("SELECT * FROM credentials WHERE engagement_id = ?", (self.engagement_id,)).fetchall()
        return [dict(r) for r in rows]

    # ── Runs / reproducibility / summary ────────────────────────────────

    def get_runs(self) -> List[Dict[str, Any]]:
        if self.backend == "json":
            return _eq.get_runs(self.engagement_id)
        rows = self._conn.execute("SELECT * FROM runs WHERE engagement_id = ?", (self.engagement_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_repro_sessions(self) -> List[Dict[str, Any]]:
        if self.backend == "json":
            return _eq.get_repro_sessions(self.engagement_id)
        raise NotImplementedError("reproducibility sessions are not yet mirrored into the sqlite backend")

    def summary(self) -> Dict[str, Any]:
        if self.backend == "json":
            return _eq.get_summary(self.engagement_id)
        findings = self.get_findings()
        by_severity: Dict[str, int] = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        return {
            "engagement_id": self.engagement_id,
            "finding_count": len(findings),
            "findings_by_severity": by_severity,
            "run_count": len(self.get_runs()),
        }