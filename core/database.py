import json
import os
import sqlite3
from datetime import datetime


class ReconDatabase:
    def __init__(self, db_path="reports/recon.db"):
        os.makedirs("reports", exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            cur = conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    profile TEXT,
                    started_at TEXT,
                    elapsed REAL,
                    targets_total INTEGER,
                    targets_done INTEGER,
                    modules_run INTEGER,
                    errors INTEGER,
                    open_ports INTEGER,
                    web_services INTEGER,
                    vulnerabilities INTEGER,
                    subdomains INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    category TEXT,
                    target TEXT,
                    summary TEXT,
                    severity TEXT,
                    data_json TEXT
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS target_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    target TEXT,
                    result_json TEXT
                )
            """)

            conn.commit()

    def save_scan(self, ctx):
        with self._connect() as conn:
            cur = conn.cursor()

            cur.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, profile, started_at, elapsed,
                    targets_total, targets_done, modules_run, errors,
                    open_ports, web_services, vulnerabilities, subdomains
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ctx.scan_id,
                ctx.profile,
                datetime.now().isoformat(),
                ctx.elapsed,
                ctx.targets_total,
                ctx.targets_done,
                ctx.modules_run,
                ctx.errors,
                ctx.open_ports,
                ctx.web_services,
                ctx.vulnerabilities,
                ctx.subdomains,
            ))

            for category, items in ctx.findings.items():
                for item in items:
                    cur.execute("""
                        INSERT INTO findings (
                            scan_id, category, target, summary, severity, data_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        ctx.scan_id,
                        category,
                        item.get("target"),
                        item.get("summary"),
                        item.get("severity", "info"),
                        json.dumps(item.get("data", {})),
                    ))

            for target, result in ctx.results.items():
                cur.execute("""
                    INSERT INTO target_results (
                        scan_id, target, result_json
                    ) VALUES (?, ?, ?)
                """, (
                    ctx.scan_id,
                    target,
                    json.dumps(result),
                ))

            conn.commit()

    def list_scans(self, limit=20):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT scan_id, profile, started_at, elapsed,
                       targets_done, open_ports, vulnerabilities
                FROM scans
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
            return cur.fetchall()