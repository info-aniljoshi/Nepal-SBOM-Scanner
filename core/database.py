import sqlite3
import json
import os
from datetime import datetime
from typing import List, Optional
from core.models import SbomReport

DB_PATH = os.environ.get("DATABASE_PATH", "nepal_sbom.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_packages INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            json_report TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_cache (
            cve_id TEXT PRIMARY KEY,
            explanation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def get_cached_explanation(cve_id: str) -> Optional[str]:
    conn = get_connection()
    row = conn.execute("SELECT explanation FROM ai_cache WHERE cve_id = ?", (cve_id,)).fetchone()
    conn.close()
    return row["explanation"] if row else None

def save_cached_explanation(cve_id: str, explanation: str):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO ai_cache (cve_id, explanation) VALUES (?, ?)",
        (cve_id, explanation)
    )
    conn.commit()
    conn.close()

def save_scan(report: SbomReport) -> int:
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO scans (project_name, total_packages, critical_count, high_count, json_report)
           VALUES (?, ?, ?, ?, ?)""",
        (
            report.project_name,
            report.total_packages,
            report.critical_count,
            report.high_count,
            json.dumps(report.model_dump(mode='json'), default=str)
        )
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 10) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id: int) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
