from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

DB_PATH = os.getenv("SQLITE_DB_PATH", "data/threat_intelligence.db")


def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    directory = os.path.dirname(db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: str = DB_PATH) -> None:
    with _connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                case_number TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source_type TEXT,
                source_message_id TEXT,
                account_id TEXT,
                subject TEXT,
                sender TEXT,
                recipient TEXT,
                original_evidence_hash TEXT,
                risk_score REAL,
                risk_level TEXT,
                confidence REAL,
                full_report_json TEXT NOT NULL
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(cases)").fetchall()}
        for column, definition in (
            ("source_type", "TEXT"),
            ("source_message_id", "TEXT"),
            ("account_id", "TEXT"),
        ):
            if column not in columns:
                connection.execute(f"ALTER TABLE cases ADD COLUMN {column} {definition}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_cases_source_identity ON cases(source_type, source_message_id, account_id)")


def save_case(case: dict[str, Any], db_path: str = DB_PATH) -> None:
    init_db(db_path)
    with _connect(db_path) as connection:
        connection.execute("""
            INSERT OR REPLACE INTO cases
            (id, case_number, status, created_at, updated_at, source_type, source_message_id, account_id,
             subject, sender, recipient, original_evidence_hash, risk_score, risk_level, confidence, full_report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case["id"], case["case_number"], case["status"], case["created_at"], case["updated_at"],
            case.get("source_type"), case.get("source_message_id"), case.get("account_id"),
            case.get("subject"), case.get("sender"), case.get("recipient"), case.get("original_evidence_hash"),
            case.get("risk_score"), case.get("risk_level"), case.get("confidence"), json.dumps(case),
        ))


def get_case(case_id: str, db_path: str = DB_PATH) -> dict[str, Any] | None:
    init_db(db_path)
    with _connect(db_path) as connection:
        row = connection.execute("SELECT full_report_json FROM cases WHERE id = ?", (case_id,)).fetchone()
    return json.loads(row["full_report_json"]) if row else None


def find_case_by_source(
    source_type: str,
    source_message_id: str,
    account_id: str | None = None,
    db_path: str = DB_PATH,
) -> dict[str, Any] | None:
    init_db(db_path)
    query = "SELECT full_report_json FROM cases WHERE source_type = ? AND source_message_id = ?"
    params: list[Any] = [source_type, source_message_id]
    if account_id is not None:
        query += " AND account_id = ?"
        params.append(account_id)
    query += " ORDER BY created_at DESC LIMIT 1"
    with _connect(db_path) as connection:
        row = connection.execute(query, params).fetchone()
    return json.loads(row["full_report_json"]) if row else None


def list_cases(limit: int = 20, offset: int = 0, db_path: str = DB_PATH) -> tuple[list[dict[str, Any]], int]:
    init_db(db_path)
    with _connect(db_path) as connection:
        rows = connection.execute("SELECT full_report_json FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        total = connection.execute("SELECT COUNT(*) AS count FROM cases").fetchone()["count"]
    return [json.loads(row["full_report_json"]) for row in rows], total


def get_recent_analyses(limit: int = 10, db_path: str = DB_PATH) -> list[dict[str, Any]]:
    cases, _ = list_cases(limit=limit, db_path=db_path)
    return cases
