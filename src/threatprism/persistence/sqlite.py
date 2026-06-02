from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from threatprism.cases.schemas import (
    AnalystFeedback,
    CaseStatus,
    CaseRecord,
    DisagreementRecord,
    TriageReport,
    TriageStatus,
    utc_now,
)


def sqlite_path_from_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.removeprefix("sqlite:///")
    if database_url == "sqlite:///:memory:":
        return ":memory:"
    return database_url


class SQLiteRepository:
    def __init__(self, database_url: str) -> None:
        self.db_path = sqlite_path_from_url(database_url)
        self._memory_conn: sqlite3.Connection | None = None
        # Serializes access to the shared in-memory connection. FastAPI runs
        # sync route handlers in a threadpool, so concurrent requests would
        # otherwise race the single :memory: connection's cursor/transaction.
        self._lock = threading.Lock()
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.execute("PRAGMA foreign_keys = ON")
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._transaction() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    source_case_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    triage_status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS triage_reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );
                CREATE TABLE IF NOT EXISTS disagreement_records (
                    feedback_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );
                """
            )

    def save_case(self, case: CaseRecord) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cases
                (case_id, source_case_id, source, status, triage_status, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case.case_id,
                    case.source_case_id,
                    str(case.source.value),
                    str(case.status.value),
                    str(case.triage_status.value),
                    case.model_dump_json(),
                    case.created_at.isoformat(),
                    case.updated_at.isoformat(),
                ),
            )

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self._transaction() as conn:
            row = conn.execute("SELECT payload_json FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        return CaseRecord.model_validate_json(row[0])

    def list_cases(self) -> list[CaseRecord]:
        with self._transaction() as conn:
            rows = conn.execute("SELECT payload_json FROM cases ORDER BY created_at DESC").fetchall()
        return [CaseRecord.model_validate_json(row[0]) for row in rows]

    def save_report(self, report: TriageReport) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO triage_reports
                (report_id, case_id, payload_json, generated_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.case_id,
                    report.model_dump_json(),
                    report.generated_at.isoformat(),
                ),
            )

    def get_report(self, case_id: str) -> TriageReport | None:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT payload_json FROM triage_reports WHERE case_id = ? ORDER BY generated_at DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        if row is None:
            return None
        return TriageReport.model_validate_json(row[0])

    def save_feedback(self, feedback: AnalystFeedback, disagreement: DisagreementRecord) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyst_feedback
                (feedback_id, case_id, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    feedback.feedback_id,
                    feedback.case_id,
                    feedback.model_dump_json(),
                    feedback.created_at.isoformat(),
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO disagreement_records
                (feedback_id, case_id, payload_json)
                VALUES (?, ?, ?)
                """,
                (
                    disagreement.feedback_id,
                    disagreement.case_id,
                    disagreement.model_dump_json(),
                ),
            )

    def list_feedback(self) -> list[AnalystFeedback]:
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM analyst_feedback ORDER BY created_at DESC"
            ).fetchall()
        return [AnalystFeedback.model_validate_json(row[0]) for row in rows]

    def list_disagreements(self) -> list[DisagreementRecord]:
        with self._transaction() as conn:
            rows = conn.execute("SELECT payload_json FROM disagreement_records").fetchall()
        return [DisagreementRecord.model_validate_json(row[0]) for row in rows]

    def update_case_status(self, case_id: str, status: CaseStatus, triage_status: TriageStatus) -> CaseRecord | None:
        case = self.get_case(case_id)
        if case is None:
            return None
        case.status = status  # type: ignore[assignment]
        case.triage_status = triage_status
        case.updated_at = utc_now()
        self.save_case(case)
        return case

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        if self._memory_conn is not None:
            # One shared connection: hold the lock for the whole transaction
            # (BEGIN -> execute -> COMMIT) so threads cannot interleave on it.
            with self._lock, self._memory_conn as conn:
                yield conn
            return
        # File-backed mode: a fresh connection per operation. SQLite handles
        # cross-connection file locking, so no process-level lock is needed.
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()
