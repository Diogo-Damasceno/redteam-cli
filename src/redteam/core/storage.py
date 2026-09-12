"""Persistencia: findings, execucoes de modulo e relatorios (SQLite, stdlib).

Um Storage por processo. Conexao compartilhada + lock (sqlite3 nao e
thread-safe por padrao e ':memory:' morre entre conexoes).
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL,
    target      TEXT NOT NULL,
    mode        TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    ok          INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES runs(id),
    module     TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT,
    evidence   TEXT,
    mitre      TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
"""


@dataclass
class Finding:
    module: str
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str = ""
    evidence: str = ""
    mitre: str = ""

    def fp(self) -> str:
        """Fingerprint estavel para deduplicar findings repetidos."""
        raw = f"{self.module}|{self.severity}|{self.title}|{self.evidence}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Storage:
    def __init__(self, path: Path | str = ":memory:"):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def start_run(self, module: str, target: str, mode: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO runs(module,target,mode,started_at) VALUES(?,?,?,?)",
                (module, target, mode, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, ok: bool = True) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET finished_at=?, ok=? WHERE id=?",
                (time.time(), 1 if ok else 0, run_id),
            )
            self._conn.commit()

    def add_finding(self, run_id: int, f: Finding) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings(run_id,module,severity,title,detail,"
                "evidence,mitre,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (run_id, f.module, f.severity, f.title, f.detail,
                 f.evidence, f.mitre, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def findings(self, run_id: Optional[int] = None) -> list[dict[str, Any]]:
        with self._lock:
            if run_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM findings ORDER BY severity DESC, id"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE run_id=? ORDER BY severity DESC, id",
                    (run_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    def runs(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM runs ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, -1)


def findings_by_severity(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[r["severity"]] = out.get(r["severity"], 0) + 1
    return out
