"""Document store (SQLite). Every query is parameterised and every read is scoped to the caller."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id      TEXT PRIMARY KEY,
    owner   TEXT NOT NULL,
    title   TEXT NOT NULL,
    body    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acl (
    doc_id  TEXT NOT NULL REFERENCES documents(id),
    user_id TEXT NOT NULL,
    PRIMARY KEY (doc_id, user_id)
);
"""

# One authorization predicate, repeated verbatim in each read query (as literal constants, never
# built at runtime). tests/test_authz.py checks every read path against it.
_CAN_READ = "(d.owner = :user OR EXISTS (SELECT 1 FROM acl a WHERE a.doc_id = d.id AND a.user_id = :user))"
SQL_READABLE = (
    "SELECT d.id, d.owner, d.title, d.body FROM documents d "
    "WHERE (d.owner = :user OR EXISTS (SELECT 1 FROM acl a WHERE a.doc_id = d.id AND a.user_id = :user)) "
    "ORDER BY d.id"
)
SQL_GET = (
    "SELECT d.id, d.owner, d.title, d.body FROM documents d "
    "WHERE d.id = :doc_id "
    "AND (d.owner = :user OR EXISTS (SELECT 1 FROM acl a WHERE a.doc_id = d.id AND a.user_id = :user))"
)
SQL_SEARCH = (
    "SELECT d.id, d.owner, d.title, d.body FROM documents d "
    "WHERE d.title LIKE :q ESCAPE '\\' "
    "AND (d.owner = :user OR EXISTS (SELECT 1 FROM acl a WHERE a.doc_id = d.id AND a.user_id = :user)) "
    "ORDER BY d.id"
)
if not all(_CAN_READ in q for q in (SQL_READABLE, SQL_GET, SQL_SEARCH)):  # import-time self-check
    raise RuntimeError("every read query must contain the authorization predicate")


@dataclass(frozen=True)
class Document:
    id: str
    owner: str
    title: str
    body: str


class DocumentStore:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def load_corpus(self, data_dir: Path) -> None:
        manifest = json.loads((data_dir / "documents.json").read_text(encoding="utf-8"))
        with self._lock, self._conn:
            for doc in manifest["documents"]:
                body = (data_dir / "docs" / doc["file"]).read_text(encoding="utf-8")
                self._conn.execute(
                    "INSERT OR REPLACE INTO documents (id, owner, title, body) VALUES (?, ?, ?, ?)",
                    (doc["id"], doc["owner"], doc["title"], body),
                )
                for user in doc.get("shared_with", []):
                    self._conn.execute(
                        "INSERT OR IGNORE INTO acl (doc_id, user_id) VALUES (?, ?)", (doc["id"], user)
                    )

    def readable_by(self, user: str) -> list[Document]:
        with self._lock:
            rows = self._conn.execute(SQL_READABLE, {"user": user}).fetchall()
        return [Document(*r) for r in rows]

    def get_for_user(self, doc_id: str, user: str) -> Document | None:
        """Returns None both when the document does not exist and when the caller may not read it,
        so the API answers 404 in both cases and does not reveal which documents exist."""
        with self._lock:
            row = self._conn.execute(SQL_GET, {"user": user, "doc_id": doc_id}).fetchone()
        return Document(*row) if row else None

    def search_titles(self, user: str, query: str) -> list[Document]:
        # LIKE wildcards in user input are escaped so they match literally.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._lock:
            rows = self._conn.execute(SQL_SEARCH, {"user": user, "q": f"%{escaped}%"}).fetchall()
        return [Document(*r) for r in rows]
