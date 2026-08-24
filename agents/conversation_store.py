from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConversationStore:
    """Simple SQLite-backed conversation persistence."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        if self.database_path != ":memory:":
            os.makedirs(
                os.path.dirname(os.path.abspath(self.database_path)), exist_ok=True
            )
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                namespace TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                messages_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (namespace, conversation_id)
            )
            """)
        self.connection.commit()

    def load_conversation(
        self, namespace: str, conversation_id: str
    ) -> Optional[List[Dict[str, Any]]]:
        row = self.connection.execute(
            """
            SELECT messages_json
            FROM conversations
            WHERE namespace = ? AND conversation_id = ?
            """,
            (namespace, conversation_id),
        ).fetchone()
        if not row:
            return None
        return json.loads(row["messages_json"])

    def save_conversation(
        self, namespace: str, conversation_id: str, messages: List[Dict[str, Any]]
    ) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO conversations(namespace, conversation_id, messages_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(namespace, conversation_id)
                DO UPDATE SET messages_json = excluded.messages_json, updated_at = excluded.updated_at
                """,
                (namespace, conversation_id, json.dumps(messages), _utc_now()),
            )

    def delete_conversation(self, namespace: str, conversation_id: str) -> None:
        with self.connection:
            self.connection.execute(
                """
                DELETE FROM conversations
                WHERE namespace = ? AND conversation_id = ?
                """,
                (namespace, conversation_id),
            )

    def close(self) -> None:
        self.connection.close()
