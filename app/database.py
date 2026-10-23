
import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "instance" / "records.db"

DATABASE_PATH = Path(
    os.environ.get("DATABASE_PATH", str(DEFAULT_DB_PATH))
)


def get_db():
    """Open a SQLite connection with safe row access."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(DATABASE_PATH),
        timeout=5
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    """Create the database schema if it does not exist."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id
                ON sessions(user_id);

            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                failed_count INTEGER NOT NULL DEFAULT 0
                    CHECK (failed_count >= 0),
                locked_until INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_records_user_id
                ON records(user_id);
        """)
