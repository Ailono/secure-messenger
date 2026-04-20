#!/usr/bin/python3
"""Local encrypted message storage — plaintext is NEVER stored on disk."""

import sqlite3, time, os

DB_PATH = os.environ.get('DB_PATH', 'messenger.db')


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        # Users table: username + bcrypt password hash
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username  TEXT PRIMARY KEY,
                pw_hash   TEXT NOT NULL,
                created   REAL NOT NULL
            )
        ''')
        # Messages: only encrypted blobs — server never sees plaintext
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                sender    TEXT NOT NULL,
                recipient TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')
        conn.commit()


# ── Auth ──────────────────────────────────────────────────────────────────────

def register_user(username: str, pw_hash: str) -> bool:
    """Store a new user. Returns False if username already taken."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                'INSERT INTO users (username, pw_hash, created) VALUES (?,?,?)',
                (username, pw_hash, time.time())
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_hash(username: str):
    """Return stored bcrypt hash for username, or None."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            'SELECT pw_hash FROM users WHERE username=?', (username,)
        ).fetchone()
    return row[0] if row else None


# ── Messages ──────────────────────────────────────────────────────────────────

def store_message(sender: str, recipient: str, ciphertext: str):
    """Store encrypted blob only — plaintext never touches disk."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT INTO messages (sender, recipient, ciphertext, timestamp) VALUES (?,?,?,?)',
            (sender, recipient, ciphertext, time.time())
        )
        conn.commit()


def get_history(user_a: str, user_b: str) -> list:
    """Return encrypted message history between two users."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            '''SELECT sender, ciphertext, timestamp FROM messages
               WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
               ORDER BY timestamp''',
            (user_a, user_b, user_b, user_a)
        ).fetchall()
    return [{'sender': r[0], 'ciphertext': r[1], 'ts': r[2]} for r in rows]


def purge_old(days: int = 30):
    cutoff = time.time() - days * 86400
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM messages WHERE timestamp < ?', (cutoff,))
        conn.commit()
