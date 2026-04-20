#!/usr/bin/python3
"""Local encrypted message storage."""

import sqlite3, time

DB_PATH = 'messenger.db'


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                sender    TEXT    NOT NULL,
                recipient TEXT    NOT NULL,
                plaintext TEXT    NOT NULL,
                timestamp REAL    NOT NULL
            )
        ''')
        conn.commit()


def store_message(sender: str, recipient: str, plaintext: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT INTO messages (sender, recipient, plaintext, timestamp) VALUES (?,?,?,?)',
            (sender, recipient, plaintext, time.time())
        )
        conn.commit()


def get_history(user_a: str, user_b: str) -> list:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            '''SELECT sender, plaintext, timestamp FROM messages
               WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?)
               ORDER BY timestamp''',
            (user_a, user_b, user_b, user_a)
        ).fetchall()
    return [{'sender': r[0], 'text': r[1], 'ts': r[2]} for r in rows]


def purge_old(days: int = 30):
    cutoff = time.time() - days * 86400
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM messages WHERE timestamp < ?', (cutoff,))
        conn.commit()
