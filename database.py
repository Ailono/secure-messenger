#!/usr/bin/python3
"""
PostgreSQL storage — plaintext NEVER stored.
All message content is encrypted ciphertext only.
"""

import os
import psycopg2
import psycopg2.extras
import bcrypt
import time

DATABASE_URL = os.environ.get('DATABASE_URL')


def _conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username  TEXT PRIMARY KEY,
                    pw_hash   TEXT NOT NULL,
                    created   DOUBLE PRECISION NOT NULL
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id         SERIAL PRIMARY KEY,
                    sender     TEXT NOT NULL,
                    recipient  TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    timestamp  DOUBLE PRECISION NOT NULL
                )
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_pair
                ON messages (sender, recipient)
            ''')
        conn.commit()


# ── Auth ──────────────────────────────────────────────────────────────────────

def register_user(username: str, pw_hash: str) -> bool:
    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO users (username, pw_hash, created) VALUES (%s, %s, %s)',
                    (username, pw_hash, time.time())
                )
            conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        return False


def get_user_hash(username: str):
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT pw_hash FROM users WHERE username=%s', (username,))
            row = cur.fetchone()
    return row[0] if row else None


def get_all_users() -> list:
    """Return list of all registered usernames."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT username FROM users ORDER BY username')
            return [r[0] for r in cur.fetchall()]


# ── Messages ──────────────────────────────────────────────────────────────────

def store_message(sender: str, recipient: str, ciphertext: str):
    """Store encrypted blob only — plaintext never touches the DB."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'INSERT INTO messages (sender, recipient, ciphertext, timestamp) VALUES (%s, %s, %s, %s)',
                (sender, recipient, ciphertext, time.time())
            )
        conn.commit()


def get_history(user_a: str, user_b: str) -> list:
    """Return encrypted message history between two users."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''SELECT sender, ciphertext, timestamp FROM messages
                   WHERE (sender=%s AND recipient=%s) OR (sender=%s AND recipient=%s)
                   ORDER BY timestamp''',
                (user_a, user_b, user_b, user_a)
            )
            rows = cur.fetchall()
    return [{'sender': r[0], 'ciphertext': r[1], 'ts': r[2]} for r in rows]


def get_conversations(username: str) -> list:
    """Return list of users this person has chatted with, most recent first."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''SELECT DISTINCT
                       CASE WHEN sender=%s THEN recipient ELSE sender END AS peer,
                       MAX(timestamp) as last_ts
                   FROM messages
                   WHERE sender=%s OR recipient=%s
                   GROUP BY peer
                   ORDER BY last_ts DESC''',
                (username, username, username)
            )
            rows = cur.fetchall()
    return [{'peer': r[0], 'last_ts': r[1]} for r in rows]


def delete_conversation(user_a: str, user_b: str):
    """Delete all messages between two users."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'DELETE FROM messages WHERE (sender=%s AND recipient=%s) OR (sender=%s AND recipient=%s)',
                (user_a, user_b, user_b, user_a)
            )
        conn.commit()


def purge_old(days: int = 30):
    cutoff = time.time() - days * 86400
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM messages WHERE timestamp < %s', (cutoff,))
        conn.commit()
