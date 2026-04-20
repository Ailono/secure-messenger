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
                    created   DOUBLE PRECISION NOT NULL,
                    fcm_token TEXT
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id         SERIAL PRIMARY KEY,
                    sender     TEXT NOT NULL,
                    recipient  TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    timestamp  DOUBLE PRECISION NOT NULL,
                    status     TEXT NOT NULL DEFAULT 'sent'
                )
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_pair
                ON messages (sender, recipient)
            ''')
            # Migrate: add columns if they don't exist yet
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE messages ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'sent';
                    ALTER TABLE users    ADD COLUMN IF NOT EXISTS fcm_token TEXT;
                EXCEPTION WHEN others THEN NULL;
                END $$;
            """)
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
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT username FROM users ORDER BY username')
            return [r[0] for r in cur.fetchall()]


def save_fcm_token(username: str, token: str):
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET fcm_token=%s WHERE username=%s', (token, username))
        conn.commit()


def get_fcm_token(username: str):
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT fcm_token FROM users WHERE username=%s', (username,))
            row = cur.fetchone()
    return row[0] if row else None


# ── Messages ──────────────────────────────────────────────────────────────────

def store_message(sender: str, recipient: str, ciphertext: str) -> int:
    """Store encrypted blob only. Returns message id."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''INSERT INTO messages (sender, recipient, ciphertext, timestamp, status)
                   VALUES (%s, %s, %s, %s, 'sent') RETURNING id''',
                (sender, recipient, ciphertext, time.time())
            )
            msg_id = cur.fetchone()[0]
        conn.commit()
    return msg_id


def get_history(user_a: str, user_b: str) -> list:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                '''SELECT id, sender, ciphertext, timestamp, status FROM messages
                   WHERE (sender=%s AND recipient=%s) OR (sender=%s AND recipient=%s)
                   ORDER BY timestamp''',
                (user_a, user_b, user_b, user_a)
            )
            rows = cur.fetchall()
    return [{'id': r[0], 'sender': r[1], 'ciphertext': r[2], 'ts': r[3], 'status': r[4]} for r in rows]


def mark_delivered(msg_id: int):
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE messages SET status='delivered' WHERE id=%s AND status='sent'", (msg_id,))
        conn.commit()


def mark_delivered_bulk(sender: str, recipient: str):
    """Mark all undelivered messages from sender to recipient as delivered."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE messages SET status='delivered' WHERE sender=%s AND recipient=%s AND status='sent'",
                (sender, recipient)
            )
        conn.commit()


def mark_read(sender: str, reader: str):
    """Mark all messages from sender to reader as read."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE messages SET status='read' WHERE sender=%s AND recipient=%s AND status!='read'",
                (sender, reader)
            )
        conn.commit()


def get_conversations(username: str) -> list:
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
