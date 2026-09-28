"""Database layer for IEA using SQLite."""
import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "iea.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'client',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message_type TEXT NOT NULL,
            content TEXT,
            image_path TEXT,
            signature TEXT,
            encrypted_session_key TEXT,
            encrypted_session_key_sender TEXT,
            is_read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # rsa_keys: stores ALL keypairs (current + historical) per user
    # is_active=1 means this is the current key
    c.execute("""
        CREATE TABLE IF NOT EXISTS rsa_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_rsa_username ON rsa_keys(username)")

    conn.commit()

    admin_pw = hashlib.sha256("admin123".encode()).hexdigest()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ("admin", admin_pw, "sysadmin")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass

    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username: str, password: str) -> bool:
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?,?)",
            (username, hash_password(password))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_user(username: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_user(username: str, password: str):
    user = get_user(username)
    if user and user["password_hash"] == hash_password(password):
        return user
    return None


# ── RSA key management ──

def save_rsa_key(username: str, public_key: str, private_key: str):
    """Mark old keys inactive, insert new active key with local timestamp."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute("UPDATE rsa_keys SET is_active=0 WHERE username=?", (username,))
    conn.execute(
        "INSERT INTO rsa_keys (username, public_key, private_key, is_active, created_at) VALUES (?,?,?,1,?)",
        (username, public_key, private_key, now)
    )
    conn.commit()
    conn.close()


def get_active_rsa_key(username: str):
    """Return the current active RSA keypair for a user."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM rsa_keys WHERE username=? AND is_active=1 ORDER BY created_at DESC LIMIT 1",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_rsa_keys(username: str):
    """Return all RSA keypairs (current + historical) for a user."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM rsa_keys WHERE username=? ORDER BY created_at DESC",
        (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_rsa_keys_table():
    """For admin: return all RSA key entries across all users."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, is_active, created_at, substr(public_key,1,60) as pub_preview FROM rsa_keys ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Messages ──

def save_message(sender, receiver, msg_type, content=None,
                 image_path=None, signature=None,
                 enc_session_key=None, enc_session_key_sender=None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute(
        """INSERT INTO messages
           (sender, receiver, message_type, content, image_path, signature,
            encrypted_session_key, encrypted_session_key_sender, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (sender, receiver, msg_type, content, image_path, signature,
         enc_session_key, enc_session_key_sender, now)
    )
    conn.commit()
    conn.close()


def get_messages(username: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM messages WHERE receiver=? OR sender=? ORDER BY created_at",
        (username, username)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_activity(username: str, action: str, details: str = None, ip: str = None):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_log (username, action, details, ip_address, created_at) VALUES (?,?,?,?,?)",
        (username, action, details, ip, now)
    )
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users WHERE role='client'"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_activity_log_count():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
    conn.close()
    return count


def get_activity_log(limit=100):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_message_count():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    conn.close()
    return count


def get_all_messages(limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM messages ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
