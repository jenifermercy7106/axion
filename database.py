import sqlite3
import bcrypt
import random
import string
from pathlib import Path

DB_PATH = Path(__file__).parent / "axion.db"


def _conn():
    return sqlite3.connect(DB_PATH)


def _generate_user_id():
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"AXN-{suffix}"


def init_db():
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)


def _unique_user_id():
    while True:
        uid = _generate_user_id()
        with _conn() as con:
            row = con.execute("SELECT 1 FROM users WHERE user_id=?", (uid,)).fetchone()
        if not row:
            return uid


def register_user(name: str, email: str, password: str):
    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        return False, "All fields are required.", None
    if len(password) < 8:
        return False, "Password must be at least 8 characters.", None

    with _conn() as con:
        row = con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
        if row:
            return False, "An account with that email already exists.", None

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = _unique_user_id()

    with _conn() as con:
        con.execute(
            "INSERT INTO users (user_id, name, email, password) VALUES (?,?,?,?)",
            (user_id, name, email, hashed),
        )

    return True, f"Welcome to AXION, {name}.", user_id


def login_user(email: str, password: str):
    email = email.strip().lower()

    with _conn() as con:
        row = con.execute(
            "SELECT id, user_id, name, email, password, created_at FROM users WHERE email=?",
            (email,),
        ).fetchone()

    if not row:
        return False, "No account found with that email.", None
    if not bcrypt.checkpw(password.encode(), row[4].encode()):
        return False, "Incorrect password.", None

    user = {
        "id": row[0],
        "user_id": row[1],
        "name": row[2],
        "email": row[3],
        "created_at": row[5],
    }
    return True, f"Welcome back, {row[2]}.", user


def get_user(email: str):
    email = email.strip().lower()
    with _conn() as con:
        row = con.execute(
            "SELECT id, user_id, name, email, created_at FROM users WHERE email=?",
            (email,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "user_id": row[1],
        "name": row[2],
        "email": row[3],
        "created_at": row[4],
    }


init_db()