"""
Secure login backend (final, fixed version).

Run with:  python3 server.py
Then open: http://127.0.0.1:5000

Security measures implemented here:
  1. Parameterized SQL queries (no string concatenation)  -> prevents SQL injection
  2. Passwords stored only as bcrypt hashes, never plaintext
  3. Server-side re-validation of email/password shape (never trusts the client)
  4. Generic error messages ("invalid email or password") so the app never
     reveals whether the email exists -> prevents user enumeration
  5. User input is never echoed back into HTML -> prevents reflected XSS
  6. A basic per-IP attempt counter to slow down brute-force / credential stuffing
"""
import re
import sqlite3
import time
from pathlib import Path

import bcrypt
from flask import Flask, g, jsonify, request, send_from_directory

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "users_secure.db"

app = Flask(__name__, static_folder=str(APP_DIR / "public"), static_url_path="")

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60
_attempts = {}  # ip -> list[timestamps]  (in-memory demo; use Redis in production)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               email TEXT UNIQUE NOT NULL,
               password_hash TEXT NOT NULL
           )"""
    )
    # Seed one demo user with a bcrypt-hashed password (never plaintext).
    demo_email = "demo@juicebox.local"
    cur = db.execute("SELECT 1 FROM users WHERE email = ?", (demo_email,))
    if cur.fetchone() is None:
        hashed = bcrypt.hashpw(b"Password123", bcrypt.gensalt())
        db.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (demo_email, hashed.decode("utf-8")),
        )
        db.commit()
    db.close()


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window = [t for t in _attempts.get(ip, []) if now - t < WINDOW_SECONDS]
    _attempts[ip] = window
    return len(window) >= MAX_ATTEMPTS


def record_attempt(ip: str) -> None:
    _attempts.setdefault(ip, []).append(time.time())


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr or "unknown"

    if is_rate_limited(ip):
        return jsonify(message="Too many attempts. Try again in a minute."), 429

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip()
    password = payload.get("password") or ""

    # --- Server-side validation: never trust the client ---
    if not email or not password:
        return jsonify(message="Email and password are required."), 400
    if not EMAIL_RE.match(email):
        return jsonify(message="Invalid email or password."), 400
    if len(password) < 8:
        return jsonify(message="Invalid email or password."), 400

    record_attempt(ip)

    db = get_db()
    # Parameterized query: email is passed as a bound parameter, never
    # concatenated into the SQL string -> immune to SQL injection.
    cur = db.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    # Same generic message whether the email exists or not, and whether
    # the password is wrong -> prevents user enumeration.
    if row is None:
        return jsonify(message="Invalid email or password."), 401

    stored_hash = row[0].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify(message="Invalid email or password."), 401

    return jsonify(message=f"Welcome back!"), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5000)
