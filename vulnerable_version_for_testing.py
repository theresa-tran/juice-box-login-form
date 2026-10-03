"""
INTENTIONALLY VULNERABLE version of the backend — used ONLY to demonstrate
and document the SQL injection attack in Part 3. This file is NOT the
version shipped in the public repo; it exists solely as a before/after
comparison so the exploit can be reproduced and explained.

Vulnerabilities on purpose:
  - Builds the SQL query by string concatenation (classic SQLi)
  - Stores/compares passwords in plaintext
"""
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "users_vulnerable.db"

app = Flask(__name__, static_folder=str(APP_DIR / "public"), static_url_path="")


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               email TEXT UNIQUE NOT NULL,
               password TEXT NOT NULL
           )"""
    )
    cur = db.execute("SELECT 1 FROM users WHERE email = ?", ("demo@juicebox.local",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            ("demo@juicebox.local", "Password123"),
        )
        db.commit()
    db.close()


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email") or ""
    password = payload.get("password") or ""

    db = sqlite3.connect(DB_PATH)
    # VULNERABLE: user input concatenated directly into the SQL string
    query = f"SELECT email FROM users WHERE email = '{email}' AND password = '{password}'"
    print("[DEBUG] Executing query:", query)
    try:
        cur = db.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        db.close()
        return jsonify(message=f"DB error: {e}"), 500
    db.close()

    if row:
        return jsonify(message=f"Welcome back, {row[0]}! (logged in as this account)"), 200
    return jsonify(message="Invalid email or password."), 401


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5001)
