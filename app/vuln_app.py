"""
VULN_APP — намеренно уязвимое приложение для учебной лабораторной работы.
НЕ ИСПОЛЬЗОВАТЬ В ПРОДАКШЕНЕ. Запускать только локально (127.0.0.1).
"""
import sqlite3
import hashlib
import secrets
from flask import Flask, request, jsonify, g

DB_PATH = "lab.db"
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-key-not-for-prod"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,   -- хранится в открытом виде (уязвимость)
            role TEXT NOT NULL DEFAULT 'user'
        );
    """)
    seed = [
        ("alice", "alice_password_123", "user"),
        ("bob",   "bob_password_456",   "user"),
        ("admin", "S3cr3tAdm1n!",       "admin"),
    ]
    cur.executemany("INSERT INTO users(username, password, role) VALUES (?,?,?)", seed)
    conn.commit()
    conn.close()


# SQL Injection (A03)
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    row = db.execute(query).fetchone()

    if row:
        return jsonify({
            "ok": True,
            "session": secrets.token_hex(16),
            "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
        })
    return jsonify({"ok": False, "error": "invalid credentials"}), 401


# A07
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"ok": False, "error": "username/password required"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users(username, password, role) VALUES (?,?,?)",
            (username, password, "user"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "user exists"}), 409
    return jsonify({"ok": True})


@app.route("/users", methods=["GET"])
def users():
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
