"""Alvo vulneravel de LABORATORIO (Flask) — intencionalmente inseguro.

SOBE APENAS LOCAL (docker compose). Serve para os modulos recon/sqli/
stuffing terem o que encontrar. Nunca exponha este container.
"""

import os
import sqlite3
import time
from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB = os.getenv("LAB_DB", "./lab.db")
FLAG = os.getenv("LAB_FLAG", "RT{lab_local_apenas}")


def db():
    if "conn" not in g:
        g.conn = sqlite3.connect(DB)
    return g.conn


def init():
    parent = os.path.dirname(os.path.abspath(DB))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY, title TEXT, body TEXT)""")
    # senhas em MD5 e fracas: e o PONTO do lab
    for u, p in [("admin", "123456"), ("operator", "password"), ("test", "teste")]:
        c.execute("INSERT OR IGNORE INTO users(username,password,email) VALUES(?,?,?)",
                  (u, __import__("hashlib").md5(p.encode()).hexdigest(), f"{u}@lab.local"))
    c.execute("INSERT OR IGNORE INTO posts(title,body) VALUES(?,?)",
              ("Bem-vindo", "Alvo de laboratorio redteam-cli"))
    c.commit()
    c.close()


@app.before_request
def _setup():
    init()


@app.get("/")
def index():
    return jsonify({"servico": "lab-target", "flag_local": FLAG})


@app.get("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})


# --- vulnerabilidade: concatenacao direta (SQLi) ----------------------------
@app.get("/search")
def search():
    q = request.args.get("q", "")
    try:
        cur = db().execute(f"SELECT id,title FROM posts WHERE title LIKE '%{q}%'")
        rows = [{"id": r[0], "title": r[1]} for r in cur.fetchall()]
        return jsonify({"results": rows})
    except Exception as e:  # vaza erro do SGBD -> sondagem detecta
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


# --- vulnerabilidade: senha fraca + MD5 + sem rate limit (stuffing) ---------
@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form or {}
    user = data.get("username", "")
    pwd = data.get("password", "")
    import hashlib
    cur = db().execute(
        "SELECT id FROM users WHERE username=? AND password=?",
        (user, hashlib.md5(str(pwd).encode()).hexdigest()),
    )
    row = cur.fetchone()
    if row:
        return jsonify({"ok": True, "token": f"lab-token-{row[0]}", "user": user})
    return jsonify({"ok": False}), 401


@app.get("/users")
def users():
    cur = db().execute("SELECT id,username,password,email FROM users")
    return jsonify([{"id": r[0], "username": r[1],
                     "md5": r[2], "email": r[3]} for r in cur.fetchall()])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
