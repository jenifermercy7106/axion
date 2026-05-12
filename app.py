from flask import Flask, request, jsonify, render_template, session
from database import register_user, login_user, get_user
from scanner import run_scan
import os

app = Flask(__name__)
app.secret_key = "axion-secret-key-2026-fixed"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def api_register():
    data     = request.get_json(silent=True) or {}
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    if not name or not email or not password:
        return jsonify({"ok": False, "error": "Name, email and password are required."}), 400
    ok, msg, user_id = register_user(name, email, password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 409
    return jsonify({"ok": True, "message": msg, "user_id": user_id})

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    if not email or not password:
        return jsonify({"ok": False, "error": "Email and password are required."}), 400
    ok, msg, user = login_user(email, password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 401
    session["user"] = user["email"]
    return jsonify({"ok": True, "message": msg, "user": user})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/profile")
def api_profile():
    email = session.get("user")
    if not email:
        return jsonify({"ok": False, "error": "Not logged in."}), 401
    user = get_user(email)
    if not user:
        return jsonify({"ok": False, "error": "User not found."}), 404
    return jsonify({"ok": True, "user": user})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not session.get("user"):
        return jsonify({"ok": False, "error": "Not logged in."}), 401
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    if not code:
        return jsonify({"ok": False, "error": "No code provided."}), 400
    try:
        results = run_scan(code)
        return jsonify({"ok": True, "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    from database import init_db
    init_db()
    app.run(debug=True)