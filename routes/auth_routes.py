"""
routes/auth_routes.py — Authentication Blueprint
Handles user registration and login.

Endpoints:
  POST /api/auth/register  — Create a new user
  POST /api/auth/login     — Authenticate and receive a JWT
"""

from flask import Blueprint, request, jsonify
from db import get_db
from utils.auth import hash_password, verify_password, generate_token

# Blueprint prefix is registered in app.py as /api/auth
auth_bp = Blueprint("auth", __name__)


# ── POST /api/auth/register ──────────────────────────────────
@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Request body (JSON):
      { "username": "alice", "password": "StrongP@ss1" }

    Success (201):
      { "message": "User registered successfully." }

    Errors:
      400 — Missing fields or username already taken
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    # ── Validation ──────────────────────────────────────────
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    # ── Persist ─────────────────────────────────────────────
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # Check for duplicate username (parameterized — no SQL injection)
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return jsonify({"error": "Username already taken."}), 400

            pw_hash = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, pw_hash),
            )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "User registered successfully."}), 201


# ── POST /api/auth/login ─────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and return a JWT.

    Request body (JSON):
      { "username": "alice", "password": "StrongP@ss1" }

    Success (200):
      { "token": "<JWT>", "user_id": 1, "username": "alice" }

    Errors:
      400 — Missing fields
      401 — Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, password_hash FROM users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()
    finally:
        conn.close()

    # Verify credentials — always run verify to prevent timing attacks
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid username or password."}), 401

    token = generate_token(user["id"], username)
    return jsonify({"token": token, "user_id": user["id"], "username": username}), 200
