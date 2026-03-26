"""
routes/auth_routes.py — Authentication Blueprint
Handles user registration and login.

Endpoints:
  POST /api/auth/register  — Create a new user
  POST /api/auth/login     — Authenticate and receive a JWT
"""

import uuid

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

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cursor:
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
    Authenticate a user, record the login session, and return a JWT.

    Request body (JSON):
      { "username": "alice", "password": "StrongP@ss1" }

    Success (200):
      {
        "token":      "<JWT>",
        "user_id":    1,
        "username":   "alice",
        "session_id": "<uuid>",
        "new_device": false
      }

    new_device is True when the login originates from an IP or
    user-agent not previously seen for this account.

    Errors:
      400 — Missing fields
      401 — Invalid credentials
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # ── Verify credentials ───────────────────────────────────
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

    # Always run verify to prevent timing attacks
    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid username or password."}), 401

    user_id    = user["id"]
    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    ip_address = ip_address.split(",")[0].strip()   # take first IP if behind a proxy
    user_agent = (request.headers.get("User-Agent") or "unknown")[:512]
    session_id = str(uuid.uuid4())

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # ── Detect new device ────────────────────────────
            # Check for previous sessions with same IP or User-Agent
            cursor.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM   login_sessions
                WHERE  user_id = %s
                  AND  revoked  = 0
                  AND  (ip_address = %s OR user_agent = %s)
                """,
                (user_id, ip_address, user_agent),
            )
            seen_before = int(cursor.fetchone()["cnt"]) > 0

            # Check if any prior sessions exist at all
            cursor.execute(
                "SELECT COUNT(*) AS total FROM login_sessions WHERE user_id = %s",
                (user_id,),
            )
            total = int(cursor.fetchone()["total"])

            # new_device fires only when prior sessions exist but none match this device
            new_device = (total > 0) and (not seen_before)

            # ── Persist the new session ──────────────────────
            cursor.execute(
                """
                INSERT INTO login_sessions (user_id, session_id, ip_address, user_agent)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, session_id, ip_address, user_agent),
            )
        conn.commit()
    finally:
        conn.close()

    token = generate_token(user_id, username, session_id)
    return jsonify({
        "token":      token,
        "user_id":    user_id,
        "username":   username,
        "session_id": session_id,
        "new_device": new_device,
    }), 200
