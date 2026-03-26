"""
routes/logs_routes.py — Activity Logs Blueprint

Endpoints:
  POST   /api/logs   — Save a single activity log entry
  GET    /api/logs   — Retrieve all logs for the user (newest first)
  DELETE /api/logs   — Clear all logs for the user
"""

from flask import Blueprint, request, jsonify, g
from functools import wraps

import jwt as pyjwt

from db import get_db
from utils.auth import decode_token

logs_bp = Blueprint("logs", __name__)

VALID_TYPES = {"success", "error", "info", "warning"}


# ── Shared JWT Required Decorator ────────────────────────────
def jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header."}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(token)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

        # Check session revocation
        session_id = payload.get("session_id")
        if session_id:
            conn = get_db()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT revoked FROM login_sessions WHERE session_id = %s",
                        (session_id,),
                    )
                    row = cur.fetchone()
                    if row and row["revoked"]:
                        return jsonify({"error": "Session revoked. Please log in again."}), 401
            finally:
                conn.close()

        g.user_id  = payload["user_id"]
        g.username = payload["username"]
        return f(*args, **kwargs)

    return wrapper


# ── POST /api/logs ───────────────────────────────────────────
@logs_bp.route("", methods=["POST"])
@jwt_required
def save_log():
    """
    Persist a single activity log entry.

    Request body (JSON):
      { "type": "success", "message": "Password added for Google." }

    Success (201):
      { "message": "Logged.", "id": 42 }
    """
    data    = request.get_json(silent=True) or {}
    log_type = (data.get("type") or "info").strip().lower()
    message  = (data.get("message") or "").strip()

    if log_type not in VALID_TYPES:
        log_type = "info"

    if not message:
        return jsonify({"error": "message is required."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO activity_logs (user_id, type, message) VALUES (%s, %s, %s)",
                (g.user_id, log_type, message),
            )
            new_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Logged.", "id": new_id}), 201


# ── GET /api/logs ────────────────────────────────────────────
@logs_bp.route("", methods=["GET"])
@jwt_required
def get_logs():
    """
    Retrieve all activity logs for the current user, newest first.

    Success (200):
      { "logs": [ { "id": 42, "type": "success", "message": "...", "created_at": "..." } ] }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, type, message, created_at
                FROM   activity_logs
                WHERE  user_id = %s
                ORDER  BY created_at DESC
                LIMIT  500
                """,
                (g.user_id,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    logs = [
        {
            "id":         r["id"],
            "type":       r["type"],
            "message":    r["message"],
            "created_at": str(r["created_at"]),
        }
        for r in rows
    ]
    return jsonify({"logs": logs}), 200


# ── DELETE /api/logs ─────────────────────────────────────────
@logs_bp.route("", methods=["DELETE"])
@jwt_required
def clear_logs():
    """
    Clear all activity logs for the current user.

    Success (200):
      { "message": "Logs cleared." }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM activity_logs WHERE user_id = %s",
                (g.user_id,),
            )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Logs cleared."}), 200
