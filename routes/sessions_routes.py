"""
routes/sessions_routes.py — Login Sessions (Multi-Device) Blueprint

Endpoints:
  GET    /api/sessions                  — List all active sessions for the user
  DELETE /api/sessions/<session_id>     — Revoke a specific session
  DELETE /api/sessions                  — Revoke all sessions except the current one
"""

from flask import Blueprint, request, jsonify, g
from functools import wraps

import jwt as pyjwt

from db import get_db
from utils.auth import decode_token

sessions_bp = Blueprint("sessions", __name__)


# ── JWT Required Decorator ───────────────────────────────────
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

        g.user_id    = payload["user_id"]
        g.username   = payload["username"]
        g.session_id = session_id
        return f(*args, **kwargs)

    return wrapper


# ── GET /api/sessions ────────────────────────────────────────
@sessions_bp.route("", methods=["GET"])
@jwt_required
def list_sessions():
    """
    Return all non-revoked (active) sessions for the current user.

    Success (200):
      {
        "sessions": [
          {
            "session_id": "...",
            "ip_address":  "...",
            "user_agent":  "...",
            "created_at":  "...",
            "last_seen":   "...",
            "is_current":  true
          }
        ]
      }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT session_id, ip_address, user_agent, created_at, last_seen
                FROM   login_sessions
                WHERE  user_id = %s AND revoked = 0
                ORDER  BY last_seen DESC
                """,
                (g.user_id,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    sessions = [
        {
            "session_id": r["session_id"],
            "ip_address": r["ip_address"],
            "user_agent": r["user_agent"],
            "created_at": str(r["created_at"]),
            "last_seen":  str(r["last_seen"]),
            "is_current": r["session_id"] == g.session_id,
        }
        for r in rows
    ]
    return jsonify({"sessions": sessions}), 200


# ── DELETE /api/sessions/<session_id> ────────────────────────
@sessions_bp.route("/<session_id>", methods=["DELETE"])
@jwt_required
def revoke_session(session_id):
    """
    Revoke a specific session (must belong to the current user).

    Success (200):
      { "message": "Session revoked." }
    Errors:
      404 — session not found or not owned by user
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE login_sessions
                SET    revoked = 1
                WHERE  session_id = %s AND user_id = %s AND revoked = 0
                """,
                (session_id, g.user_id),
            )
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()

    if affected == 0:
        return jsonify({"error": "Session not found."}), 404

    return jsonify({"message": "Session revoked."}), 200


# ── DELETE /api/sessions ─────────────────────────────────────
@sessions_bp.route("", methods=["DELETE"])
@jwt_required
def revoke_other_sessions():
    """
    Revoke all sessions belonging to the current user EXCEPT the current one.
    Useful as a "sign out all other devices" action.

    Success (200):
      { "message": "All other sessions revoked.", "revoked_count": 3 }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE login_sessions
                SET    revoked = 1
                WHERE  user_id = %s
                  AND  session_id != %s
                  AND  revoked = 0
                """,
                (g.user_id, g.session_id or ""),
            )
            count = cur.rowcount
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "All other sessions revoked.", "revoked_count": count}), 200
