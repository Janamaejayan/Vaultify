"""
routes/generator_routes.py — Password Generator History Blueprint

Endpoints:
  POST   /api/generator   — Save a generated password to history
  GET    /api/generator   — Retrieve generator history (latest 50)
  DELETE /api/generator   — Clear all generator history for the user
"""

from flask import Blueprint, request, jsonify, g
from functools import wraps

import jwt as pyjwt

from db import get_db
from utils.auth import decode_token

generator_bp = Blueprint("generator", __name__)


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


# ── POST /api/generator ──────────────────────────────────────
@generator_bp.route("", methods=["POST"])
@jwt_required
def save_generated():
    """
    Save a generated password to the user's history.

    Request body (JSON):
      { "password": "Xy!9kP...", "length": 16 }

    Success (201):
      { "message": "Saved.", "id": 7 }
    """
    data     = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()
    length   = data.get("length", len(password))

    if not password:
        return jsonify({"error": "password is required."}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO generated_passwords (user_id, password, length) VALUES (%s, %s, %s)",
                (g.user_id, password, length),
            )
            new_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Saved.", "id": new_id}), 201


# ── GET /api/generator ───────────────────────────────────────
@generator_bp.route("", methods=["GET"])
@jwt_required
def get_history():
    """
    Retrieve the latest 50 generated passwords for the current user.

    Success (200):
      { "history": [ { "id": 7, "password": "...", "length": 16, "created_at": "..." } ] }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, password, length, created_at
                FROM   generated_passwords
                WHERE  user_id = %s
                ORDER  BY created_at DESC
                LIMIT  50
                """,
                (g.user_id,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    history = [
        {
            "id":         r["id"],
            "password":   r["password"],
            "length":     r["length"],
            "created_at": str(r["created_at"]),
        }
        for r in rows
    ]
    return jsonify({"history": history}), 200


# ── DELETE /api/generator ─────────────────────────────────────
@generator_bp.route("", methods=["DELETE"])
@jwt_required
def clear_history():
    """
    Clear all generated-password history for the current user.

    Success (200):
      { "message": "History cleared." }
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM generated_passwords WHERE user_id = %s",
                (g.user_id,),
            )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "History cleared."}), 200
