"""
routes/password_routes.py — Password CRUD Blueprint
All endpoints require a valid JWT in the Authorization header.

Endpoints:
  POST   /api/passwords          — Encrypt & save a new password entry
  GET    /api/passwords          — Retrieve & decrypt all entries for the user
  PUT    /api/passwords/<int:id> — Update an existing entry
  DELETE /api/passwords/<int:id> — Delete an entry

JWT middleware:
  Every route is wrapped with @jwt_required, a decorator defined
  in this file that extracts and verifies the token, then injects
  the current user_id into Flask's g object.
"""

from functools import wraps

import jwt as pyjwt
from flask import Blueprint, request, jsonify, g

from db import get_db
from utils.auth import decode_token
from utils.crypto import encrypt_password, decrypt_password

passwords_bp = Blueprint("passwords", __name__)


# ── JWT Required Decorator ───────────────────────────────────
def jwt_required(f):
    """
    Decorator that validates the Bearer token from the Authorization header.
    On success, sets g.user_id, g.username, and g.session_id for use in the route.
    Also checks whether the session has been revoked in the DB.
    On failure, returns 401 Unauthorized.
    """
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

        # ── Session revocation check ─────────────────────────
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


# ── POST /api/passwords ──────────────────────────────────────
@passwords_bp.route("", methods=["POST"])
@jwt_required
def add_password():
    """
    Encrypt and store a new password entry.

    Request body (JSON):
      { "site": "Google", "site_username": "alice@gmail.com", "password": "G00gle@123" }

    Success (201):
      { "message": "Password saved.", "id": 5 }
    """
    data = request.get_json(silent=True) or {}
    site          = (data.get("site")          or "").strip()
    site_username = (data.get("site_username") or "").strip()
    plain_pw      = (data.get("password")      or "").strip()

    if not site or not site_username or not plain_pw:
        return jsonify({"error": "site, site_username, and password are required."}), 400

    encrypted = encrypt_password(plain_pw)

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO passwords (user_id, site, site_username, encrypted_password)
                VALUES (%s, %s, %s, %s)
                """,
                (g.user_id, site, site_username, encrypted),
            )
            new_id = cursor.lastrowid
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Password saved.", "id": new_id}), 201


# ── GET /api/passwords ───────────────────────────────────────
@passwords_bp.route("", methods=["GET"])
@jwt_required
def get_passwords():
    """
    Retrieve and decrypt all password entries belonging to the logged-in user.

    Success (200):
      {
        "passwords": [
          { "id": 1, "site": "Google", "site_username": "alice@gmail.com",
            "password": "G00gle@123", "created_at": "...", "updated_at": "..." }
        ]
      }
    """
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, site, site_username, encrypted_password,
                       created_at, updated_at
                FROM   passwords
                WHERE  user_id = %s
                ORDER  BY created_at DESC
                """,
                (g.user_id,),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    # Decrypt each stored password before sending to the client
    results = []
    for row in rows:
        results.append({
            "id":            row["id"],
            "site":          row["site"],
            "site_username": row["site_username"],
            "password":      decrypt_password(row["encrypted_password"]),
            "created_at":    str(row["created_at"]),
            "updated_at":    str(row["updated_at"]),
        })

    return jsonify({"passwords": results}), 200


# ── PUT /api/passwords/<id> ──────────────────────────────────
@passwords_bp.route("/<int:entry_id>", methods=["PUT"])
@jwt_required
def update_password(entry_id):
    """
    Update an existing password entry.
    Only the owner (matched by user_id) can update their entries.

    Request body (JSON) — all fields optional:
      { "site": "NewSite", "site_username": "new@email.com", "password": "NewP@ss!" }

    Success (200):
      { "message": "Entry updated." }
    """
    data = request.get_json(silent=True) or {}

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # Fetch the existing row (ownership check)
            cursor.execute(
                "SELECT id, site, site_username, encrypted_password "
                "FROM passwords WHERE id = %s AND user_id = %s",
                (entry_id, g.user_id),
            )
            existing = cursor.fetchone()
            if not existing:
                return jsonify({"error": "Entry not found."}), 404

            # Apply updates — fall back to existing values if not provided
            site          = (data.get("site")          or "").strip() or existing["site"]
            site_username = (data.get("site_username") or "").strip() or existing["site_username"]
            plain_pw      = (data.get("password")      or "").strip()
            encrypted     = encrypt_password(plain_pw) if plain_pw else existing["encrypted_password"]

            cursor.execute(
                """
                UPDATE passwords
                SET    site = %s, site_username = %s, encrypted_password = %s
                WHERE  id = %s AND user_id = %s
                """,
                (site, site_username, encrypted, entry_id, g.user_id),
            )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"message": "Entry updated."}), 200


# ── DELETE /api/passwords/<id> ───────────────────────────────
@passwords_bp.route("/<int:entry_id>", methods=["DELETE"])
@jwt_required
def delete_password(entry_id):
    """
    Delete a password entry (ownership enforced via user_id).

    Success (200):
      { "message": "Entry deleted." }

    Errors:
      404 — Entry not found or not owned by user
    """
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM passwords WHERE id = %s AND user_id = %s",
                (entry_id, g.user_id),
            )
            affected = cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    if affected == 0:
        return jsonify({"error": "Entry not found."}), 404

    return jsonify({"message": "Entry deleted."}), 200
