"""
app.py — Vaultify Flask Application Entry Point
Creates the Flask app, registers Blueprints, enables CORS,
and adds global error handlers.

Run:
  python app.py
"""

from flask import Flask, jsonify
from flask_cors import CORS

from routes.auth_routes import auth_bp
from routes.password_routes import passwords_bp
import config


def create_app() -> Flask:
    """
    Application factory — creates and configures the Flask app.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.JWT_SECRET_KEY

    # ── CORS ─────────────────────────────────────────────────
    # Allow the frontend (served as a local file or dev server) to
    # reach the API.  In production, restrict origins to your domain.
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ── Blueprints ───────────────────────────────────────────
    app.register_blueprint(auth_bp,      url_prefix="/api/auth")
    app.register_blueprint(passwords_bp, url_prefix="/api/passwords")

    # ── Global error handlers ────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error."}), 500

    # ── Health check ─────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "Vaultify API"}), 200

    return app


# ── Entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=config.FLASK_DEBUG,
    )
