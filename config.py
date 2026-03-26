"""
config.py — Vaultify configuration
Loads all settings from the .env file via python-dotenv.
"""

import os
from dotenv import load_dotenv

# Load variables from .env (if present) into the environment
load_dotenv()

# ── Database ────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "3306"))
DB_USER     = os.getenv("DB_USER",     "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "jana")
DB_NAME     = os.getenv("DB_NAME",     "vaultify")

# ── JWT ─────────────────────────────────────────────────────
JWT_SECRET_KEY  = os.getenv("JWT_SECRET_KEY", "dev_secret_change_me")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

# ── Fernet (AES encryption for stored passwords) ─────────────
FERNET_KEY = os.getenv("FERNET_KEY", "")

# ── Flask ───────────────────────────────────────────────────
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"
