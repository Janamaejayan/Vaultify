"""
db.py — Vaultify database helpers
Provides a get_db() function that returns a PyMySQL connection.
Each request opens a connection and closes it when done.
Parameterized queries are used everywhere to prevent SQL injection.
"""

import pymysql
import pymysql.cursors
import config


def get_db() -> pymysql.connections.Connection:
    """
    Open and return a new PyMySQL database connection.
    Uses DictCursor so rows come back as plain Python dicts.
    Caller is responsible for closing the connection (use with 'with' or try/finally).
    """
    connection = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )
    return connection
