"""SQLite access scoped to one application context."""

import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_app(app):
    app.teardown_appcontext(close_db)
    Path(app.config["DATABASE"]).expanduser().parent.mkdir(parents=True, exist_ok=True)
    with app.app_context():
        connection = get_db()
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    login TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
                """
            )
