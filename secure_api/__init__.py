"""Application factory for the laboratory REST API."""

import os
import secrets
from pathlib import Path

from flask import Flask
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from . import db
from .routes import auth, protected

SCRYPT_PARAMETERS = "scrypt:32768:8:3"


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "api.sqlite3")),
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        JWT_ISSUER="infosec-lab-1",
        JWT_AUDIENCE="infosec-lab-1-api",
        MAX_CONTENT_LENGTH=8 * 1024,
    )
    if config is not None:
        app.config.update(config)

    key = app.config["JWT_SECRET"]
    if not isinstance(key, str) or len(key.encode("utf-8")) < 32:
        raise RuntimeError("Set JWT_SECRET to a random value of at least 32 bytes.")

    app.config["DATABASE"] = str(Path(app.config["DATABASE"]).expanduser())
    app.config["PASSWORD_METHOD"] = SCRYPT_PARAMETERS
    app.config["DUMMY_HASH"] = generate_password_hash(
        secrets.token_urlsafe(32), method=SCRYPT_PARAMETERS
    )
    db.init_app(app)
    app.register_blueprint(auth)
    app.register_blueprint(protected)

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.errorhandler(HTTPException)
    def json_http_error(error):
        response = error.get_response()
        response.set_data(app.json.dumps({"error": error.name.lower().replace(" ", "_")}))
        response.mimetype = "application/json"
        return response

    return app
