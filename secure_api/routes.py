"""Registration, token issuance, and a protected JSON resource."""

from datetime import datetime, timedelta, timezone

import jwt
from flask import Blueprint, current_app, g, request
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

auth = Blueprint("auth", __name__, url_prefix="/auth")
protected = Blueprint("protected", __name__, url_prefix="/api")

RECORDS = (
    {"id": 1, "title": "HTTP and TLS"},
    {"id": 2, "title": "Password storage"},
)
TOKEN_TTL = timedelta(minutes=15)
AUTH_SCHEME = "Bearer"


def credentials():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"login", "password"}:
        return None

    login = payload["login"]
    password = payload["password"]
    if not isinstance(login, str) or not isinstance(password, str):
        return None
    if not (3 <= len(login) <= 64 and login.isprintable() and login == login.strip()):
        return None
    if not 12 <= len(password) <= 128:
        return None
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return login, password


def public_user(user_id, login):
    return {"id": user_id, "login": str(escape(login))}


@auth.post("/register")
def register():
    values = credentials()
    if values is None:
        return {"error": "invalid_credentials_format"}, 400
    login, password = values
    password_hash = generate_password_hash(password, method=current_app.config["PASSWORD_METHOD"])
    connection = get_db()
    with connection:
        cursor = connection.execute(
            "INSERT INTO users (login, password_hash) VALUES (?, ?) ON CONFLICT(login) DO NOTHING",
            (login, password_hash),
        )
    if cursor.rowcount == 0:
        return {"error": "login_already_exists"}, 409
    return {"user": public_user(cursor.lastrowid, login)}, 201


@auth.post("/login")
def login():
    values = credentials()
    if values is None:
        return {"error": "invalid_credentials_format"}, 400
    username, password = values
    user = get_db().execute(
        "SELECT id, password_hash FROM users WHERE login = ?", (username,)
    ).fetchone()
    password_hash = user["password_hash"] if user is not None else current_app.config["DUMMY_HASH"]
    if not check_password_hash(password_hash, password) or user is None:
        return {"error": "invalid_login_or_password"}, 401

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user["id"]),
            "iss": current_app.config["JWT_ISSUER"],
            "aud": current_app.config["JWT_AUDIENCE"],
            "iat": now,
            "exp": now + TOKEN_TTL,
        },
        current_app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": AUTH_SCHEME, "expires_in": int(TOKEN_TTL.total_seconds())}


def bearer_required():
    return {"error": "authentication_required"}, 401, {"WWW-Authenticate": AUTH_SCHEME}


@protected.before_request
def authenticate():
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != AUTH_SCHEME.lower() or not token or len(token) > 4096:
        return bearer_required()
    try:
        claims = jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=["HS256"],
            issuer=current_app.config["JWT_ISSUER"],
            audience=current_app.config["JWT_AUDIENCE"],
            options={"require": ["sub", "iss", "aud", "iat", "exp"], "strict_aud": True},
        )
    except jwt.InvalidTokenError:
        return bearer_required()
    user = get_db().execute("SELECT id, login FROM users WHERE id = ?", (claims["sub"],)).fetchone()
    if user is None:
        return bearer_required()
    g.user = user
    return None


@protected.get("/data")
def data():
    return {"user": public_user(g.user["id"], g.user["login"]), "records": RECORDS}
