"""Verify the documented HTTP contract with curl on an isolated local server."""

import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from threading import Thread

from werkzeug.serving import make_server

from secure_api import create_app


def request(base_url, method, path, expected, *, payload=None, token=None):
    args = ["curl", "--silent", "--show-error", "--max-time", "10", "--request", method]
    if payload is not None:
        args += ["--header", "Content-Type: application/json", "--data-binary", json.dumps(payload)]
    if token is not None:
        args += ["--header", f"Authorization: Bearer {token}"]
    args += ["--write-out", "\n%{http_code}", base_url + path]
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=12)
    body, _, status = result.stdout.rpartition("\n")
    if status != str(expected):
        raise RuntimeError(f"{method} {path}: expected HTTP {expected}, received {status}")
    auth = " (with JWT)" if token is not None else ""
    print(f"{method} {path}{auth} -> HTTP {status}")
    return json.loads(body)


def main():
    with tempfile.TemporaryDirectory() as temp:
        app = create_app(
            {"JWT_SECRET": secrets.token_hex(32), "DATABASE": str(Path(temp) / "smoke.sqlite3")}
        )
        server = make_server("127.0.0.1", 0, app)
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            account = {"login": "demo-student", "password": secrets.token_urlsafe(24)}
            request(base_url, "POST", "/auth/register", 201, payload=account)
            login = request(base_url, "POST", "/auth/login", 200, payload=account)
            request(base_url, "GET", "/api/data", 401)
            data = request(base_url, "GET", "/api/data", 200, token=login["access_token"])
            if data["user"]["login"] != account["login"] or len(data["records"]) != 2:
                raise RuntimeError("Unexpected protected response")
        finally:
            server.shutdown()
            worker.join()
            server.server_close()


if __name__ == "__main__":
    main()
