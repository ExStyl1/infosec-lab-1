import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

from secure_api import create_app
from secure_api.db import get_db


class RestApiTests(unittest.TestCase):
    credentials = {"login": "Лаборатория '5 & <6", "password": "synthetic demonstration phrase"}

    @classmethod
    def setUpClass(cls):
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.app = create_app(
            {"TESTING": True, "DATABASE": str(Path(folder.name) / "tests.sqlite3"), "JWT_SECRET": "a" * 64}
        )

    def setUp(self):
        with self.app.app_context(), get_db() as db:
            db.execute("DELETE FROM users")
        self.client = self.app.test_client()

    def register(self):
        return self.client.post("/auth/register", json=self.credentials)

    def token(self):
        self.assertEqual(self.register().status_code, 201)
        response = self.client.post("/auth/login", json=self.credentials)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["expires_in"], 900)
        return response.json["access_token"]

    def test_register_stores_a_scrypt_hash_and_handles_duplicates(self):
        created = self.register()
        self.assertEqual(created.status_code, 201)
        self.assertIn("&amp;", created.json["user"]["login"])
        self.assertIn("&#39;", created.json["user"]["login"])
        self.assertNotIn("password", created.json)
        with self.app.app_context():
            row = get_db().execute("SELECT login, password_hash FROM users").fetchone()
            self.assertEqual(row["login"], self.credentials["login"])
            self.assertTrue(row["password_hash"].startswith("scrypt:32768:8:3$"))
            self.assertNotIn(self.credentials["password"], row["password_hash"])
        self.assertEqual(self.register().status_code, 409)

    def test_login_rejects_wrong_password_and_unknown_login_equally(self):
        self.register()
        wrong = self.client.post("/auth/login", json={**self.credentials, "password": "different password"})
        absent = self.client.post("/auth/login", json={**self.credentials, "login": "Unknown"})
        self.assertEqual((wrong.status_code, wrong.json), (absent.status_code, absent.json))
        self.assertEqual(wrong.status_code, 401)

    def test_protected_resources_require_a_bearer_token(self):
        no_token = self.client.get("/api/data")
        self.assertEqual(no_token.status_code, 401)
        self.assertEqual(no_token.headers["WWW-Authenticate"], "Bearer")
        invalid = self.client.get("/api/data", headers={"Authorization": "Bearer not-a-jwt"})
        self.assertEqual(invalid.status_code, 401)

    def test_valid_token_returns_json_with_escaped_login_and_security_headers(self):
        token = self.token()
        response = self.client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("&lt;6", response.json["user"]["login"])
        self.assertEqual(len(response.json["records"]), 2)

    def test_expired_token_is_rejected(self):
        self.assertEqual(self.register().status_code, 201)
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": "1",
                "iss": self.app.config["JWT_ISSUER"],
                "aud": self.app.config["JWT_AUDIENCE"],
                "iat": now - timedelta(minutes=16),
                "exp": now - timedelta(minutes=1),
            },
            self.app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        response = self.client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 401)

    def test_malformed_json_and_oversized_body_have_json_errors(self):
        malformed = self.client.post("/auth/register", content_type="application/json", data="{")
        self.assertEqual(malformed.status_code, 400)
        too_big = self.client.post("/auth/register", json={**self.credentials, "password": "p" * 9000})
        self.assertEqual(too_big.status_code, 413)
        self.assertEqual(too_big.mimetype, "application/json")
