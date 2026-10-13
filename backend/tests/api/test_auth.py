"""
Tests for authentication (JWT) and authorization (roles).
"""

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
import jwt
from starlette.websockets import WebSocketDisconnect

from app.api.websocket import manager
from app.core.config import settings
from app.core.security import create_access_token
from app.main import app
from app.models.user import User

from tests.conftest import TEST_PASSWORD, create_user

PUBLIC_ROUTES = {"/", "/health", "/auth/login"}


def _protected_routes():
    """Every HTTP route of the app except the public ones.

    Routes are read from the OpenAPI schema (public API, the source of /docs)
    rather than from app.routes, whose structure differs between FastAPI versions.
    """
    for path, operations in app.openapi()["paths"].items():
        if path in PUBLIC_ROUTES:
            continue
        for method in operations:
            # Fill path parameters such as {scan_id} with a dummy value
            yield method.upper(), re.sub(r"\{[^}]+\}", "x", path)


class TestEveryRouteRequiresAuth:

    @pytest.mark.parametrize("method, path", sorted(_protected_routes()))
    def test_returns_401_without_token(self, anon_client: TestClient, method, path):
        response = anon_client.request(method, path)

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_route_list_is_not_empty(self):
        # Guard: if route discovery broke, the parametrized test above would run 0 times
        assert len(list(_protected_routes())) > 20

    def test_public_routes_need_no_token(self, anon_client: TestClient):
        assert anon_client.get("/health").status_code == 200
        assert anon_client.get("/").status_code == 200


class TestLogin:

    def test_valid_credentials_return_a_working_token(self, anon_client: TestClient, test_db):
        create_user(test_db, "alice", "analyst")

        response = anon_client.post("/auth/login", json={"username": "alice", "password": TEST_PASSWORD})

        assert response.status_code == 200
        token = response.json()["access_token"]
        me = anon_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.json()["username"] == "alice"
        assert "hashed_password" not in me.json()

    def test_login_records_last_login(self, anon_client: TestClient, test_db):
        user = create_user(test_db, "alice", "analyst")

        anon_client.post("/auth/login", json={"username": "alice", "password": TEST_PASSWORD})

        test_db.refresh(user)
        assert user.last_login is not None

    def test_wrong_password_and_unknown_user_get_the_same_error(self, anon_client: TestClient, test_db):
        create_user(test_db, "alice", "analyst")

        wrong_pw = anon_client.post("/auth/login", json={"username": "alice", "password": "nope-nope-nope"})
        unknown = anon_client.post("/auth/login", json={"username": "bob", "password": "nope-nope-nope"})

        assert wrong_pw.status_code == unknown.status_code == 401
        assert wrong_pw.json() == unknown.json()

    def test_inactive_user_cannot_log_in(self, anon_client: TestClient, test_db):
        create_user(test_db, "alice", "analyst", is_active=False)

        response = anon_client.post("/auth/login", json={"username": "alice", "password": TEST_PASSWORD})

        assert response.status_code == 403


class TestTokenValidation:

    def _get_me(self, anon_client, token):
        return anon_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    def test_expired_token_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        token = create_access_token(user.id, expires_delta=timedelta(seconds=-1))

        assert self._get_me(anon_client, token).status_code == 401

    def test_token_signed_with_another_secret_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        forged = jwt.encode({"sub": user.id}, "attacker-secret", algorithm="HS256")

        assert self._get_me(anon_client, forged).status_code == 401

    def test_unsigned_alg_none_token_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        # header {"alg":"none"} + payload + empty signature
        import base64, json
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        unsigned = f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"sub": user.id})}.'

        assert self._get_me(anon_client, unsigned).status_code == 401

    def test_token_without_expiry_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        no_exp = jwt.encode({"sub": user.id}, settings.JWT_SECRET, algorithm="HS256")

        assert self._get_me(anon_client, no_exp).status_code == 401

    def test_garbage_token_is_rejected(self, anon_client):
        assert self._get_me(anon_client, "not-a-jwt").status_code == 401

    def test_token_of_deactivated_user_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        token = create_access_token(user.id)
        user.is_active = False
        test_db.commit()

        assert self._get_me(anon_client, token).status_code == 401

    def test_token_of_deleted_user_is_rejected(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")
        token = create_access_token(user.id)
        test_db.delete(user)
        test_db.commit()

        assert self._get_me(anon_client, token).status_code == 401

    def test_token_contains_only_user_id_and_expiry(self, test_db):
        user = create_user(test_db, "alice", "analyst")
        claims = jwt.decode(create_access_token(user.id), settings.JWT_SECRET,
                            algorithms=["HS256"])

        assert set(claims) == {"sub", "exp"}


class TestRoles:

    NEW_USER = {"username": "carol", "email": "carol@example.com", "password": "a-long-password"}

    def test_admin_can_create_user(self, admin_client: TestClient, test_db):
        response = admin_client.post("/auth/users", json=self.NEW_USER)

        assert response.status_code == 201
        assert response.json()["role"] == "analyst"
        stored = test_db.query(User).filter(User.username == "carol").one()
        assert stored.hashed_password != self.NEW_USER["password"]
        assert stored.hashed_password.startswith("$2b$")      # bcrypt

    def test_analyst_cannot_create_user(self, client: TestClient):
        assert client.post("/auth/users", json=self.NEW_USER).status_code == 403

    def test_duplicate_username_is_rejected(self, admin_client: TestClient):
        admin_client.post("/auth/users", json=self.NEW_USER)

        assert admin_client.post("/auth/users", json=self.NEW_USER).status_code == 409

    @pytest.mark.parametrize("field, value", [
        ("password", "short"),                       # < 10 characters
        ("password", "é" * 40),                      # 80 bytes > bcrypt's 72-byte limit
        ("username", "ab"),                          # too short
        ("username", "bad name!"),                   # invalid characters
        ("email", "not-an-email"),
        ("role", "superuser"),                       # unknown role
    ])
    def test_invalid_input_is_rejected(self, admin_client: TestClient, field, value):
        response = admin_client.post("/auth/users", json={**self.NEW_USER, field: value})

        assert response.status_code == 422

    def test_only_admin_can_delete_scans(self, client: TestClient, admin_client: TestClient, test_db):
        from app.models.scan import ScanSession
        scan = ScanSession(type="domain", target="example.com")
        test_db.add(scan)
        test_db.commit()

        assert client.delete(f"/results/{scan.id}").status_code == 403
        assert admin_client.delete(f"/results/{scan.id}").status_code == 200


class TestWebSocketAuth:

    def _close_code(self, anon_client, first_message):
        with anon_client.websocket_connect("/ws/scan-1") as ws:
            ws.send_json(first_message)
            with pytest.raises(WebSocketDisconnect) as closed:
                ws.receive_json()
        return closed.value.code

    def test_missing_auth_message_closes_with_1008(self, anon_client):
        assert self._close_code(anon_client, {"type": "hello"}) == 1008

    def test_invalid_token_closes_with_1008(self, anon_client):
        assert self._close_code(anon_client, {"type": "auth", "token": "not-a-jwt"}) == 1008

    def test_valid_token_subscribes_to_scan_events(self, anon_client, test_db):
        user = create_user(test_db, "alice", "analyst")

        with anon_client.websocket_connect("/ws/scan-1") as ws:
            ws.send_json({"type": "auth", "token": create_access_token(user.id)})

            assert ws.receive_json() == {"type": "auth_ok"}
            assert manager.has_listeners("scan-1")
