from __future__ import annotations

from tests.helpers import csrf_headers, login_user, register_user


def test_first_registered_user_is_admin_and_can_login(client):
    response = register_user(client, "admin@example.com")

    assert response.status_code == 201
    assert response.json()["isAdmin"] is True

    login = login_user(client, "admin@example.com")

    assert login.status_code == 200
    assert login.json()["user"]["isAdmin"] is True
    assert client.get("/api/me").status_code == 200


def test_logout_revokes_existing_session_token(client):
    assert register_user(client, "admin@example.com").status_code == 201
    assert login_user(client, "admin@example.com").status_code == 200
    token = client.cookies.get("sv_session")

    logout = client.post("/api/auth/logout", headers=csrf_headers(client))

    assert logout.status_code == 200
    assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
