from __future__ import annotations

from tests.helpers import csrf_headers, encrypted_blob, login_user, register_user


def test_user_cannot_modify_another_users_personal_item(make_client):
    owner = make_client()
    attacker = make_client()
    assert register_user(owner, "owner@example.com").status_code == 201
    assert login_user(owner, "owner@example.com").status_code == 200
    assert register_user(attacker, "attacker@example.com").status_code == 201
    assert login_user(attacker, "attacker@example.com").status_code == 200

    created = owner.post(
        "/api/items",
        headers=csrf_headers(owner),
        json={"encryptedPayload": encrypted_blob()},
    )
    assert created.status_code == 201

    deleted = attacker.delete(f"/api/items/{created.json()['id']}", headers=csrf_headers(attacker))

    assert deleted.status_code == 403


def test_non_admin_cannot_use_admin_api(make_client):
    admin = make_client()
    user = make_client()
    assert register_user(admin, "admin@example.com").status_code == 201
    assert register_user(user, "user@example.com").status_code == 201
    assert login_user(user, "user@example.com").status_code == 200

    response = user.get("/api/admin/stats")

    assert response.status_code == 403


def test_admin_can_disable_registration(client):
    assert register_user(client, "admin@example.com").status_code == 201
    assert login_user(client, "admin@example.com").status_code == 200

    update = client.put(
        "/api/admin/settings",
        headers=csrf_headers(client),
        json={"registrationEnabled": False},
    )
    denied = client.post(
        "/api/auth/register",
        headers=csrf_headers(client),
        json={
            "email": "new@example.com",
            "displayName": "new",
            "authHash": "a" * 64,
            "kdfSalt": "b" * 16,
            "kdfIterations": 200000,
            "publicKey": "c" * 96,
            "encryptedPrivateKey": {"alg": "AES-GCM", "iv": "iv", "ct": "ct"},
        },
    )

    assert update.status_code == 200
    assert denied.status_code == 403
