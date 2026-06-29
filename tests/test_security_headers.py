from __future__ import annotations

from tests.helpers import registration_payload


def test_config_response_sets_security_headers_and_csrf_cookie(client):
    response = client.get("/api/config")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert client.cookies.get("sv_csrf")


def test_cookie_mutation_requires_csrf_header(client):
    response = client.post("/api/auth/register", json=registration_payload("admin@example.com"))

    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed"
