import base64
import hashlib
import json
from pathlib import Path
import sys
import time
import ssl
from urllib.parse import parse_qs, urlsplit

import httpx
import certifi
from itsdangerous import TimestampSigner
from joserfc import jwt
from joserfc.jwk import RSAKey
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from infrasec.backend import create_app as create_backend
from infrasec.settings import WebSettings
from infrasec.web import create_app, oidc_client


@pytest.fixture
def system(tmp_path):
    front_file = tmp_path / "frontend.json"
    back_file = tmp_path / "backend.json"
    values = {"session_secret": "unit-test-session-" + "a" * 32,
              "oidc_client_secret": "unit-test-oidc-value", "backend_api_key": "unit-test-api-value"}
    front_file.write_text(json.dumps(values))
    back_file.write_text(json.dumps({"api_key": values["backend_api_key"]}))
    settings = WebSettings(front_file, "https://login.example/realms/infrasec",
                           "https://keycloak.internal/realms/infrasec", "infrasec-web",
                           "http://testserver", "http://backend")
    backend = create_backend(back_file)
    app = create_app(settings)
    app.state.backend_transport = httpx.ASGITransport(app=backend)
    key = RSAKey.generate_key(2048, parameters={"kid": "unit-test-key"})
    flow = {"claims_override": {}, "token_requests": 0}

    def oidc_response(request):
        if request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [key.as_dict(private=False)]})
        if request.url.path.endswith("/token"):
            flow["token_requests"] += 1
            form = parse_qs(request.content.decode())
            verifier = form["code_verifier"][0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            assert challenge == flow["challenge"]
            assert form["redirect_uri"] == ["http://testserver/auth/callback"]
            assert request.url.host == "keycloak.internal"
            assert request.headers["authorization"].startswith("Basic ")
            now = int(time.time())
            claims = {"sub": "ldap-user-id", "preferred_username": "student",
                      "name": "Учебный пользователь", "iss": settings.keycloak_public_url,
                      "aud": settings.client_id, "iat": now, "exp": now + 300, "nonce": flow["nonce"]}
            claims.update(flow["claims_override"])
            signing_key = flow.get("signing_key", key)
            identity = jwt.encode({"alg": "RS256", "kid": "unit-test-key"}, claims, signing_key)
            return httpx.Response(200, json={"access_token": "unit-test-access-value", "token_type": "Bearer",
                                             "id_token": identity, "expires_in": 300})
        raise AssertionError("Неожиданный запрос OIDC")

    def client_factory(config):
        client = oidc_client(settings, config)
        client.client_kwargs["transport"] = httpx.MockTransport(oidc_response)
        return client

    app.state.oidc_factory = client_factory
    return app, backend, values, front_file, back_file, flow


def begin_login(client, flow):
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    authorization = urlsplit(response.headers["location"])
    assert authorization.hostname == "login.example"
    query = parse_qs(authorization.query)
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["infrasec-web"]
    assert query["code_challenge_method"] == ["S256"]
    flow["nonce"] = query["nonce"][0]
    flow["challenge"] = query["code_challenge"][0]
    return query["state"][0]


def complete_login(client, flow):
    state = begin_login(client, flow)
    return client.get("/auth/callback", params={"code": "unit-test-code", "state": state}, follow_redirects=False)


def test_backend_denies_missing_and_wrong_key(system):
    _, backend, values, _, _, _ = system
    client = TestClient(backend)
    assert client.get("/data").status_code == 401
    assert client.get("/data", headers={"X-API-Key": "wrong"}).status_code == 401
    response = client.get("/data", headers={"X-API-Key": values["backend_api_key"]})
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert values["backend_api_key"] not in response.text


def test_backend_reads_rotated_key_without_restart(system):
    _, backend, values, _, back_file, _ = system
    client = TestClient(backend)
    assert client.get("/data", headers={"X-API-Key": values["backend_api_key"]}).status_code == 200
    back_file.write_text(json.dumps({"api_key": "unit-test-replacement"}))
    assert client.get("/data", headers={"X-API-Key": values["backend_api_key"]}).status_code == 401
    assert client.get("/data", headers={"X-API-Key": "unit-test-replacement"}).status_code == 200


def test_frontend_protected_routes_require_login(system):
    app, *_ = system
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert "Войти через Keycloak" in client.get("/").text
    assert client.get("/api/data").status_code == 401
    assert client.get("/profile").status_code == 401


def test_real_oidc_validation_pkce_and_service_call(system):
    app, _, values, _, _, flow = system
    client = TestClient(app)
    response = complete_login(client, flow)
    assert response.status_code == 303
    assert client.get("/api/data").json()["backend"]["authenticated"] is True
    assert "Пользователь LDAP" in client.get("/profile").text
    assert flow["token_requests"] == 1
    cookie = client.cookies["infrasec_session"]
    session = json.loads(base64.b64decode(TimestampSigner(values["session_secret"]).unsign(cookie)))
    assert session == {"user": {"sub": "ldap-user-id", "username": "student", "name": "Учебный пользователь"}}
    assert "unit-test-access-value" not in json.dumps(session)
    assert values["oidc_client_secret"] not in json.dumps(session)
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=lax" in response.headers["set-cookie"].lower()
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("claim,value", [
    ("iss", "https://another.example/realms/other"),
    ("aud", "another-client"),
    ("nonce", "another-nonce"),
    ("exp", 1),
])
def test_wrong_oidc_claims_are_rejected(system, claim, value):
    app, _, _, _, _, flow = system
    flow["claims_override"] = {claim: value}
    client = TestClient(app)
    assert complete_login(client, flow).status_code == 400
    assert client.get("/api/data").status_code == 401


def test_invalid_oidc_signature_is_rejected(system):
    app, _, _, _, _, flow = system
    flow["signing_key"] = RSAKey.generate_key(2048, parameters={"kid": "unit-test-key"})
    client = TestClient(app)
    assert complete_login(client, flow).status_code == 400
    assert client.get("/api/data").status_code == 401


def test_wrong_state_is_rejected_before_token_request(system):
    app, _, _, _, _, flow = system
    client = TestClient(app)
    begin_login(client, flow)
    response = client.get("/auth/callback?code=unit-test-code&state=wrong", follow_redirects=False)
    assert response.status_code == 400
    assert flow["token_requests"] == 0
    assert client.get("/api/data").status_code == 401


def test_cookie_tampering_and_session_key_rotation_remove_login(system):
    app, _, values, front_file, _, flow = system
    client = TestClient(app)
    assert complete_login(client, flow).status_code == 303
    cookie = client.cookies["infrasec_session"]
    forged = cookie[:-3] + "xyz"
    assert client.get("/api/data", headers={"Cookie": "infrasec_session=" + forged}).status_code == 401
    assert client.get("/api/data").status_code == 200
    front_file.write_text(json.dumps({**values, "session_secret": "unit-test-replacement-" + "b" * 32}))
    assert client.get("/api/data").status_code == 401


def test_frontend_and_backend_read_rotated_service_key(system):
    app, _, values, front_file, back_file, flow = system
    client = TestClient(app)
    assert complete_login(client, flow).status_code == 303
    front_file.write_text(json.dumps({**values, "backend_api_key": "unit-test-next-service-key"}))
    back_file.write_text(json.dumps({"api_key": "unit-test-next-service-key"}))
    response = client.get("/api/data")
    assert response.status_code == 200
    assert "unit-test-next-service-key" not in response.text


def test_secret_file_errors_do_not_reveal_values_or_paths(system):
    app, backend, values, front_file, back_file, _ = system
    front_file.write_text("not-json")
    back_file.unlink()
    for application in (app, backend):
        response = TestClient(application).get("/health")
        assert response.status_code == 503
        assert str(front_file.parent) not in response.text
        assert all(value not in response.text for value in values.values())


def test_user_text_is_escaped_in_html_and_logout_clears_session(system):
    app, _, _, _, _, flow = system
    flow["claims_override"] = {"preferred_username": "<script>alert(1)</script>"}
    client = TestClient(app)
    assert complete_login(client, flow).status_code == 303
    response = client.get("/")
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert client.post("/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/logout", headers={"Origin": "http://testserver"}, follow_redirects=False).status_code == 303
    assert client.get("/api/data").status_code == 401


def test_tls_ca_comes_from_environment_and_is_verified(system, monkeypatch):
    _, _, values, front_file, _, _ = system
    monkeypatch.setenv("KEYCLOAK_PUBLIC_URL", "http://127.0.0.1:18081/realms/infrasec")
    monkeypatch.setenv("KEYCLOAK_INTERNAL_URL", "https://keycloak.internal/realms/infrasec")
    monkeypatch.setenv("VAULT_CONFIG_FILE", str(front_file))
    monkeypatch.setenv("SSL_CERT_FILE", certifi.where())
    monkeypatch.delenv("KEYCLOAK_CA_FILE", raising=False)
    settings = WebSettings.from_env()
    assert settings.keycloak_ca_file == certifi.where()
    verification = oidc_client(settings, values).client_kwargs["verify"]
    assert verification.verify_mode == ssl.CERT_REQUIRED
    assert verification.check_hostname is True


def test_https_app_sets_secure_cookie(system):
    _, _, _, front_file, _, _ = system
    settings = WebSettings(front_file, "https://login.example/realms/infrasec",
                           "https://keycloak.internal/realms/infrasec", "infrasec-web",
                           "https://frontend.example", "http://backend")
    client = TestClient(create_app(settings), base_url="https://frontend.example")
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    assert "secure" in response.headers["set-cookie"].lower()
