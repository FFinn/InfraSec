"""HTTPX должен учитывать безопасный loopback-контекст Keycloak, сохраняя Secure."""
import base64
from http.cookies import SimpleCookie
import importlib.util
import json
from pathlib import Path
import sys
import time

import httpx
from itsdangerous import TimestampSigner
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("infrasec_verifier", ROOT / "scripts/verify_integration.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@pytest.mark.parametrize("keycloak,should_succeed,clock_skew", [
    ("http://127.0.0.1:18081", True, 0),
    ("http://127.0.0.1:18081", True, 3),
    ("http://keycloak.example:18081", False, 0),
    ("https://keycloak.example", True, 0),
])
def test_oidc_secure_cookie_is_supported_only_for_https_or_explicit_loopback(monkeypatch, keycloak, should_succeed, clock_skew):
    frontend = "http://127.0.0.1:18080"
    values = {"frontend": {"session_secret": "unit-test-session-" + "a" * 32,
                            "backend_api_key": "unit-test-api", "oidc_client_secret": "unit-test-client"}}
    identity = {"users": {"alice": {"username": "alice", "password": "unit-test-password"}}}
    session = base64.b64encode(json.dumps({"user": {"sub": "unit-subject", "username": "alice", "name": "Alice"}}).encode())
    signer = TimestampSigner(values["frontend"]["session_secret"])
    signer.get_timestamp = lambda: int(time.time()) + clock_skew
    signed = signer.sign(session).decode()
    state = {"authenticated": False, "keycloak_cookie_sent": False}
    clients = []

    def respond(request):
        path = request.url.path
        if verifier.origin(str(request.url)) == verifier.origin(keycloak):
            if path.endswith("/auth"):
                form = '<form method="post" action="/realms/infrasec/login-actions/authenticate"><input name="username"><input name="password" type="password"></form>'
                return httpx.Response(200, text=form, headers={"set-cookie": "AUTH_SESSION_ID=unit-test-auth-session; Path=/realms/infrasec/; Secure; HttpOnly; SameSite=None"})
            if path.endswith("/authenticate"):
                incoming = SimpleCookie()
                incoming.load(request.headers.get("cookie", ""))
                state["keycloak_cookie_sent"] = "AUTH_SESSION_ID" in incoming
                if not state["keycloak_cookie_sent"]:
                    return httpx.Response(400, text="Cookie not found")
                return httpx.Response(302, headers={"location": frontend + "/auth/callback?code=unit-test-code&state=unit-test-state"})
        if path == "/login":
            return httpx.Response(302, headers={"location": keycloak + "/realms/infrasec/protocol/openid-connect/auth"})
        if path == "/auth/callback":
            state["authenticated"] = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "infrasec_session=" + signed + "; Path=/; HttpOnly; SameSite=Lax"})
        if path == "/":
            return httpx.Response(200, text="Вход выполнен")
        if path == "/profile":
            return httpx.Response(200, text="alice")
        if path == "/api/data":
            return httpx.Response(200, json={"user": {"username": "alice"}, "backend": {"authenticated": True}}) if state["authenticated"] else httpx.Response(401)
        if path == "/logout":
            state["authenticated"] = False
            return httpx.Response(303, headers={"location": "/"})
        raise AssertionError("Неожиданный тестовый запрос")

    original = httpx.Client

    def make_client(**kwargs):
        client = original(transport=httpx.MockTransport(respond), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(verifier.httpx, "Client", make_client)
    if should_succeed:
        assert verifier.oidc_login(frontend, keycloak, identity, values, "alice")["login_completed"]
    else:
        with pytest.raises(verifier.SafeError):
            verifier.oidc_login(frontend, keycloak, identity, values, "alice")
    assert state["keycloak_cookie_sent"] is should_succeed
    stored = [cookie for client in clients for cookie in client.cookies.jar if cookie.name == "AUTH_SESSION_ID"]
    assert stored and all(cookie.secure for cookie in stored)
