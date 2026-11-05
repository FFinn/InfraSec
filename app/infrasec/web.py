"""Вход через Keycloak и обращение к внутреннему сервису после проверки OIDC."""
from html import escape
import logging
import ssl

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException, Request
import httpx
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, RedirectResponse

from .common import ConfigurationUnavailable, SecurityHeadersMiddleware, read_config, unavailable_response
from .settings import WebSettings

LOGGER = logging.getLogger("infrasec.auth")
FIELDS = ("oidc_client_secret", "session_secret", "backend_api_key")


def configuration(settings: WebSettings):
    values = read_config(settings.config_file, FIELDS)
    if len(values["session_secret"]) < 32:
        raise ConfigurationUnavailable
    return values


class VaultSessionMiddleware:
    """Смена ключа в файле Vault сбрасывает ранее подписанные сеансы."""
    def __init__(self, app, settings: WebSettings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        try:
            secret = configuration(self.settings)["session_secret"]
        except ConfigurationUnavailable:
            await unavailable_response()(scope, receive, send)
            return
        middleware = SessionMiddleware(self.app, secret_key=secret, session_cookie="infrasec_session",
                                       max_age=900, same_site="lax",
                                       https_only=self.settings.public_url.startswith("https://"))
        await middleware(scope, receive, send)


def oidc_client(settings: WebSettings, values: dict[str, str]):
    oauth = OAuth()
    verification = ssl.create_default_context(cafile=settings.keycloak_ca_file) if settings.keycloak_ca_file else True
    public = settings.keycloak_public_url + "/protocol/openid-connect"
    internal = settings.keycloak_internal_url + "/protocol/openid-connect"
    oauth.register(
        "keycloak", client_id=settings.client_id, client_secret=values["oidc_client_secret"],
        authorize_url=public + "/auth", access_token_url=internal + "/token",
        jwks_uri=internal + "/certs", issuer=settings.keycloak_public_url,
        id_token_signing_alg_values_supported=["RS256"],
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256",
                       "token_endpoint_auth_method": "client_secret_basic",
                       "timeout": 10, "trust_env": False, "verify": verification},
    )
    return oauth.create_client("keycloak")


def page(title: str, body: str, status: int = 200):
    return HTMLResponse("<!doctype html><html lang='ru'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>InfraSec — " + escape(title) + "</title><style>"
        "body{font:18px system-ui;background:#f4f7f8;color:#19312b;max-width:820px;margin:8vh auto;padding:24px}"
        "main{background:white;padding:36px;border:1px solid #dbe5e1;border-radius:16px}"
        "a,button{color:#145c42}h1{font-size:30px}p{line-height:1.6}"
        "a{display:inline-block;margin:10px 18px 10px 0}button{font:inherit;background:none;border:0;padding:0;cursor:pointer}"
        "</style><main><p>Учебное приложение InfraSec</p><h1>" + escape(title) + "</h1>" + body + "</main></html>",
        status_code=status)


def user_from_session(request: Request):
    user = request.session.get("user")
    if not isinstance(user, dict) or not user.get("sub"):
        raise HTTPException(status_code=401, detail="Необходимо войти через Keycloak")
    return user


def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or WebSettings.from_env()
    app = FastAPI(title="Приложение InfraSec", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(VaultSessionMiddleware, settings=settings)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.oidc_factory = lambda values: oidc_client(settings, values)
    app.state.backend_transport = None

    @app.exception_handler(ConfigurationUnavailable)
    async def configuration_error(request, exc):
        return unavailable_response()

    @app.get("/health")
    async def health():
        configuration(settings)
        return {"status": "ok", "service": "frontend", "config_loaded": True}

    @app.get("/")
    async def index(request: Request):
        user = request.session.get("user")
        if user:
            username = escape(str(user.get("username", "Пользователь")))
            return page("Вход выполнен", f"<p>Пользователь: <strong>{username}</strong></p>"
                        "<p>Учётная запись подтверждена Keycloak.</p>"
                        "<a href='/profile'>Проверить защищённый сервис</a>"
                        "<form action='/logout' method='post'><button type='submit'>Выйти из приложения</button></form>")
        return page("Вход в приложение", "<p>Для доступа к внутреннему сервису войдите с учебной учётной записью LDAP.</p>"
                    "<a href='/login'>Войти через Keycloak</a>")

    @app.get("/login")
    async def login(request: Request):
        request.session.clear()
        client = app.state.oidc_factory(configuration(settings))
        return await client.authorize_redirect(request, settings.public_url + "/auth/callback")

    @app.get("/auth/callback")
    async def callback(request: Request):
        try:
            client = app.state.oidc_factory(configuration(settings))
            token = await client.authorize_access_token(request, claims_options={
                "iss": {"essential": True, "value": settings.keycloak_public_url},
                "aud": {"essential": True, "value": settings.client_id},
            })
            # Authlib проверяет подпись, issuer, audience, nonce и state до возврата userinfo.
            user = token.get("userinfo")
            if not token.get("id_token") or not isinstance(user, dict) or not user.get("sub"):
                raise ValueError("OIDC verification failed")
            request.session.clear()
            request.session["user"] = {"sub": str(user["sub"]),
                                       "username": str(user.get("preferred_username", user["sub"])),
                                       "name": str(user.get("name", ""))}
            return RedirectResponse("/", status_code=303)
        except ConfigurationUnavailable:
            raise
        except Exception:
            request.session.clear()
            LOGGER.info("Вход OIDC отклонён")
            return page("Вход не выполнен", "<p>Не удалось подтвердить вход. Попробуйте начать заново.</p><a href='/login'>Повторить вход</a>", 400)

    async def service_data(request: Request):
        user = user_from_session(request)
        values = configuration(settings)
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False, transport=app.state.backend_transport) as client:
                response = await client.get(settings.backend_url + "/data", headers={"X-API-Key": values["backend_api_key"]})
                response.raise_for_status()
                data = response.json()
            return {"user": user, "backend": data}
        except (httpx.HTTPError, ValueError):
            raise HTTPException(status_code=503, detail="Внутренний сервис временно недоступен") from None

    @app.get("/api/data")
    async def api_data(request: Request):
        return await service_data(request)

    @app.get("/profile")
    async def profile(request: Request):
        result = await service_data(request)
        return page("Доступ подтверждён", "<p>Пользователь LDAP: <strong>" + escape(result["user"]["username"]) +
                    "</strong></p><p>Вход через Keycloak выполнен. Внутренний сервис проверил ключ, полученный из Vault.</p>"
                    "<p>Содержимое секретов не выводится.</p><a href='/'>На главную</a>")

    @app.post("/logout")
    async def logout(request: Request):
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != settings.public_url:
            raise HTTPException(status_code=403, detail="Запрос отклонён")
        request.session.clear()
        return RedirectResponse("/", status_code=303)

    return app
