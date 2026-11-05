"""Внутренний сервис: проверяет актуальный ключ из файла Vault Agent."""
import hmac
import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

from .common import ConfigurationUnavailable, SecurityHeadersMiddleware, read_config, unavailable_response


def create_app(config_file: Path | None = None) -> FastAPI:
    app = FastAPI(title="Внутренний сервис InfraSec", docs_url=None, redoc_url=None, openapi_url=None)
    path = config_file or Path(os.environ.get("VAULT_CONFIG_FILE", "/vault/secrets/config.json"))
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(ConfigurationUnavailable)
    async def configuration_error(request, exc):
        return unavailable_response()

    @app.get("/health")
    async def health():
        read_config(path, ("api_key",))
        return {"status": "ok", "service": "backend", "config_loaded": True}

    @app.get("/data")
    async def protected_data(x_api_key: str | None = Header(default=None)):
        expected = read_config(path, ("api_key",))["api_key"]
        if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="Доступ запрещён")
        return {"service": "backend", "message": "Защищённый сервис доступен", "authenticated": True}

    return app
