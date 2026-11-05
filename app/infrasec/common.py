"""Чтение конфигурации и общие HTTP-заголовки без вывода значений секретов."""
import json
from pathlib import Path

from starlette.responses import JSONResponse


class ConfigurationUnavailable(Exception):
    pass


def read_config(path: Path, required: tuple[str, ...]) -> dict[str, str]:
    try:
        if path.stat().st_size > 65536:
            raise ConfigurationUnavailable
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ConfigurationUnavailable
        if any(not isinstance(values.get(key), str) or not values[key] for key in required):
            raise ConfigurationUnavailable
        return {key: values[key] for key in required}
    except (OSError, ValueError, TypeError):
        raise ConfigurationUnavailable from None


def unavailable_response() -> JSONResponse:
    return JSONResponse({"detail": "Конфигурация сервиса временно недоступна"}, status_code=503)


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (b"content-security-policy", b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
                ])
            await send(message)

        await self.app(scope, receive, send_with_headers)
