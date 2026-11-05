from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit


def base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("Некорректный адрес сервиса")
    return value.rstrip("/")


@dataclass(frozen=True)
class WebSettings:
    config_file: Path
    keycloak_public_url: str
    keycloak_internal_url: str
    client_id: str
    public_url: str
    backend_url: str
    keycloak_ca_file: str | None = None

    @classmethod
    def from_env(cls):
        public = base_url(os.environ["KEYCLOAK_PUBLIC_URL"])
        return cls(
            config_file=Path(os.environ.get("VAULT_CONFIG_FILE", "/vault/secrets/config.json")),
            keycloak_public_url=public,
            keycloak_internal_url=base_url(os.environ.get("KEYCLOAK_INTERNAL_URL", public)),
            client_id=os.environ.get("OIDC_CLIENT_ID", "infrasec-web"),
            public_url=base_url(os.environ.get("APP_PUBLIC_URL", "http://127.0.0.1:18080")),
            backend_url=base_url(os.environ.get("BACKEND_URL", "http://backend:8000")),
            keycloak_ca_file=os.environ.get("KEYCLOAK_CA_FILE") or os.environ.get("SSL_CERT_FILE") or None,
        )
