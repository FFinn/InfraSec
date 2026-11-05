#!/usr/bin/env python3
"""Проверка OIDC/LDAP, приложения и Vault без сохранения значений секретов."""
import argparse
import base64
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy
import ipaddress
import json
import logging
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import urljoin, urlsplit

import httpx
from itsdangerous import TimestampSigner

from vault_setup import SafeError, Vault, read_private_json, save_json

ROOT = Path(__file__).resolve().parent.parent
REDIRECTS = {301, 302, 303, 307, 308}
TOKEN_KEYS = {"access_token", "refresh_token", "id_token", "client_token"}


def require(condition, message):
    if not condition:
        raise SafeError(message)


def base_url(value):
    parts = urlsplit(value)
    require(parts.scheme in ("http", "https") and parts.hostname and
            not parts.username and not parts.password and not parts.query and not parts.fragment,
            "Некорректный адрес HTTP-сервиса")
    return value.rstrip("/")


def origin(value):
    parts = urlsplit(value)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, parts.hostname, port


def trusted_url(value, allowed_origins):
    parts = urlsplit(value)
    require(not parts.username and not parts.password and not parts.fragment and
            origin(value) in allowed_origins,
            "Переход на неподтверждённый адрес отклонён")
    return value


def loopback_host(host):
    if not host:
        return False
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class BrowserLoopbackCookiePolicy(DefaultCookiePolicy):
    """Как браузер, учитывает защищённый контекст явно заданного loopback."""
    def __init__(self, urls):
        super().__init__()
        self.loopback_origins = {origin(url) for url in urls
                                 if urlsplit(url).scheme == "http" and loopback_host(urlsplit(url).hostname)}

    def return_ok_secure(self, cookie, request):
        if super().return_ok_secure(cookie, request):
            return True
        # Флаг Secure не снимается. Остальные проверки CookieJar (домен,
        # путь, срок и порт) сохраняются. Обычные HTTP-хосты исключены.
        return origin(request.get_full_url()) in self.loopback_origins


def oidc_http_client(frontend, keycloak):
    allowed = {origin(frontend), origin(keycloak)}
    jar = CookieJar(policy=BrowserLoopbackCookiePolicy((frontend, keycloak)))
    client = httpx.Client(timeout=20, follow_redirects=False, trust_env=False, cookies=jar)

    def attach_cookies(request):
        trusted_url(str(request.url), allowed)
        # При объединении cookie HTTPX создаёт CookieJar с обычной политикой.
        # Применяем исходное хранилище с ограниченным исключением loopback.
        request.headers.pop("cookie", None)
        client.cookies.set_cookie_header(request)

    client.event_hooks["request"].append(attach_cookies)
    return client


class LoginForms(HTMLParser):
    """Читает форму входа; её содержимое никогда не попадает в отчёт."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "form":
            self.current = {"action": attributes.get("action", ""),
                            "method": attributes.get("method", "get").lower(),
                            "fields": {}, "has_password": False}
        elif tag == "input" and self.current is not None:
            name = attributes.get("name")
            if name:
                self.current["fields"][name] = attributes.get("value", "")
            if attributes.get("type", "").lower() == "password":
                self.current["has_password"] = True

    def handle_endtag(self, tag):
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None

    def login_form(self):
        candidates = [form for form in self.forms if form["has_password"] and
                      "username" in form["fields"] and "password" in form["fields"]]
        require(len(candidates) == 1, "Не найдена однозначная форма входа Keycloak")
        require(candidates[0]["method"] == "post", "Форма входа должна использовать POST")
        return candidates[0]


def follow_get(client, response, allowed_origins):
    count = 0
    while response.status_code in REDIRECTS:
        require(count < 12, "Превышено число переходов при входе")
        location = response.headers.get("location")
        require(bool(location), "В перенаправлении отсутствует адрес")
        target = trusted_url(urljoin(str(response.url), location), allowed_origins)
        response = client.get(target)
        count += 1
    return response


def forbidden_session_content(value):
    if isinstance(value, dict):
        return bool(TOKEN_KEYS.intersection(value)) or any(forbidden_session_content(item) for item in value.values())
    if isinstance(value, list):
        return any(forbidden_session_content(item) for item in value)
    return isinstance(value, str) and bool(re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value))


def frontend_session(client, values):
    cookie = client.cookies.get("infrasec_session")
    require(bool(cookie), "Приложение не создало сеанс")
    # Срок сеанса проверяет приложение на своей ВМ. Здесь проверяется подпись;
    # часы компьютера оператора могут немного отличаться от часов подписанта.
    payload = TimestampSigner(values["frontend"]["session_secret"]).unsign(cookie)
    session = json.loads(base64.b64decode(payload))
    require(set(session) == {"user"} and isinstance(session["user"], dict),
            "В сеансе сохранены дополнительные данные")
    require(set(session["user"]) <= {"sub", "username", "name"},
            "В сеансе сохранены дополнительные поля пользователя")
    require(not forbidden_session_content(session), "В сеансе найден токен")
    content = json.dumps(session, ensure_ascii=False)
    require(not any(secret in content for secret in values["frontend"].values()),
            "В сеансе найден секрет приложения")
    return session


def oidc_login(frontend, keycloak, identity, values, username):
    allowed = {origin(frontend), origin(keycloak)}
    user = identity["users"][username]
    require(user["username"] == username and isinstance(user["password"], str) and user["password"],
            "Некорректная учебная учётная запись")
    with oidc_http_client(frontend, keycloak) as client:
        response = client.get(frontend + "/login")
        require(response.status_code in REDIRECTS, "Приложение не начало вход OIDC")
        response = follow_get(client, response, allowed)
        require(response.status_code == 200 and origin(str(response.url)) == origin(keycloak),
                "Не открылась форма входа Keycloak")
        parser = LoginForms()
        parser.feed(response.text)
        form = parser.login_form()
        action = trusted_url(urljoin(str(response.url), form["action"]), {origin(keycloak)})
        form["fields"].update({"username": user["username"], "password": user["password"]})
        response = client.post(action, data=form["fields"])
        response = follow_get(client, response, allowed)
        require(response.status_code == 200 and origin(str(response.url)) == origin(frontend),
                "Вход LDAP/OIDC не завершился в приложении")
        session = frontend_session(client, values)
        require(session["user"].get("username") == username, "В сеансе другой пользователь")
        profile = client.get(frontend + "/profile")
        require(profile.status_code == 200 and username in profile.text, "Профиль пользователя не открыт")
        result = client.get(frontend + "/api/data")
        require(result.status_code == 200, "Внутренний сервис недоступен через приложение")
        body = result.json()
        require(body.get("user", {}).get("username") == username and
                body.get("backend", {}).get("authenticated") is True,
                "Приложение не подтвердило обращение к внутреннему сервису")
        require(not any(secret in profile.text + result.text for secret in values["frontend"].values()),
                "Секрет приложения найден в HTTP-ответе")
        logout = client.post(frontend + "/logout", headers={"Origin": frontend})
        require(logout.status_code in (302, 303), "Не выполнен выход из приложения")
        require(client.get(frontend + "/api/data").status_code == 401,
                "После выхода сохранился доступ к внутреннему сервису")
        return {"login_completed": True, "profile_status": profile.status_code,
                "protected_api_status": result.status_code, "session_contains_no_tokens": True,
                "responses_contain_no_secrets": True, "logout_denies_access": True}


def anonymous_frontend(frontend):
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
        response = client.get(frontend + "/profile")
        denied = response.status_code == 401
        if response.status_code in REDIRECTS:
            location = urljoin(frontend, response.headers.get("location", ""))
            denied = origin(location) == origin(frontend) and urlsplit(location).path == "/login"
        require(denied, "Профиль открыт без входа")
        api_status = client.get(frontend + "/api/data").status_code
        require(api_status == 401, "API приложения открыт без входа")
        return {"profile_status": response.status_code, "api_status": api_status, "access_denied": True}


def backend_check(backend, values):
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
        denied = client.get(backend + "/data")
        require(denied.status_code == 401, "Внутренний сервис открыт без ключа")
        allowed = client.get(backend + "/data", headers={"X-API-Key": values["backend"]["api_key"]})
        require(allowed.status_code == 200 and allowed.json().get("authenticated") is True,
                "Внутренний сервис не принимает ожидаемый ключ")
        require(values["backend"]["api_key"] not in allowed.text, "Сервис вернул ключ в ответе")
        return {"without_key_status": denied.status_code, "with_key_status": allowed.status_code,
                "response_contains_no_secret": True}


class Kubernetes:
    def __init__(self, ssh_config=None, host="dso08"):
        self.ssh_config = ssh_config
        self.host = host
        require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host)), "Некорректное имя SSH-хоста")

    def call(self, *arguments, allowed=(0,)):
        kubectl = ["kubectl", *arguments]
        if self.ssh_config:
            command = ["ssh", "-F", str(self.ssh_config), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                       self.host, shlex.join(kubectl)]
        else:
            command = kubectl
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        require(result.returncode in allowed, "Команда проверки Kubernetes не выполнена")
        return result.stdout

    def service_jwt(self, service_account, audience="vault"):
        return self.call("-n", "infrasec", "create", "token", service_account,
                         "--audience=" + audience, "--duration=10m").strip()

    def app_pod(self, component):
        items = json.loads(self.call("-n", "infrasec", "get", "pods", "-l", "app=" + component, "-o", "json"))["items"]
        items = [item for item in items if not item["metadata"].get("deletionTimestamp")]
        require(len(items) == 1, "Ожидался один действующий под приложения")
        return items[0]

    def exec(self, pod, *arguments):
        return self.call("-n", "infrasec", "exec", pod["metadata"]["name"], "-c", "app", "--", *arguments)


def kubernetes_pod(kube, values, component):
    pod = kube.app_pod(component)
    require(pod.get("status", {}).get("phase") == "Running", "Под не запущен")
    statuses = {item["name"]: item for item in pod["status"].get("containerStatuses", [])}
    require(statuses.get("app", {}).get("ready") and statuses.get("vault-agent", {}).get("ready"),
            "Приложение или Vault Agent не готовы")
    initialized = {item["name"]: item for item in pod["status"].get("initContainerStatuses", [])}
    require(initialized.get("vault-agent-init", {}).get("state", {}).get("terminated", {}).get("exitCode") == 0,
            "Начальный контейнер агента не завершился успешно")
    require(pod["spec"].get("automountServiceAccountToken") is False, "Автоматическое монтирование JWT включено")
    require(pod["spec"]["serviceAccountName"] == component + "-sa", "Использован другой сервисный аккаунт")
    pod_context = pod["spec"].get("securityContext", {})
    require(pod_context.get("runAsNonRoot") and pod_context.get("runAsUser") == 1000 and
            pod_context.get("seccompProfile", {}).get("type") == "RuntimeDefault",
            "Под не соответствует заданной защите")
    containers = {item["name"]: item for item in pod["spec"]["containers"]}
    require(not any(item["name"] == "vault-auth" or item["name"].startswith("kube-api-access-")
                    for item in containers["app"].get("volumeMounts", [])), "JWT смонтирован приложению")
    for container in pod["spec"]["containers"] + pod["spec"].get("initContainers", []):
        context = container.get("securityContext", {})
        require(context.get("runAsNonRoot") and context.get("runAsUser") == 1000 and
                context.get("allowPrivilegeEscalation") is False and context.get("readOnlyRootFilesystem") is True and
                context.get("capabilities", {}).get("drop") == ["ALL"] and
                context.get("seccompProfile", {}).get("type") == "RuntimeDefault",
                "Контейнер не соответствует заданной защите")
    metadata = kube.exec(pod, "stat", "-c", "%a %u", "/vault/secrets/config.json").strip()
    require(metadata == "400 1000", "Файл должен иметь права 0400 и принадлежать UID 1000")
    content = json.loads(kube.exec(pod, "cat", "/vault/secrets/config.json"))
    require(content == values[component], "Файл приложения не совпадает с учебными значениями Vault")
    kube.exec(pod, "/bin/sh", "-ec", "\n".join("test ! -e " + path for path in (
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/vault.hashicorp.com/serviceaccount/token",
        "/vault/secrets/token", "/vault/secrets/.vault-token", "/home/vault/.vault-token")))
    return {"app_ready": True, "agent_ready": True, "init_completed": True,
            "permissions_0400": True, "owner_uid_1000": True, "secret_file_matches_vault_values": True,
            "app_has_no_jwt_or_vault_token_file": True, "containers_hardened": True}


def vault_login(client, kube, component, *, account=None, audience="vault", expected=(200,)):
    jwt = kube.service_jwt(account or component + "-sa", audience)
    return client.call("POST", "auth/kubernetes/login", {"role": "infrasec-" + component, "jwt": jwt}, expected=expected)


def own_secret(client, kube, component, values, tokens):
    _, body = vault_login(client, kube, component)
    auth = body["auth"]
    token = auth["client_token"]
    tokens[component] = token
    require(0 < auth.get("lease_duration", 0) <= 300 and auth.get("policies") == ["infrasec-" + component],
            "Срок или политика проверочного токена не соответствуют роли")
    metadata = auth.get("metadata", {})
    require(metadata.get("service_account_name") == component + "-sa" and
            metadata.get("service_account_namespace") == "infrasec",
            "Vault не подтвердил ожидаемый сервисный аккаунт")
    _, secret = client.call("GET", "secret/data/infrasec/app/" + component, token=token)
    require(secret["data"]["data"] == values[component], "В Vault другое значение секрета приложения")
    return {"login_status": 200, "own_secret_status": 200, "secret_matches": True, "minimal_policy": True}


def forbidden_vault_read(client, tokens, component):
    require(component in tokens, "Нет проверочного токена приложения")
    other = "backend" if component == "frontend" else "frontend"
    client.call("GET", "secret/data/infrasec/app/" + other, token=tokens[component], expected=(403,))
    return {"status": 403, "access_denied": True}


def forbidden_vault_write(client, tokens, component):
    require(component in tokens, "Нет проверочного токена приложения")
    # Если политика ошибочна, сохраняется то же значение; ошибка всё равно фиксируется.
    _, current = client.call("GET", "secret/data/infrasec/app/" + component, token=tokens[component])
    client.call("POST", "secret/data/infrasec/app/" + component,
                {"data": current["data"]["data"]}, token=tokens[component], expected=(403,))
    return {"status": 403, "access_denied": True}


def wrong_vault_role(client, kube, component):
    other = "backend" if component == "frontend" else "frontend"
    vault_login(client, kube, other, account=component + "-sa", expected=(403,))
    return {"status": 403, "access_denied": True}


def denied_vault_login(client, kube, component, **kwargs):
    vault_login(client, kube, component, expected=(403,), **kwargs)
    return {"status": 403, "access_denied": True}


def vault_health(client):
    _, status = client.call("GET", "sys/seal-status")
    require(status.get("initialized") and not status.get("sealed"), "Vault не инициализирован или заблокирован")
    return {"initialized": True, "sealed": False, "tls_certificate_verified": True}


def secret_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and len(item) >= 16 and any(word in key.lower() for word in
                    ("password", "secret", "api_key", "token", "deploy_marker")):
                yield item
            elif isinstance(item, (dict, list)):
                yield from secret_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from secret_values(item)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--app-values-file", type=Path, required=True)
    parser.add_argument("--vault-ca-file", type=Path, required=True)
    parser.add_argument("--frontend-url", default="http://127.0.0.1:18080")
    parser.add_argument("--keycloak-url", default="http://127.0.0.1:18081")
    parser.add_argument("--backend-url", default="http://127.0.0.1:18082")
    parser.add_argument("--vault-url", default="https://127.0.0.1:18200")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--ssh-host", default="dso08")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "artifacts/integration")
    return parser.parse_args()


def main(args):
    result = {"started_at": datetime.now(timezone.utc).isoformat(), "checks": []}
    vault = None
    protected = []

    def check(name, operation):
        try:
            details = operation()
            result["checks"].append({"name": name, "ok": True, "details": details})
        except Exception as exc:
            details = str(exc) if isinstance(exc, SafeError) else type(exc).__name__
            result["checks"].append({"name": name, "ok": False, "details": details})

    try:
        identity = read_private_json(args.identity_file, "Закрытые учётные записи LDAP")
        values = read_private_json(args.app_values_file, "Закрытые значения приложения")
        protected = list(secret_values(identity)) + list(secret_values(values))
        require(isinstance(values.get("frontend"), dict) and isinstance(values.get("backend"), dict),
                "Некорректный формат значений приложения")
        frontend, keycloak, backend = map(base_url, (args.frontend_url, args.keycloak_url, args.backend_url))
        check("Без входа профиль и API приложения недоступны", lambda: anonymous_frontend(frontend))
        check("Внутренний сервис проверяет ключ Vault", lambda: backend_check(backend, values))
        for username in ("alice", "bob"):
            check("Вход OIDC с учётной записью LDAP " + username,
                  lambda who=username: oidc_login(frontend, keycloak, identity, values, who))
        vault = Vault(args.vault_url, args.vault_ca_file)
        check("Vault разблокирован, сертификат TLS проверен", lambda: vault_health(vault))
        kube = Kubernetes(args.ssh_config, args.ssh_host)
        tokens = {}
        for component in ("frontend", "backend"):
            check(component + ": под и внедрённый файл секрета",
                  lambda who=component: kubernetes_pod(kube, values, who))
            check(component + ": вход в Vault и чтение своего пути",
                  lambda who=component: own_secret(vault, kube, who, values, tokens))
            check(component + ": чужой путь Vault запрещён",
                  lambda who=component: forbidden_vault_read(vault, tokens, who))
            check(component + ": запись в Vault запрещена",
                  lambda who=component: forbidden_vault_write(vault, tokens, who))
            check(component + ": чужая роль Vault запрещена",
                  lambda who=component: wrong_vault_role(vault, kube, who))
            check(component + ": default ServiceAccount не может войти в Vault",
                  lambda who=component: denied_vault_login(vault, kube, who, account="default"))
            check(component + ": неверная аудитория JWT отклонена",
                  lambda who=component: denied_vault_login(vault, kube, who, audience="vault-mismatch"))
    except Exception as exc:
        result["checks"].append({"name": "Подготовка проверки", "ok": False,
                                 "details": str(exc) if isinstance(exc, SafeError) else type(exc).__name__})
    finally:
        if vault is not None:
            for index, token in enumerate(vault.issued_tokens, 1):
                def revoke(value=token):
                    vault.call("POST", "auth/token/revoke-self", token=value, expected=(204,))
                    return {"status": 204, "revoked": True}
                check("Отзыв проверочного токена Vault №" + str(index), revoke)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    result["passed"] = sum(item["ok"] for item in result["checks"])
    result["failed"] = sum(not item["ok"] for item in result["checks"])
    result["ok"] = result["failed"] == 0
    output = json.dumps(result, ensure_ascii=False)
    if any(value in output for value in protected):
        print("Отчёт не сохранён: обнаружено закрытое значение.")
        return 1
    target = args.evidence_dir.expanduser().resolve()
    save_json(target / "verification.json", result)
    lines = ["| Проверка | Результат |", "|---|---|"]
    for item in result["checks"]:
        lines.append("| " + item["name"] + " | " + ("Пройдена" if item["ok"] else "Ошибка: " + str(item["details"])) + " |")
    lines.append(f"\nПройдено: {result['passed']}; ошибок: {result['failed']}.")
    (target / "verification.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    try:
        sys.exit(main(parse_args()))
    except Exception:
        print("Не удалось завершить проверку или сохранить безопасный отчёт.")
        sys.exit(1)
