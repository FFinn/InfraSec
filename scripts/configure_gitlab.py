#!/usr/bin/env python3
"""Настроить CI InfraSec через glab, не выводя секреты и одноразовые токены."""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
from urllib.parse import quote, urlencode, urlsplit

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_HOST = 'devsecops.gitlab.yandexcloud.net'
EXPECTED_PROJECT = 's2417991/infrasec'
ENVIRONMENT = 'infrasec'
REGISTRY_TOKEN_NAME = 'infrasec-kubernetes-pull'
REGISTRY_EXPIRY = '2026-11-12T00:00:00Z'
OWN_VARIABLES = {'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_ADDR', 'VAULT_CACERT',
                 'KUBE_TOKEN', 'KUBE_API_URL', 'KUBE_CA_CERT'}


class SafeError(Exception):
    """Текст ошибки заранее ограничен и не включает ответы API."""


class ApiError(SafeError):
    def __init__(self, method, endpoint, status):
        self.status = status
        super().__init__(f'GitLab API {method} {endpoint.split("?")[0]}: HTTP {status or "не определён"}')


def require(condition, message):
    if not condition:
        raise SafeError(message)


def external_path(value, description):
    path = Path(value).expanduser().resolve()
    require(path != ROOT and ROOT not in path.parents,
            description + ': используйте путь вне репозитория')
    return path


def read_file(value, description, private=True):
    path = external_path(value, description)
    details = path.stat()
    require(stat.S_ISREG(details.st_mode), description + ': нужен обычный файл')
    if private:
        require(not details.st_mode & 0o077, description + ': нужны права 0600 или 0400')
    return path.read_text()


def read_json(value, description):
    data = json.loads(read_file(value, description))
    require(isinstance(data, dict), description + ': нужен JSON-объект')
    return data


def save_new_private(path, value):
    # Не перезаписывать прежний одноразовый токен даже при ошибке повторного запуска.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def secret_string(value, description):
    require(isinstance(value, str) and len(value) >= 8 and not re.search(r'\s', value),
            description + ': для маскирования нужна строка без пробелов и переводов строк, от 8 символов')
    return value


def https_origin(value, description):
    require(isinstance(value, str), description + ': нужен HTTPS-адрес')
    parts = urlsplit(value)
    require(parts.scheme == 'https' and parts.hostname and not parts.username and
            not parts.password and parts.path in ('', '/') and not parts.query and not parts.fragment,
            description + ': нужен HTTPS-адрес без логина, пути и дополнительных параметров')
    return value.rstrip('/')


def certificate(value, description):
    require(isinstance(value, str), description + ': нужен PEM-сертификат')
    if '-----BEGIN CERTIFICATE-----' not in value:
        try:
            value = base64.b64decode(value, validate=True).decode()
        except (ValueError, UnicodeError):
            raise SafeError(description + ': неверный формат сертификата') from None
    try:
        ssl.create_default_context(cadata=value)
    except ssl.SSLError:
        raise SafeError(description + ': неверный PEM-сертификат') from None
    return value.strip() + '\n'


class GitLab:
    def __init__(self, host, project):
        self.host, self.project = host, project
        self.environment = os.environ.copy()
        for key in tuple(self.environment):
            if key in ('DEBUG', 'GLAB_DEBUG', 'GITLAB_DEBUG', 'GLAB_DEBUG_LOG_FILE'):
                self.environment.pop(key)
        self.environment.update({'NO_COLOR': '1', 'GLAB_CHECK_UPDATE': 'false', 'PAGER': 'cat'})

    def api(self, method, endpoint, payload=None, missing_ok=False):
        command = ['glab', 'api', '--hostname', self.host, '--method', method,
                   '--output', 'json', endpoint]
        body = None
        if payload is not None:
            command.extend(['--header', 'Content-Type: application/json', '--input', '-'])
            body = json.dumps(payload)
        # Значения передаются только в stdin; argv и сообщения об ошибках их не содержат.
        completed = subprocess.run(command, input=body, capture_output=True, text=True,
                                   env=self.environment, timeout=60)
        if completed.returncode:
            match = re.search(r'HTTP\s+(\d{3})', completed.stderr)
            status = int(match.group(1)) if match else None
            if missing_ok and status == 404:
                return None
            raise ApiError(method, endpoint, status)
        try:
            return json.loads(completed.stdout) if completed.stdout.strip() else None
        except json.JSONDecodeError:
            raise SafeError('GitLab вернул ответ, который не удалось разобрать как JSON') from None

    def project_endpoint(self, suffix=''):
        return f'projects/{self.project}' + suffix

    def pages(self, endpoint):
        items = []
        separator = '&' if '?' in endpoint else '?'
        for page in range(1, 101):
            batch = self.api('GET', endpoint + separator + urlencode({'per_page': 100, 'page': page}))
            require(isinstance(batch, list), 'GitLab не вернул ожидаемый список')
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise SafeError('Слишком много страниц API; автоматическая настройка остановлена')


def desired_variables(args):
    result = {}

    def add(key, value, secret=False, file=False):
        require(key in OWN_VARIABLES, 'Попытка изменить переменную вне списка InfraSec')
        result[key] = {'key': key, 'value': value, 'protected': True, 'raw': True,
                       'environment_scope': ENVIRONMENT, 'masked': secret,
                       'variable_type': 'file' if file else 'env_var',
                       'description': 'InfraSec: ' + key}
        if secret:
            result[key]['masked_and_hidden'] = True

    if args.approle_file:
        data = read_json(args.approle_file, 'Закрытый файл AppRole CI')
        require(data.get('role_name', 'infrasec-ci') == 'infrasec-ci',
                'Нужны реквизиты отдельного AppRole infrasec-ci')
        add('VAULT_ROLE_ID', secret_string(data.get('role_id'), 'Vault RoleID'), secret=True)
        add('VAULT_SECRET_ID', secret_string(data.get('secret_id'), 'Vault SecretID'), secret=True)
    if args.vault_address:
        add('VAULT_ADDR', https_origin(args.vault_address, 'Адрес Vault'))
    if args.vault_ca_file:
        add('VAULT_CACERT', certificate(read_file(args.vault_ca_file, 'Файл CA Vault', private=False),
                                      'CA Vault'), file=True)
    if args.kube_file:
        data = read_json(args.kube_file, 'Закрытый файл доступа Kubernetes')
        add('KUBE_TOKEN', secret_string(data.get('token'), 'Токен Kubernetes'), secret=True)
        add('KUBE_API_URL', https_origin(data.get('api_url'), 'Адрес API Kubernetes'))
        add('KUBE_CA_CERT', certificate(data.get('ca_certificate'), 'CA Kubernetes'), file=True)
    return result


def prepare_variable_plan(client, desired):
    plan = []
    if any(value.get('masked_and_hidden') for value in desired.values()):
        version = client.api('GET', 'version')
        parsed = re.match(r'^(\d+)\.(\d+)', str(version.get('version', '')))
        require(parsed and tuple(map(int, parsed.groups())) >= (17, 4),
                'Для masked_and_hidden нужен GitLab 17.4 или новее')
    for key, payload in desired.items():
        endpoint = client.project_endpoint('/variables/' + quote(key, safe=''))
        scoped = endpoint + '?' + urlencode({'filter[environment_scope]': ENVIRONMENT})
        existing = client.api('GET', scoped, missing_ok=True)
        if existing is not None:
            require(existing.get('key') == key and existing.get('environment_scope') == ENVIRONMENT,
                    'API вернул переменную другого имени или окружения')
            if payload.get('masked_and_hidden'):
                # GitLab позволяет включить hidden только при создании переменной.
                require(existing.get('hidden') is True,
                        key + ': существующая переменная не hidden; автоматическое удаление отключено')
        plan.append((key, payload, existing is not None, scoped))
    return plan


def apply_variables(client, plan):
    summary = []
    for key, desired, exists, endpoint in plan:
        payload = dict(desired)
        if exists:
            # Для PUT параметр masked_and_hidden не предусмотрен; hidden сохраняется.
            payload.pop('masked_and_hidden', None)
            current = client.api('PUT', endpoint, payload)
        else:
            current = client.api('POST', client.project_endpoint('/variables'), payload)
        expected = {'key': key, 'protected': True, 'raw': True,
                    'environment_scope': ENVIRONMENT, 'variable_type': desired['variable_type'],
                    'masked': desired['masked']}
        require(isinstance(current, dict) and all(current.get(name) == value for name, value in expected.items()),
                key + ': GitLab не подтвердил требуемые настройки переменной')
        if desired.get('masked_and_hidden'):
            require(current.get('hidden') is True, key + ': GitLab не подтвердил hidden')
        summary.append(dict(expected, hidden=bool(current.get('hidden')), action='updated' if exists else 'created'))
    return summary


def validate_saved_ownership(data, client, description):
    require(data.get('host') == client.host and data.get('project_id') == client.project,
            description + ': файл относится к другому GitLab или проекту')
    require(isinstance(data.get('id'), int) and data['id'] > 0 and
            isinstance(data.get('token'), str) and bool(data['token']),
            description + ': неполные сохранённые реквизиты')


def configure_runner(client, directory):
    target = directory / 'runner.json'
    reused = target.exists()
    if reused:
        saved = read_json(target, 'Закрытый файл Runner')
        validate_saved_ownership(saved, client, 'Runner')
    else:
        known = client.pages(client.project_endpoint('/runners'))
        require(not any(item.get('description') == 'InfraSec' and item.get('runner_type') == 'project_type'
                        for item in known),
                'Runner InfraSec уже существует, но закрытый файл отсутствует; повторное создание остановлено')
        created = client.api('POST', 'user/runners', {
            'runner_type': 'project_type', 'project_id': client.project,
            'description': 'InfraSec', 'tag_list': 'infrasec',
            'run_untagged': False, 'locked': True, 'access_level': 'ref_protected',
            'maximum_timeout': 1800,
        })
        require(isinstance(created, dict) and isinstance(created.get('id'), int) and
                isinstance(created.get('token'), str) and created['token'],
                'GitLab не вернул одноразовый токен Runner; проверьте список Runner вручную')
        saved = {'id': created['id'], 'token': created['token'], 'host': client.host,
                 'project_id': client.project, 'url': 'https://' + client.host,
                 'token_expires_at': created.get('token_expires_at'),
                 'created_at': datetime.now(timezone.utc).isoformat()}
        save_new_private(target, saved)
    actual = client.api('GET', 'runners/' + str(saved['id']))
    require(isinstance(actual, dict) and actual.get('runner_type') == 'project_type' and
            any(project.get('id') == client.project for project in actual.get('projects', [])),
            'Сохранённый Runner не относится к нужному проекту')
    expected = {'description': 'InfraSec', 'tag_list': ['infrasec'], 'run_untagged': False,
                'locked': True, 'access_level': 'ref_protected', 'maximum_timeout': 1800}
    if any(actual.get(key) != value for key, value in expected.items()):
        actual = client.api('PUT', 'runners/' + str(saved['id']), expected)
    require(all(actual.get(key) == value for key, value in expected.items()),
            'GitLab не подтвердил настройки собственного Runner')
    return dict(expected, id=saved['id'], project_id=client.project, reused_private_file=reused,
                authentication_token_saved_outside_repository=True)


def configure_registry_token(client, directory):
    target = directory / 'registry.json'
    reused = target.exists()
    if reused:
        saved = read_json(target, 'Закрытый файл DeployToken')
        validate_saved_ownership(saved, client, 'DeployToken')
        actual = client.api('GET', client.project_endpoint('/deploy_tokens/' + str(saved['id'])))
    else:
        expires = datetime.fromisoformat(REGISTRY_EXPIRY.replace('Z', '+00:00'))
        require(datetime.now(timezone.utc) < expires, 'Срок запрошенного DeployToken уже истёк')
        known = client.pages(client.project_endpoint('/deploy_tokens'))
        require(not any(item.get('name') == REGISTRY_TOKEN_NAME and
                        not item.get('revoked') and not item.get('expired') for item in known),
                'DeployToken InfraSec уже существует, но закрытый файл отсутствует; повторное создание остановлено')
        actual = client.api('POST', client.project_endpoint('/deploy_tokens'), {
            'name': REGISTRY_TOKEN_NAME, 'scopes': ['read_registry'], 'expires_at': REGISTRY_EXPIRY,
        })
        require(isinstance(actual, dict) and isinstance(actual.get('id'), int) and
                isinstance(actual.get('token'), str) and actual['token'] and
                isinstance(actual.get('username'), str) and actual['username'],
                'GitLab не вернул одноразовые реквизиты DeployToken; проверьте его список вручную')
        saved = {'id': actual['id'], 'username': actual['username'], 'token': actual['token'],
                 'project_id': client.project, 'host': client.host,
                 'registry': client.host + ':5050', 'name': REGISTRY_TOKEN_NAME,
                 'scopes': ['read_registry'], 'expires_at': actual.get('expires_at'),
                 'created_at': datetime.now(timezone.utc).isoformat()}
        save_new_private(target, saved)
    require(isinstance(actual, dict) and actual.get('name') == REGISTRY_TOKEN_NAME and
            actual.get('username') == saved.get('username') and
            actual.get('scopes') == ['read_registry'] and not actual.get('revoked') and not actual.get('expired'),
            'DeployToken не подтвердил требуемые права или уже недействителен')
    require(str(actual.get('expires_at', '')).startswith('2026-11-12'),
            'Срок DeployToken отличается от установленного для практики')
    require(saved.get('registry') == client.host + ':5050', 'Сохранён неверный адрес реестра')
    return {'id': saved['id'], 'project_id': client.project, 'scopes': ['read_registry'],
            'expires_at': actual['expires_at'], 'reused_private_file': reused,
            'credentials_saved_outside_repository': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', required=True)
    parser.add_argument('--project', type=int, default=1165)
    parser.add_argument('--host', default=EXPECTED_HOST)
    parser.add_argument('--approle-file')
    parser.add_argument('--vault-ca-file')
    parser.add_argument('--vault-address')
    parser.add_argument('--kube-file', help='Закрытый JSON с token, ca_certificate и api_url')
    parser.add_argument('--create-runner', action='store_true')
    parser.add_argument('--create-registry-token', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    summary = {'ok': False, 'project_id': args.project, 'variables': []}
    lock = None
    try:
        require(args.host == EXPECTED_HOST and args.project > 0,
                'Разрешён только учебный GitLab и положительный идентификатор проекта')
        directory = external_path(args.private_dir, 'Закрытая папка GitLab')
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not directory.stat().st_mode & 0o077, 'Закрытая папка должна иметь права 0700')
        lock = os.open(directory / '.configure-gitlab.lock', os.O_WRONLY | os.O_CREAT, 0o600)
        os.fchmod(lock, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafeError('Настройка GitLab уже выполняется другим процессом') from None
        desired = desired_variables(args)
        client = GitLab(args.host, args.project)
        project = client.api('GET', client.project_endpoint())
        require(isinstance(project, dict) and project.get('id') == args.project and
                project.get('path_with_namespace') == EXPECTED_PROJECT,
                'Проект не совпадает с ожидаемым s2417991/infrasec; изменения остановлены')
        summary['project_verified'] = True
        plan = prepare_variable_plan(client, desired)
        summary['variables'] = apply_variables(client, plan)
        if args.create_runner:
            summary['runner'] = configure_runner(client, directory)
        if args.create_registry_token:
            summary['registry_token'] = configure_registry_token(client, directory)
        summary['ok'] = True
        summary['checked_at'] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        summary['error'] = str(exc) if isinstance(exc, SafeError) else type(exc).__name__
    finally:
        if lock is not None:
            os.close(lock)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
