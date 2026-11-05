#!/usr/bin/env python3
"""Настройка отдельных секретов и ролей InfraSec без вывода учётных данных."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import sys
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parent.parent
PATHS = {
    'frontend': 'infrasec/app/frontend',
    'backend': 'infrasec/app/backend',
    'ansible': 'infrasec/infrastructure/credentials',
    'ci': 'infrasec/ci/deploy',
    'identity': 'infrasec/infrastructure/identity',
}
ROLE_SETTINGS = {
    'secret_id_ttl': 7200,
    'secret_id_num_uses': 20,
    'token_ttl': 300,
    'token_max_ttl': 600,
    'token_explicit_max_ttl': 600,
    'token_no_default_policy': True,
    'bind_secret_id': True,
}


class SafeError(Exception):
    """Сообщение не содержит тел HTTP-ответов и значений секретов."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def save_json(path, value, private=True):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    if private:
        path.chmod(0o600)


def outside_repository(path, description):
    path = path.expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise SafeError(description + ': используйте путь вне репозитория')
    return path


def read_private_json(path, description):
    path = outside_repository(path, description)
    attributes = path.stat()
    if not stat.S_ISREG(attributes.st_mode) or attributes.st_mode & 0o077:
        raise SafeError(description + ': нужен обычный файл с правами 0600 или 0400')
    return json.loads(path.read_text())


class Vault:
    def __init__(self, address, ca_path):
        parts = parse.urlsplit(address)
        if (parts.scheme != 'https' or not parts.hostname or parts.username or
                parts.password or parts.query or parts.fragment or parts.path not in ('', '/')):
            raise SafeError('VAULT_ADDR должен быть HTTPS-адресом без логина и дополнительных параметров')
        self.base = address.rstrip('/') + '/v1/'
        self.opener = request.build_opener(
            request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_path))))
        self.issued_tokens = []

    def call(self, method, path, data=None, token=None, expected=(200,)):
        headers = {'X-Vault-Token': token} if token else {}
        payload = None
        if data is not None:
            headers['Content-Type'] = 'application/json'
            payload = json.dumps(data).encode()
        query = request.Request(self.base + path, method=method, headers=headers, data=payload)
        try:
            response = self.opener.open(query, timeout=20)
        except error.HTTPError as exc:
            response = exc
        with response:
            status, content = response.status, response.read()
        body = json.loads(content) if content else None
        # Даже токен, неожиданно выданный при отрицательной пробе, будет отозван.
        if isinstance(body, dict) and isinstance(body.get('auth'), dict):
            issued = body['auth'].get('client_token')
            if issued and issued not in self.issued_tokens:
                self.issued_tokens.append(issued)
        if status not in expected:
            raise SafeError(f'Vault {method} {path}: HTTP {status}')
        return status, body


def current_cluster(client):
    _, status = client.call('GET', 'sys/seal-status')
    if not status.get('initialized') or status.get('sealed') or not status.get('cluster_id'):
        raise SafeError('Vault должен быть инициализирован и разблокирован')
    return status['cluster_id']


def check_private_state(directory, cluster_id):
    target = directory / 'vault-state.json'
    if target.exists():
        state = read_private_json(target, 'Файл состояния InfraSec')
        if state.get('cluster_id') != cluster_id:
            raise SafeError('Закрытая папка относится к другому Vault; проверьте пути вручную')


def admin_token(args):
    if not args.admin_file:
        raise SafeError('Укажите --admin-file или INFRASEC_VAULT_ADMIN_FILE')
    value = read_private_json(Path(args.admin_file), 'Административный файл Vault')
    token = value.get('root_token') or value.get('token')
    if not isinstance(token, str) or not token:
        raise SafeError('В административном файле нет поля root_token или token')
    return token


def configure_mounts(client, token):
    _, mounts = client.call('GET', 'sys/mounts', token=token)
    if 'secret/' not in mounts['data']:
        client.call('POST', 'sys/mounts/secret',
                    {'type': 'kv', 'options': {'version': '2'}}, token, expected=(204,))
    elif (mounts['data']['secret/'].get('type') != 'kv' or
          mounts['data']['secret/'].get('options', {}).get('version') != '2'):
        raise SafeError('Путь secret/ уже занят движком другого типа или версии')
    _, methods = client.call('GET', 'sys/auth', token=token)
    if 'approle/' not in methods['data']:
        client.call('POST', 'sys/auth/approle', {'type': 'approle'}, token, expected=(204,))
    elif methods['data']['approle/'].get('type') != 'approle':
        raise SafeError('Путь approle/ уже занят другим методом аутентификации')
    if 'kubernetes/' not in methods['data']:
        client.call('POST', 'sys/auth/kubernetes', {'type': 'kubernetes'}, token, expected=(204,))
    elif methods['data']['kubernetes/'].get('type') != 'kubernetes':
        raise SafeError('Путь kubernetes/ уже занят другим методом аутентификации')
    # Vault в кластере перечитывает собственный короткоживущий JWT и CA.
    # Постоянный reviewer token в конфигурацию не записывается.
    client.call('POST', 'auth/kubernetes/config',
                {'kubernetes_host': 'https://kubernetes.default.svc:443',
                 'disable_local_ca_jwt': False}, token, expected=(204,))
    _, audits = client.call('GET', 'sys/audit', token=token)
    if 'file/' not in audits['data']:
        client.call('POST', 'sys/audit/file',
                    {'type': 'file', 'options': {'file_path': '/vault/audit/audit.log'}},
                    token, expected=(204,))


def configure_policies(client, token):
    for component in ('frontend', 'backend', 'ci', 'ansible'):
        name = 'infrasec-' + component
        policy = (ROOT / 'vault/policies' / (name + '.hcl')).read_text()
        client.call('PUT', 'sys/policies/acl/' + name, {'policy': policy}, token, expected=(204,))


def configure_app_roles(client, token, directory, refresh=False):
    summaries = {}
    for component in ('ci', 'ansible'):
        name = 'infrasec-' + component
        settings = dict(ROLE_SETTINGS, token_policies=[name])
        client.call('POST', 'auth/approle/role/' + name, settings, token, expected=(204,))
        _, role_id = client.call('GET', 'auth/approle/role/' + name + '/role-id', token=token)
        target = directory / (component + '-approle.json')
        previous = read_private_json(target, 'Реквизиты AppRole') if target.exists() else None
        valid = False
        if previous and previous.get('role_name') != name:
            raise SafeError('Реквизиты AppRole относятся к другой роли')
        if previous and previous.get('secret_id_accessor'):
            status, _ = client.call('POST', 'auth/approle/role/' + name + '/secret-id-accessor/lookup',
                {'secret_id_accessor': previous['secret_id_accessor']}, token, expected=(200, 400, 404))
            valid = status == 200 and previous.get('role_id') == role_id['data']['role_id']
            if valid and refresh:
                client.call('POST', 'auth/approle/role/' + name + '/secret-id-accessor/destroy',
                    {'secret_id_accessor': previous['secret_id_accessor']}, token, expected=(204,))
                valid = False
        if not valid:
            _, generated = client.call('POST', 'auth/approle/role/' + name + '/secret-id',
                                       {'metadata': json.dumps({'project': 'infrasec', 'component': component})}, token)
            credentials = dict(generated['data'], role_name=name,
                               role_id=role_id['data']['role_id'],
                               created_at=datetime.now(timezone.utc).isoformat())
            save_json(target, credentials)
        summaries[name] = {'token_ttl': 300, 'token_explicit_max_ttl': 600,
                           'secret_id_ttl': 7200, 'secret_id_num_uses': 20,
                           'no_default_policy': True, 'credentials_reused': valid}
    return summaries


def configure_kubernetes_roles(client, token):
    summaries = {}
    for component in ('frontend', 'backend'):
        name = 'infrasec-' + component
        role = {'bound_service_account_names': [component + '-sa'],
                'bound_service_account_namespaces': ['infrasec'], 'audience': 'vault',
                'token_policies': [name], 'token_ttl': 300, 'token_max_ttl': 900,
                'token_explicit_max_ttl': 900, 'token_no_default_policy': True}
        client.call('POST', 'auth/kubernetes/role/' + name, role, token, expected=(204,))
        summaries[name] = role
    return summaries


def application_values(args, directory):
    if not args.oidc_file:
        raise SafeError('Укажите --oidc-file или INFRASEC_OIDC_CLIENT_FILE')
    supplied = read_private_json(Path(args.oidc_file), 'Файл клиента Keycloak')
    client_secret = supplied.get('client_secret') or supplied.get('oidc_client_secret')
    if not isinstance(client_secret, str) or len(client_secret) < 16:
        raise SafeError('В файле клиента нужен непустой client_secret или oidc_client_secret длиной от 16 символов')
    target = directory / 'app-values.json'
    if target.exists():
        values = read_private_json(target, 'Учебные значения InfraSec')
        required = (values.get('frontend', {}).get('session_secret'),
                    values.get('backend', {}).get('api_key'),
                    values.get('ansible', {}).get('deploy_password'),
                    values.get('ci', {}).get('deploy_marker'))
        if not all(isinstance(value, str) and len(value) >= 32 for value in required):
            raise SafeError('Формат сохранённых учебных значений не соответствует проекту')
        if values['frontend'].get('backend_api_key') != values['backend']['api_key']:
            raise SafeError('Сохранённые ключи frontend и backend не совпадают')
        values['frontend']['oidc_client_secret'] = client_secret
    else:
        backend_key = 'demo-' + secrets.token_urlsafe(32)
        values = {
            'frontend': {'oidc_client_secret': client_secret,
                         'session_secret': secrets.token_urlsafe(48),
                         'backend_api_key': backend_key},
            'backend': {'api_key': backend_key},
            'ansible': {'deploy_password': 'demo-' + secrets.token_urlsafe(32)},
            'ci': {'deploy_marker': 'demo-' + secrets.token_urlsafe(32)},
        }
    if args.identity_file:
        identity = read_private_json(Path(args.identity_file), 'Файл учётных данных инфраструктуры')
        if not isinstance(identity, dict) or not identity:
            raise SafeError('Файл учётных данных инфраструктуры должен содержать непустой JSON-объект')
        values['identity'] = identity
    save_json(target, values)
    return values


def configure(args, client, directory, cluster_id):
    token = admin_token(args)
    configure_mounts(client, token)
    configure_policies(client, token)
    written_paths = []
    if not args.refresh_approle:
        values = application_values(args, directory)
        for component, path in PATHS.items():
            if component not in values:
                continue
            written_paths.append('secret/data/' + path)
            # Запись с CAS сохраняет номер версии и не затирает чужую параллельную правку.
            status, existing = client.call('GET', 'secret/data/' + path, token=token, expected=(200, 404))
            if status == 200 and existing['data']['data'] == values[component]:
                continue
            version = existing['data']['metadata']['version'] if status == 200 else 0
            client.call('POST', 'secret/data/' + path,
                        {'data': values[component], 'options': {'cas': version}}, token)
        kubernetes = configure_kubernetes_roles(client, token)
    else:
        kubernetes = 'без изменений'
    approles = configure_app_roles(client, token, directory, refresh=args.refresh_approle)
    save_json(directory / 'vault-state.json', {'cluster_id': cluster_id, 'configured': True})
    return {'ok': True, 'tls_verified': True, 'kv_version': 2,
            'secret_paths': written_paths if not args.refresh_approle else 'без изменений',
            'policies': ['infrasec-' + component for component in ('frontend', 'backend', 'ci', 'ansible')],
            'kubernetes_roles': kubernetes, 'approles': approles,
            'private_credentials_written_outside_repository': True}


def verify(client, directory):
    checks = []
    credentials = {name: read_private_json(directory / (name + '-approle.json'), 'Реквизиты AppRole')
                   for name in ('ci', 'ansible')}
    values = read_private_json(directory / 'app-values.json', 'Учебные значения InfraSec')

    def check(name, action):
        try:
            detail = action()
            checks.append({'name': name, 'ok': True, 'detail': detail})
        except Exception as exc:
            detail = str(exc) if isinstance(exc, SafeError) else type(exc).__name__
            checks.append({'name': name, 'ok': False, 'detail': detail})

    tokens = {}

    def login(component):
        current = credentials[component]
        _, response = client.call('POST', 'auth/approle/login',
            {'role_id': current['role_id'], 'secret_id': current['secret_id']})
        auth = response['auth']
        tokens[component] = auth['client_token']
        if auth['policies'] != ['infrasec-' + component] or not 0 < auth['lease_duration'] <= 300:
            raise SafeError('Политика или срок токена не соответствуют роли')
        _, lookup = client.call('GET', 'auth/token/lookup-self', token=tokens[component])
        if lookup['data']['explicit_max_ttl'] != 600:
            raise SafeError('Не установлен предельный срок токена')
        return {'http': 200, 'ttl': auth['lease_duration'], 'explicit_max_ttl': 600}

    def own_read(component):
        _, response = client.call('GET', 'secret/data/' + PATHS[component], token=tokens[component])
        if response['data']['data'] != values[component]:
            raise SafeError('Значение не совпало с сохранённым учебным значением')
        return {'http': 200, 'value_matches': True}

    def denied_read(component, destination):
        client.call('GET', 'secret/data/' + PATHS[destination], token=tokens[component], expected=(403,))
        return {'http': 403}

    def denied_write(component):
        client.call('POST', 'secret/data/' + PATHS[component],
                    {'data': values[component]}, token=tokens[component], expected=(403,))
        return {'http': 403}

    def mixed_credentials():
        status, _ = client.call('POST', 'auth/approle/login',
            {'role_id': credentials['ci']['role_id'], 'secret_id': credentials['ansible']['secret_id']},
            expected=(400, 403))
        return {'http': status}

    try:
        for component in ('ci', 'ansible'):
            check(component + ': вход и срок токена', lambda value=component: login(value))
            check(component + ': чтение своего пути', lambda value=component: own_read(value))
            check(component + ': запрет записи', lambda value=component: denied_write(value))
            for destination in PATHS:
                if destination != component:
                    check(component + ': запрет чтения ' + destination,
                          lambda value=component, target=destination: denied_read(value, target))
        check('SecretID другого AppRole не подходит', mixed_credentials)
    finally:
        for number, token in enumerate(client.issued_tokens, 1):
            check('Отзыв проверочного токена ' + str(number),
                  lambda value=token: client.call('POST', 'auth/token/revoke-self', token=value, expected=(204,))[0])
    return {'ok': all(item['ok'] for item in checks), 'checks': checks,
            'passed': sum(item['ok'] for item in checks),
            'failed': sum(not item['ok'] for item in checks), 'tls_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', required=True)
    parser.add_argument('--address', default=os.environ.get('VAULT_ADDR', 'https://127.0.0.1:18200'))
    parser.add_argument('--admin-file', default=os.environ.get('INFRASEC_VAULT_ADMIN_FILE'))
    parser.add_argument('--oidc-file', default=os.environ.get('INFRASEC_OIDC_CLIENT_FILE'))
    parser.add_argument('--identity-file', default=os.environ.get('INFRASEC_IDENTITY_FILE'),
                        help='Необязательный закрытый JSON с паролями LDAP и Keycloak')
    parser.add_argument('--ca-file', default=os.environ.get('VAULT_CACERT'))
    parser.add_argument('--evidence-file', help='Файл только с безопасной сводкой, без значений и токенов')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--refresh-approle', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        directory = outside_repository(Path(args.private_dir), 'Закрытая папка')
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise SafeError('Закрытая папка должна иметь права 0700')
        if not args.ca_file:
            raise SafeError('Укажите --ca-file или VAULT_CACERT')
        client = Vault(args.address, Path(args.ca_file).expanduser())
        cluster_id = current_cluster(client)
        check_private_state(directory, cluster_id)
        if args.refresh_approle and not (directory / 'vault-state.json').is_file():
            raise SafeError('Сначала выполните полную настройку; замена AppRole доступна после неё')
        result = verify(client, directory) if args.verify else configure(args, client, directory, cluster_id)
        result['checked_at'] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        message = str(exc) if isinstance(exc, SafeError) else type(exc).__name__
        result = {'ok': False, 'error': message}
    if args.evidence_file:
        save_json(Path(args.evidence_file).expanduser().resolve(), result, private=False)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
