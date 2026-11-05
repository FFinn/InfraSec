#!/usr/bin/env python3
"""Показать проверяемые настройки Vault только через GET, без чтения секретов KV."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import stat
import sys
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ['infrasec-frontend', 'infrasec-backend', 'infrasec-ci', 'infrasec-ansible']


class SafeError(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise SafeError(message)


def outside(value):
    path = Path(value).expanduser().resolve()
    require(path != ROOT and ROOT not in path.parents, 'Файлы доступа должны находиться вне репозитория')
    return path


class ReadOnlyVault:
    def __init__(self, address, ca_path, token):
        origin = parse.urlsplit(address)
        require(origin.scheme == 'https' and origin.hostname and not origin.username and
                not origin.password and origin.path in ('', '/') and not origin.query and not origin.fragment,
                'Нужен HTTPS-адрес Vault без логина и дополнительных параметров')
        self.base, self.token = address.rstrip('/') + '/v1/', token
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_path))))

    def get(self, path, *, authenticated=True, statuses=(200,)):
        headers = {'X-Vault-Token': self.token} if authenticated else {}
        query = request.Request(self.base + path, method='GET', headers=headers)
        try:
            response = self.opener.open(query, timeout=20)
        except error.HTTPError as exc:
            response = exc
        with response:
            code, content = response.status, response.read()
        require(code in statuses, f'Vault GET {path}: HTTP {code}')
        return json.loads(content) if content else None


def status(client):
    seal = client.get('sys/seal-status', authenticated=False)
    health = client.get('sys/health', authenticated=False, statuses=(200, 429, 472, 473, 501, 503))
    leader = client.get('sys/leader', authenticated=False)
    servers = client.get('sys/storage/raft/configuration')['data']['config']['servers']
    require(not any('$(' in server.get('address', '') for server in servers),
            'В адресе участника Raft осталась нераскрытая переменная')
    return {'initialized': seal['initialized'], 'sealed': seal['sealed'],
            'version': health['version'], 'storage_type': seal['storage_type'],
            'key_shares': seal['n'], 'unseal_threshold': seal['t'],
            'standby': health['standby'], 'leader_address': leader['leader_address'],
            'voters': sum(bool(server['voter']) for server in servers),
            'leaders': sum(bool(server['leader']) for server in servers),
            'addresses_expanded': True,
            'peers': [{key: server[key] for key in ('node_id', 'address', 'leader', 'voter')} for server in servers],
            'tls_verified': True}


def engines(client):
    mounts = client.get('sys/mounts')['data']
    return [{'path': path, 'type': settings['type'],
             'version': (settings.get('options') or {}).get('version')}
            for path, settings in sorted(mounts.items())]


def authentication(client):
    methods = client.get('sys/auth')['data']
    return [{'path': path, 'type': settings['type']} for path, settings in sorted(methods.items())]


def policies(client):
    result = []
    for name in POLICIES:
        configured = client.get('sys/policies/acl/' + name)['data']['policy']
        reviewed = (ROOT / 'vault/policies' / (name + '.hcl')).read_text()
        # Не печатать неизвестное содержимое, если ACL расходится с проверенным кодом.
        require(configured.strip() == reviewed.strip(),
                'Политика ' + name + ' отличается от файла проекта; автоматический показ остановлен')
        result.append({'name': name, 'policy': configured})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', default=os.environ.get('VAULT_ADDR', 'https://127.0.0.1:18202'))
    parser.add_argument('--admin-file', default=os.environ.get('INFRASEC_VAULT_ADMIN_FILE'))
    parser.add_argument('--ca-file', default=os.environ.get('VAULT_CACERT'))
    parser.add_argument('--section', choices=('all', 'status', 'engines', 'auth', 'policies'), default='all')
    parser.add_argument('--evidence-file')
    args = parser.parse_args()
    output_target = None
    try:
        if args.evidence_file:
            candidate = Path(args.evidence_file).expanduser().resolve()
            require((ROOT / 'artifacts').resolve() in candidate.parents,
                    'Сводку можно записать только в каталог artifacts проекта')
            output_target = candidate
        require(args.admin_file and args.ca_file, 'Укажите пути к административному JSON и открытому CA')
        admin_path = outside(args.admin_file)
        details = admin_path.stat()
        require(stat.S_ISREG(details.st_mode) and not details.st_mode & 0o077,
                'Административный файл должен быть обычным файлом с правами 0600 или 0400')
        admin = json.loads(admin_path.read_text())
        token = admin.get('root_token') or admin.get('token')
        require(isinstance(token, str) and bool(token), 'В административном JSON нет токена')
        client = ReadOnlyVault(args.address, outside(args.ca_file), token)
        result = {'ok': True, 'checked_at': datetime.now(timezone.utc).isoformat()}
        sections = {'status': status, 'engines': engines, 'auth': authentication, 'policies': policies}
        for name, action in sections.items():
            if args.section in ('all', name):
                result[name] = action(client)
    except Exception as exc:
        result = {'ok': False, 'error': str(exc) if isinstance(exc, SafeError) else type(exc).__name__}
    if output_target is not None:
        target = output_target
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
            output.write('\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
