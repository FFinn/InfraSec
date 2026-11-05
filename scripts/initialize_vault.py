#!/usr/bin/env python3
"""Инициализировать отдельный Raft-кластер Vault, сохранив ключи вне Git."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib import error, request

ROOT = Path(__file__).resolve().parent.parent
NAMESPACE = 'infrasec-vault'
PODS = ['infrasec-vault-' + str(index) for index in range(3)]


class SafeError(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise SafeError(message)


def save(path, value, *, exclusive=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o600)


def kubectl(*arguments):
    run = subprocess.run(['kubectl', '-n', NAMESPACE, *arguments], capture_output=True,
                         text=True, timeout=120)
    require(run.returncode == 0, 'Ошибка kubectl при работе с новым namespace infrasec-vault')
    return run.stdout


class Api:
    def __init__(self, port, ca_path):
        self.base = 'https://127.0.0.1:' + str(port) + '/v1/'
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_path))))

    def call(self, method, path, data=None, token=None, expected=(200,)):
        headers = {'X-Vault-Token': token} if token else {}
        payload = None
        if data is not None:
            headers['Content-Type'] = 'application/json'
            payload = json.dumps(data).encode()
        query = request.Request(self.base + path, method=method, headers=headers, data=payload)
        try:
            response = self.opener.open(query, timeout=15)
        except error.HTTPError as exc:
            response = exc
        with response:
            status, content = response.status, response.read()
        require(status in expected, f'Vault {method} {path}: HTTP {status}')
        return json.loads(content) if content else None


def wait_until(action, description, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = action()
        if value:
            return value
        time.sleep(1)
    raise SafeError(description)


def start_forward(pod, port, client):
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            raise SafeError('Локальный порт для настройки уже занят: ' + str(port)) from None
    process = subprocess.Popen(['kubectl', '-n', NAMESPACE, 'port-forward', '--address=127.0.0.1',
                                'pod/' + pod, str(port) + ':8200'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def connected():
        require(process.poll() is None, 'Прерван проброс порта к ' + pod)
        try:
            return client.call('GET', 'sys/init') is not None
        except error.URLError:
            return False
    try:
        wait_until(connected, 'Нет доступа к API ' + pod, timeout=35)
    except Exception:
        process.terminate()
        process.wait(timeout=10)
        raise
    return process


def unseal(client, keys):
    status = client.call('GET', 'sys/seal-status')
    if status['sealed']:
        # Сбрасывается только незавершённый ввод долей, а не само хранилище.
        client.call('PUT', 'sys/unseal', {'reset': True})
        for key in keys[:2]:
            status = client.call('PUT', 'sys/unseal', {'key': key})
    def unsealed():
        current = client.call('GET', 'sys/seal-status')
        return current if not current['sealed'] else False
    # При Raft join Shamir challenge завершается после ответа на вторую долю.
    return wait_until(unsealed, 'Vault не разблокирован после двух долей', timeout=25)


def health(client):
    return client.call('GET', 'sys/health', expected=(200, 429, 472, 473, 501, 503))


def run(args):
    private = Path(args.private_dir).expanduser().resolve()
    require(private != ROOT and ROOT not in private.parents, 'Ключи нужно хранить вне репозитория')
    evidence = Path(args.evidence_file).expanduser().resolve()
    require((ROOT / 'artifacts').resolve() in evidence.parents,
            'Сводку можно записать только в каталог artifacts проекта')
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not private.stat().st_mode & 0o077, 'Закрытая папка должна иметь права 0700')
    ca = base64.b64decode(kubectl('get', 'secret', 'infrasec-vault-tls', '-o',
                                r'jsonpath={.data.ca\.crt}')).decode()
    ca_path = private / 'ca.crt'
    if ca_path.exists():
        require(ca_path.read_text() == ca, 'CA отличается от сохранённого; требуется ручная проверка')
    else:
        save(ca_path, ca, exclusive=True)
    clients = [Api(args.base_port + index, ca_path) for index in range(3)]
    forwards = []
    try:
        for index, pod in enumerate(PODS):
            forwards.append(start_forward(pod, args.base_port + index, clients[index]))
        init_path = private / 'vault-init.json'
        initialized = clients[0].call('GET', 'sys/init')['initialized']
        if not initialized:
            require(not init_path.exists(), 'Сохранены ключи другого хранилища; инициализация остановлена')
            initial = clients[0].call('POST', 'sys/init', {'secret_shares': 3, 'secret_threshold': 2})
            save(init_path, initial, exclusive=True)
        require(init_path.is_file() and not init_path.stat().st_mode & 0o077,
                'Нужен закрытый vault-init.json с правами 0600')
        initial = json.loads(init_path.read_text())
        keys = initial.get('keys_base64', [])
        require(len(keys) == 3 and bool(initial.get('root_token')), 'Нужны три доли именно нового Vault')
        token = initial['root_token']
        if args.admin_file:
            admin_path = Path(args.admin_file).expanduser().resolve()
            require(admin_path != ROOT and ROOT not in admin_path.parents and
                    admin_path.is_file() and not admin_path.stat().st_mode & 0o077,
                    'Административный файл должен находиться вне Git и иметь права 0600')
            admin = json.loads(admin_path.read_text())
            token = admin.get('token') or admin.get('root_token')
            require(isinstance(token, str) and bool(token), 'Нет административного токена')
        leader_status = unseal(clients[0], keys)
        require(leader_status.get('n') == 3 and leader_status.get('t') == 2 and
                leader_status.get('storage_type') == 'raft',
                'Параметры нового хранилища должны быть Raft и 3 доли с порогом 2')
        state_path = private / 'ha-state.json'
        if state_path.exists():
            require(json.loads(state_path.read_text()).get('cluster_id') == leader_status['cluster_id'],
                    'Сохранённая отметка относится к другому кластеру')
        # После перезапуска существующего кластера для выбора лидера нужен кворум.
        for index in (1, 2):
            if clients[index].call('GET', 'sys/seal-status')['initialized']:
                unseal(clients[index], keys)
        def selected_leader():
            for index, client in enumerate(clients):
                status = health(client)
                if status['initialized'] and not status['sealed'] and not status['standby']:
                    return index, status
            return False
        first_active, _ = wait_until(selected_leader, 'Не выбран лидер Raft-кластера')
        leader = clients[first_active].call('GET', 'sys/leader')['leader_address']
        require(leader.startswith('https://'), 'Лидер должен использовать TLS')
        for index in (1, 2):
            status = clients[index].call('GET', 'sys/seal-status')
            if not status['initialized']:
                joined = clients[index].call('POST', 'sys/storage/raft/join', {
                    'leader_api_addr': leader, 'leader_ca_cert': ca,
                    'leader_tls_servername': leader.split('/')[2].split(':')[0]})
                require(joined.get('joined') is True, 'Узел не присоединился к Raft')
            unseal(clients[index], keys)
        def ready_peers():
            states = [health(client) for client in clients]
            active = [index for index, status in enumerate(states) if not status['sealed'] and not status['standby']]
            if len(active) != 1 or any(status['sealed'] for status in states):
                return False
            response = clients[active[0]].call('GET', 'sys/storage/raft/configuration', token=token)
            servers = response['data']['config']['servers']
            return (states, active[0], servers) if len(servers) == 3 and all(server['voter'] for server in servers) else False
        states, active, servers = wait_until(ready_peers, 'Не получены три голосующих участника Raft', timeout=90)
        require({server['node_id'] for server in servers} == set(PODS), 'Неожиданный состав Raft-кластера')
        require(sum(bool(server['leader']) for server in servers) == 1, 'У Raft должен быть один лидер')
        kubectl('wait', '--for=condition=Ready', *('pod/' + pod for pod in PODS), '--timeout=90s')
        kubectl('rollout', 'status', 'deployment/infrasec-vault-agent-injector', '--timeout=90s')
        # Файловый аудит хранится на отдельном постоянном томе каждого экземпляра.
        audits = clients[active].call('GET', 'sys/audit', token=token)['data']
        if 'file/' not in audits:
            clients[active].call('POST', 'sys/audit/file',
                {'type': 'file', 'options': {'file_path': '/vault/audit/audit.log'}}, token=token, expected=(204,))
        def active_endpoints():
            endpoint = json.loads(kubectl('get', 'endpoints', 'infrasec-vault-active', '-o', 'json'))
            names = [address.get('targetRef', {}).get('name') for subset in endpoint.get('subsets', [])
                     for address in subset.get('addresses', [])]
            return names if names == [PODS[active]] else False
        endpoints = wait_until(active_endpoints, 'Active Service не выбрал текущего лидера', timeout=45)
        pods = json.loads(kubectl('get', 'pods', *PODS, '-o', 'json'))['items']
        safe = {'ok': True, 'checked_at': datetime.now(timezone.utc).isoformat(),
                'namespace': NAMESPACE, 'release': 'infrasec-vault', 'storage_type': 'raft',
                'tls_verified': True, 'shares': 3, 'threshold': 2, 'audit_file_enabled': True,
                'active_count': 1, 'standby_count': 2, 'voters': 3,
                'peers': [{key: server[key] for key in ('node_id', 'address', 'leader', 'voter')} for server in servers],
                'pods': [{'name': item['metadata']['name'], 'phase': item['status']['phase'],
                          'ready': any(condition['type'] == 'Ready' and condition['status'] == 'True'
                                       for condition in item['status'].get('conditions', [])),
                          'node': item['spec']['nodeName']} for item in pods],
                'health': [{'pod': PODS[index], 'initialized': status['initialized'], 'sealed': status['sealed'],
                            'standby': status['standby'], 'version': status['version']} for index, status in enumerate(states)],
                'active_service': 'https://infrasec-vault-active.infrasec-vault.svc:8200',
                'active_service_endpoints': endpoints,
                'physical_ha_limit': 'Три экземпляра Raft размещены на одной учебной ВМ; отказ ВМ остановит весь кластер.'}
        save(state_path, {'cluster_id': leader_status['cluster_id'], 'shares': 3, 'threshold': 2})
        save(evidence, safe)
        print(json.dumps(safe, ensure_ascii=False, indent=2))
        return 0
    finally:
        for process in forwards:
            process.terminate()
        for process in forwards:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', required=True)
    parser.add_argument('--base-port', type=int, default=18210)
    parser.add_argument('--admin-file', help='Внешний токен для проверки после отзыва initial root token')
    parser.add_argument('--evidence-file', default='artifacts/vault/ha-status.json')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        return run(args)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, SafeError) else type(exc).__name__},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
