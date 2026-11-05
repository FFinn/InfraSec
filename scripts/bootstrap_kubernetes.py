#!/usr/bin/env python3
"""Подготовить InfraSec в Kubernetes, не записывая секреты в репозиторий.

Запускать с административным kubectl на ВМ Kubernetes. Python-зависимости:
  python3 -m pip install -r ci/requirements.txt

Без --apply-deployments создаются только необходимые ресурсы; Deployment применит CI.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
NAMESPACE = 'infrasec'
SERVICE_ACCOUNT = 'infrasec-deployer'
OWNER_KEY = 'infrasec.dev/managed-by'
OWNER = 'bootstrap-kubernetes'


class SafeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SafeError(message)


def outside(value, label):
    path = Path(value).expanduser().resolve()
    require(path != ROOT and ROOT not in path.parents, label + ' должен находиться вне репозитория')
    return path


def private_json(path, label):
    details = path.stat()
    require(stat.S_ISREG(details.st_mode) and not details.st_mode & 0o077,
            label + ': нужен обычный файл с правами 0600 или 0400')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), label + ': нужен JSON-объект')
    return value


def save(path, value, private=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600 if private else 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def kubectl(*arguments, data=None, missing=False):
    process = subprocess.run(['kubectl', *arguments], input=data, capture_output=True,
                             text=True, timeout=60)
    if process.returncode:
        if missing and 'NotFound' in process.stderr:
            return None
        # Не выводим stderr: клиент может повторить фрагмент секретного JSON.
        raise SafeError('Команда kubectl не выполнена: ' + ' '.join(arguments[:3]))
    return process.stdout


def get(item):
    arguments = ['get', item['kind'], item['metadata']['name'], '-o', 'json']
    if item['kind'] != 'Namespace':
        arguments.extend(['-n', NAMESPACE])
    result = kubectl(*arguments, missing=True)
    return json.loads(result) if result is not None else None


def clean(item):
    """Поля исходного описания без отметок kubectl и самого bootstrap."""
    result = json.loads(json.dumps(item))
    metadata = result['metadata']
    for key in ('creationTimestamp', 'generation', 'resourceVersion', 'uid', 'managedFields'):
        metadata.pop(key, None)
    annotations = metadata.get('annotations', {})
    annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
    annotations.pop(OWNER_KEY, None)
    if not annotations:
        metadata.pop('annotations', None)
    labels = metadata.get('labels', {})
    labels.pop('app.kubernetes.io/part-of', None)
    if not labels:
        metadata.pop('labels', None)
    result.pop('status', None)
    return result


def registry_auth(data, address):
    try:
        document = json.loads(base64.b64decode(data['.dockerconfigjson']))
        auths = document['auths']
        if set(auths) != {address}:
            return None
        entry = auths[address]
        if entry.get('auth'):
            return base64.b64decode(entry['auth']).decode().split(':', 1)
        return [entry['username'], entry['password']]
    except (ValueError, KeyError, UnicodeError, TypeError):
        return None


def owned(existing, desired, registry=None):
    if existing is None:
        return True
    annotations = existing['metadata'].get('annotations', {})
    if annotations.get(OWNER_KEY) not in (None, OWNER):
        return False
    if existing['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') not in (None, 'infrasec'):
        return False
    if annotations.get(OWNER_KEY) == OWNER:
        if desired['kind'] == 'Secret':
            return existing.get('type') == desired.get('type') and set(existing.get('data', {})) == set(desired['data'])
        return True
    # Допускается принять ранее применённый из этого же проекта объект,
    # только если сохранённое исходное описание совпадает с текущим.
    previous = annotations.get('kubectl.kubernetes.io/last-applied-configuration')
    if previous and desired['kind'] != 'Secret':
        try:
            if clean(json.loads(previous)) == clean(desired):
                return True
        except (ValueError, KeyError, TypeError):
            pass
    if desired['kind'] == 'Deployment':
        component = desired['metadata']['name']
        if component not in ('frontend', 'backend'):
            return False
        template = existing.get('spec', {}).get('template', {})
        return (existing.get('metadata', {}).get('namespace') == NAMESPACE and
                existing.get('spec', {}).get('selector') == desired['spec']['selector'] and
                template.get('spec', {}).get('serviceAccountName') == component + '-sa' and
                template.get('metadata', {}).get('annotations', {}).get('vault.hashicorp.com/role') ==
                'infrasec-' + component)
    if desired['kind'] == 'Secret' and desired['metadata']['name'] == 'infrasec-registry':
        return (existing.get('type') == desired['type'] and
                set(existing.get('data', {})) == {'.dockerconfigjson'} and
                registry_auth(existing['data'], registry['registry']) == [registry['username'], registry['token']])
    if desired['kind'] in ('Secret', 'ConfigMap'):
        return (existing.get('type') == desired.get('type') and
                existing.get('data') == desired.get('data'))
    return False


def apply(item, existing):
    item = json.loads(json.dumps(item))
    item['metadata'].setdefault('annotations', {})[OWNER_KEY] = OWNER
    item['metadata'].setdefault('labels', {})['app.kubernetes.io/part-of'] = 'infrasec'
    if item['kind'] == 'Secret':
        if (existing and existing.get('data') == item['data'] and
                existing.get('type') == item.get('type') and
                existing['metadata'].get('annotations', {}).get(OWNER_KEY) == OWNER and
                existing['metadata'].get('labels', {}).get('app.kubernetes.io/part-of') == 'infrasec'):
            return
        # Не создаём annotation last-applied с повторной копией реквизитов реестра.
        if existing:
            item['metadata']['resourceVersion'] = existing['metadata']['resourceVersion']
            kubectl('replace', '-f', '-', data=json.dumps(item))
        else:
            kubectl('create', '-f', '-', data=json.dumps(item))
    else:
        kubectl('apply', '-f', '-', data=json.dumps(item))


def token_claims(token):
    try:
        part = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    except (ValueError, IndexError, UnicodeError):
        raise SafeError('Неверный формат сохранённого токена Kubernetes') from None


def review(token):
    body = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview', 'spec': {'token': token}}
    result = json.loads(kubectl('create', '--raw', '/apis/authentication.k8s.io/v1/tokenreviews',
                                '-f', '-', data=json.dumps(body)))
    status = result.get('status', {})
    return bool(status.get('authenticated') and status.get('user', {}).get('username') ==
                'system:serviceaccount:' + NAMESPACE + ':' + SERVICE_ACCOUNT)


def kube_credentials(args, directory):
    ca_encoded = kubectl('config', 'view', '--minify', '--flatten', '--raw', '-o',
                        'jsonpath={.clusters[0].cluster.certificate-authority-data}')
    ca = base64.b64decode(ca_encoded).decode()
    require(ca.startswith('-----BEGIN CERTIFICATE-----') and 'PRIVATE KEY' not in ca,
            'Не удалось получить только открытый CA Kubernetes')
    ssl.create_default_context(cadata=ca)
    endpoint = args.kube_api_url.rstrip('/')
    address = urlsplit(endpoint)
    require(address.scheme == 'https' and address.hostname and not address.username and not address.password
            and not address.query and not address.fragment and address.path in ('', '/'),
            '--kube-api-url должен содержать HTTPS-адрес без учётных данных')
    target = directory / 'kube-ci.json'
    previous = private_json(target, 'Сохранённые реквизиты CI') if target.exists() else None
    now = datetime.now(timezone.utc).timestamp()
    reused = False
    if previous:
        previous_ca = previous.get('ca_certificate', '')
        if not previous_ca.startswith('-----BEGIN CERTIFICATE-----'):
            try:
                previous_ca = base64.b64decode(previous_ca).decode()
            except (ValueError, UnicodeError):
                raise SafeError('Сохранённый CA Kubernetes имеет неверный формат') from None
        require(previous.get('api_url') == endpoint and previous_ca.strip() == ca.strip(),
                'kube-ci.json относится к другому адресу API или CA; перезапись запрещена')
        claims = token_claims(previous.get('token', ''))
        require(claims.get('sub') == 'system:serviceaccount:' + NAMESPACE + ':' + SERVICE_ACCOUNT,
                'kube-ci.json относится к другому сервисному аккаунту')
        reused = not args.refresh_token and claims.get('exp', 0) > now + 600 and review(previous['token'])
    if reused:
        token = previous['token']
        expires = token_claims(token)['exp']
    else:
        body = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                'spec': {'expirationSeconds': args.token_duration}}
        result = json.loads(kubectl('create', '--raw',
            '/api/v1/namespaces/' + NAMESPACE + '/serviceaccounts/' + SERVICE_ACCOUNT + '/token',
            '-f', '-', data=json.dumps(body)))
        token = result['status']['token']
        claims = token_claims(token)
        require(review(token), 'Выданный токен не прошёл TokenReview ожидаемого сервисного аккаунта')
        expires = claims['exp']
        require(isinstance(expires, int) and now < expires <= now + args.token_duration + 60,
                'API выдал токен с неожиданным сроком действия')
    value = {'token': token, 'api_url': endpoint, 'ca_certificate': ca,
             'namespace': NAMESPACE, 'service_account': SERVICE_ACCOUNT,
             'expires_at': datetime.fromtimestamp(expires, timezone.utc).isoformat()}
    save(target, value, private=True)
    return {'credentials_file': target.name, 'token_reused': reused,
            'expires_at': value['expires_at'], 'requested_lifetime_seconds': args.token_duration}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument('--registry-file', required=True)
    parser.add_argument('--private-dir', required=True)
    parser.add_argument('--kube-api-url', required=True)
    parser.add_argument('--token-duration', type=int, default=10800)
    parser.add_argument('--refresh-token', action='store_true')
    parser.add_argument('--apply-deployments', action='store_true')
    parser.add_argument('--image')
    parser.add_argument('--evidence-file', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.evidence_file:
        args.evidence_file = args.evidence_file.expanduser().resolve()
        require((ROOT / 'artifacts') in args.evidence_file.parents and args.evidence_file.suffix == '.json',
                '--evidence-file должен указывать на JSON внутри artifacts этого репозитория')
    require(600 <= args.token_duration <= 10800, 'Допустимый срок CI-токена: от 600 до 10800 секунд')
    require(bool(args.image) == args.apply_deployments, '--image используется только вместе с --apply-deployments')
    address = urlsplit(args.kube_api_url)
    require(address.scheme == 'https' and address.hostname and not address.username and not address.password
            and not address.query and not address.fragment and address.path in ('', '/'),
            '--kube-api-url должен содержать HTTPS-адрес без учётных данных')
    if args.image:
        require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]+', args.image)), 'Неверное имя образа')
    directory = outside(args.private_dir, 'Закрытая папка')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not directory.stat().st_mode & 0o077, 'Закрытая папка должна иметь права 0700')
    ca = outside(args.ca_file, 'Файл CA Vault').read_text()
    require(ca.startswith('-----BEGIN CERTIFICATE-----') and 'PRIVATE KEY' not in ca,
            'Файл должен содержать только открытый CA Vault')
    ssl.create_default_context(cadata=ca)
    registry = private_json(outside(args.registry_file, 'Файл DeployToken'), 'Реквизиты реестра')
    require(registry.get('scopes') == ['read_registry'], 'Нужен DeployToken только с правом read_registry')
    require(all(isinstance(registry.get(key), str) and registry[key] for key in ('registry', 'username', 'token')),
            'В реквизитах реестра нужны registry, username и token')
    require(bool(re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', registry['registry'])), 'Неверный адрес реестра')
    if registry.get('expires_at'):
        expiry = datetime.fromisoformat(registry['expires_at'].replace('Z', '+00:00'))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        require(expiry > datetime.now(timezone.utc), 'Срок DeployToken истёк; нужны новые реквизиты реестра')
    documents = []
    for filename in ('00-namespace.yaml', '30-ci-rbac.yaml', '10-apps.yaml', '20-network-policies.yaml'):
        for item in yaml.safe_load_all((ROOT / 'manifests' / filename).read_text()):
            if not item:
                continue
            if item['kind'] == 'Deployment':
                if not args.apply_deployments:
                    continue
                replacements = 0
                for container in item['spec']['template']['spec']['containers']:
                    if container.get('image') == 'INFRASEC_APP_IMAGE':
                        container['image'] = args.image
                        replacements += 1
                require(replacements == 1, 'В Deployment ожидался один placeholder INFRASEC_APP_IMAGE')
            require((item['kind'] == 'Namespace' and item['metadata']['name'] == NAMESPACE) or
                    (item['metadata'].get('namespace') == NAMESPACE and item['kind'] in
                     ('ServiceAccount', 'Role', 'RoleBinding', 'Service', 'Deployment', 'NetworkPolicy')),
                    'Манифест выходит за пределы разрешённых ресурсов InfraSec')
            if item['kind'] == 'Role':
                require(not any('*' in rule.get(key, []) for rule in item.get('rules', [])
                                for key in ('apiGroups', 'resources', 'verbs')),
                        'Wildcard-права Role не допускаются')
            if item['kind'] == 'RoleBinding':
                require(item.get('roleRef', {}).get('kind') == 'Role' and
                        item['roleRef'].get('name') == SERVICE_ACCOUNT,
                        'RoleBinding должен ссылаться на ограниченную Role infrasec-deployer')
            documents.append(item)
    encoded_auth = base64.b64encode((registry['username'] + ':' + registry['token']).encode()).decode()
    docker_config = json.dumps({'auths': {registry['registry']: {'auth': encoded_auth}}})
    documents.extend([
        {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'infrasec-ca', 'namespace': NAMESPACE},
         'data': {'ca.crt': ca}},
        {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'vault-agent-ca', 'namespace': NAMESPACE},
         'type': 'Opaque', 'data': {'ca.crt': base64.b64encode(ca.encode()).decode()}},
        {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'infrasec-registry', 'namespace': NAMESPACE},
         'type': 'kubernetes.io/dockerconfigjson',
         'data': {'.dockerconfigjson': base64.b64encode(docker_config.encode()).decode()}},
    ])
    # Проверяем все конфликты до первого изменения кластера.
    planned = []
    for item in documents:
        existing = get(item)
        require(owned(existing, item, registry),
                item['kind'] + '/' + item['metadata']['name'] +
                ' уже существует без подтверждённого владения InfraSec; изменение остановлено')
        planned.append((item, existing))
    ordered = sorted(planned, key=lambda pair: 0 if pair[0]['kind'] == 'Namespace' else
                     (2 if pair[0]['kind'] == 'Deployment' else 1))
    for item, existing in ordered:
        apply(item, existing)
        if item['kind'] == 'Namespace':
            labels = json.loads(kubectl('get', 'namespace', NAMESPACE, '-o', 'json'))['metadata'].get('labels', {})
            if 'vault-injection' in labels:
                kubectl('label', 'namespace', NAMESPACE, 'vault-injection-')
    credentials = kube_credentials(args, directory)
    if args.apply_deployments:
        for name in ('frontend', 'backend'):
            kubectl('-n', NAMESPACE, 'rollout', 'status', 'deployment/' + name, '--timeout=180s')
    summary = {'ok': True, 'checked_at': datetime.now(timezone.utc).isoformat(),
               'namespace': NAMESPACE, 'resources': [item['kind'] + '/' + item['metadata']['name'] for item in documents],
               'deployments_applied': args.apply_deployments, 'only_public_ca_copied': True,
               'registry_scope': ['read_registry'], 'private_credentials_saved_outside_repository': True,
               'kubernetes_ci': credentials}
    if args.evidence_file:
        save(args.evidence_file, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else 'Подготовка Kubernetes не выполнена: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
