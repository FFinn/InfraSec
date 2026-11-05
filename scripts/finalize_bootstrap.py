#!/usr/bin/env python3
"""Завершить первичную настройку: ограниченный просмотр и отзыв initial root token."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from vault_setup import ROOT, SafeError, Vault, read_private_json, outside_repository, save_json


def require(condition, message):
    if not condition:
        raise SafeError(message)


def run(args):
    evidence = Path(args.evidence_file).expanduser().resolve()
    require((ROOT / 'artifacts').resolve() in evidence.parents,
            'Сводку можно записать только в каталог artifacts проекта')
    initial = read_private_json(Path(args.init_file), 'Файл инициализации')
    require(len(initial.get('keys_base64', [])) == 3 and bool(initial.get('root_token')),
            'Нужны сохранённые три доли ключа и initial root token')
    inspector_path = outside_repository(Path(args.inspector_file), 'Файл доступа для просмотра')
    inspector_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not inspector_path.parent.stat().st_mode & 0o077, 'Закрытый каталог должен иметь права 0700')
    api = Vault(args.address, Path(args.ca_file).expanduser().resolve())
    root_token = initial['root_token']
    root_status, _ = api.call('GET', 'auth/token/lookup-self', token=root_token, expected=(200, 403))
    if not inspector_path.exists():
        require(root_status == 200, 'Root уже отозван; для нового доступа требуется процедура восстановления')
        policy = (ROOT / 'vault/policies/infrasec-inspector.hcl').read_text()
        api.call('PUT', 'sys/policies/acl/infrasec-inspector', {'policy': policy}, root_token, expected=(204,))
        _, result = api.call('POST', 'auth/token/create-orphan', {
            'policies': ['infrasec-inspector'], 'no_default_policy': True,
            'ttl': '1h', 'explicit_max_ttl': '1h', 'renewable': False,
            'display_name': 'infrasec-final-inspection'}, root_token)
        save_json(inspector_path, {'token': result['auth']['client_token']})
    inspector = read_private_json(inspector_path, 'Файл доступа для просмотра')['token']
    for path in ('sys/storage/raft/configuration', 'sys/mounts', 'sys/auth', 'sys/audit',
                 'sys/policies/acl/infrasec-frontend'):
        api.call('GET', path, token=inspector)
    _, lookup = api.call('GET', 'auth/token/lookup-self', token=inspector)
    require(lookup['data']['policies'] == ['infrasec-inspector'] and lookup['data']['orphan'],
            'Доступ для просмотра должен быть независимым и без default/root')
    denied, _ = api.call('GET', 'secret/data/infrasec/app/frontend', token=inspector, expected=(403,))
    revoked = root_status == 403
    if args.revoke_root and not revoked:
        api.call('POST', 'auth/token/revoke-self', token=root_token, expected=(204,))
        code, _ = api.call('GET', 'auth/token/lookup-self', token=root_token, expected=(403,))
        revoked = code == 403
    api.call('GET', 'auth/token/lookup-self', token=inspector)
    summary = {'ok': True, 'checked_at': datetime.now(timezone.utc).isoformat(),
               'initial_root_revoked': revoked, 'inspector_policy': 'infrasec-inspector',
               'inspector_orphan': True, 'inspector_ttl_max_seconds': 3600,
               'inspector_cannot_read_secrets': denied == 403,
               'recovery_shares_preserved': True, 'secret_values_in_report': False}
    save_json(evidence, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', default='https://127.0.0.1:18202')
    parser.add_argument('--init-file', required=True)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument('--inspector-file', required=True)
    parser.add_argument('--evidence-file', default='artifacts/vault/bootstrap-finalized.json')
    parser.add_argument('--revoke-root', action='store_true', help='Отозвать root после всех настроек')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        run(args)
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
