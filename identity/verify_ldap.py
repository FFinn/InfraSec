#!/usr/bin/env python3
"""Проверка прав читателя LDAP без раскрытия пароля или хешей."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    args = parser.parse_args()
    compose = ['docker', 'compose', '--env-file', str(args.env_file.resolve()), '-f',
               str(Path(__file__).resolve().parent / 'compose.yaml'), 'exec', '-T', 'openldap']
    authentication = ['-x', '-H', 'ldap://127.0.0.1:389',
                      '-D', 'cn=keycloak-reader,ou=services,dc=infrasec,dc=test',
                      '-y', '/run/secrets/ldap-reader-password']
    query = subprocess.run(compose + ['ldapsearch', '-LLL', *authentication,
        '-b', 'ou=users,dc=infrasec,dc=test', '(objectClass=inetOrgPerson)', 'uid', 'userPassword'],
        capture_output=True, text=True, timeout=30)
    if query.returncode:
        raise RuntimeError(f'LDAP-поиск от имени читателя завершился с кодом {query.returncode}')
    if 'uid: alice' not in query.stdout or 'uid: bob' not in query.stdout:
        raise RuntimeError('Читатель LDAP не получил ожидаемые записи')
    if 'userPassword:' in query.stdout or 'userPassword::' in query.stdout:
        raise RuntimeError('Читатель LDAP получил доступ к хешам паролей')
    change = ('dn: uid=alice,ou=users,dc=infrasec,dc=test\nchangetype: modify\n'
              'add: description\ndescription: readonly-access-negative-test\n')
    write = subprocess.run(compose + ['ldapmodify', *authentication], input=change,
                           capture_output=True, text=True, timeout=30)
    if write.returncode != 50:
        raise RuntimeError('Ожидался отказ LDAP insufficientAccessRights (50) при записи')
    anonymous = subprocess.run(compose + ['ldapsearch', '-LLL', '-x', '-H',
        'ldap://127.0.0.1:389', '-b', 'ou=users,dc=infrasec,dc=test',
        '(objectClass=inetOrgPerson)', 'uid'], capture_output=True, text=True, timeout=30)
    if 'uid: alice' in anonymous.stdout or 'uid: bob' in anonymous.stdout:
        raise RuntimeError('Анонимный пользователь может читать каталог')
    print(json.dumps({'reader_search_succeeded': True, 'reader_search_exit_code': query.returncode,
                      'password_hashes_not_readable': True,
                      'reader_write_denied_code': write.returncode,
                      'anonymous_user_search_denied': True}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
