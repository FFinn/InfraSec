#!/usr/bin/env python3
"""Подготовка защищённых файлов и настройка Keycloak/LDAP без вывода секретов."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from urllib import error, parse, request

REPOSITORY = Path(__file__).resolve().parent.parent
REALM = 'infrasec'
CLIENT = 'infrasec-web'
BIND_DN = 'cn=keycloak-reader,ou=services,dc=infrasec,dc=test'
USERS_DN = 'ou=users,dc=infrasec,dc=test'


def save_private(path, value, *, replace=False):
    content = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
    if path.exists() and not replace:
        if path.read_text() != content:
            raise RuntimeError(f'Существующий закрытый файл отличается: {path.name}')
        os.chmod(path, 0o600)
        return
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(content)
    os.chmod(path, 0o600)


def ssha(password):
    salt = secrets.token_bytes(16)
    return '{SSHA}' + base64.b64encode(hashlib.sha1(password.encode() + salt).digest() + salt).decode()


def prepare(private, public_url):
    target = private / 'identity.json'
    if target.exists():
        values = json.loads(target.read_text())
        if values['public_url'] != public_url:
            raise RuntimeError('Адрес существующего стенда отличается; требуется отдельный закрытый каталог')
    else:
        values = {
            'realm': REALM, 'client_id': CLIENT, 'public_url': public_url,
            'bootstrap_admin_username': 'bootstrap-infrasec',
            'bootstrap_admin_password': secrets.token_urlsafe(32),
            'keycloak_admin_username': 'infrasec-admin',
            'keycloak_admin_password': secrets.token_urlsafe(32),
            'postgres_password': secrets.token_urlsafe(32),
            'ldap_admin_password': secrets.token_urlsafe(32),
            'ldap_config_password': secrets.token_urlsafe(32),
            'ldap_bind_dn': BIND_DN, 'ldap_bind_password': secrets.token_urlsafe(32),
            'users': {},
        }
        values['ldap_bind_password_hash'] = ssha(values['ldap_bind_password'])
        for name, first, last in (('alice', 'Alice', 'Ivanova'), ('bob', 'Bob', 'Petrov')):
            password = secrets.token_urlsafe(24)
            values['users'][name] = {'username': name, 'first_name': first, 'last_name': last,
                                      'email': name + '@infrasec.test', 'password': password,
                                      'password_hash': ssha(password)}
        save_private(target, values)
    environment = '\n'.join([
        'IDENTITY_PRIVATE_DIR=' + str(private),
        'POSTGRES_PASSWORD=' + values['postgres_password'],
        'KEYCLOAK_BOOTSTRAP_USERNAME=' + values['bootstrap_admin_username'],
        'KEYCLOAK_BOOTSTRAP_PASSWORD=' + values['bootstrap_admin_password'],
        'LDAP_ADMIN_PASSWORD=' + values['ldap_admin_password'],
        'LDAP_CONFIG_PASSWORD=' + values['ldap_config_password'],
        'KC_PUBLIC_URL=' + public_url,
        '',
    ])
    save_private(private / 'identity.env', environment)
    # ldapsearch -y считает перевод строки частью пароля.
    save_private(private / 'ldap-reader-password', values['ldap_bind_password'])
    entries = [
        'dn: ou=users,dc=infrasec,dc=test\nobjectClass: organizationalUnit\nou: users',
        'dn: ou=services,dc=infrasec,dc=test\nobjectClass: organizationalUnit\nou: services',
        'dn: ' + BIND_DN + '\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\n'
        'cn: keycloak-reader\ndescription: Read-only directory account for Keycloak\n'
        'userPassword: ' + values['ldap_bind_password_hash'],
    ]
    for user in values['users'].values():
        entries.append('\n'.join([
            'dn: uid=' + user['username'] + ',' + USERS_DN,
            'objectClass: inetOrgPerson', 'objectClass: organizationalPerson', 'objectClass: person',
            'uid: ' + user['username'], 'cn: ' + user['first_name'] + ' ' + user['last_name'],
            'sn: ' + user['last_name'], 'givenName: ' + user['first_name'],
            'mail: ' + user['email'], 'userPassword: ' + user['password_hash'],
        ]))
    save_private(private / 'ldap-bootstrap.ldif', '\n\n'.join(entries) + '\n')
    print('Закрытые файлы для Keycloak, PostgreSQL и LDAP подготовлены.')
    return values


class Keycloak:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.token = None

    def send(self, method, path, data=None, *, form=False, expected=(200, 201, 204), authenticated=True):
        headers = {}
        if authenticated and self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        body = None
        if data is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            body = (parse.urlencode(data) if form else json.dumps(data)).encode()
        req = request.Request(self.base + path, method=method, headers=headers, data=body)
        try:
            response = request.urlopen(req, timeout=30)
        except error.HTTPError as exc:
            response = exc
        with response:
            status, content = response.code, response.read()
        if status not in expected:
            # Тело ответа не выводится: в нём могут быть чувствительные параметры.
            raise RuntimeError(f'Keycloak {method} {path.split("?")[0]}: HTTP {status}')
        return json.loads(content) if content else None

    def login(self, username, password):
        result = self.send('POST', '/realms/master/protocol/openid-connect/token', {
            'grant_type': 'password', 'client_id': 'admin-cli',
            'username': username, 'password': password,
        }, form=True, authenticated=False)
        self.token = result['access_token']

    def realm(self, method, path='', data=None, **kwargs):
        return self.send(method, '/admin/realms/' + REALM + path, data, **kwargs)


def configure(values, private, keycloak_url, ldap_url, evidence_dir):
    kc = Keycloak(keycloak_url)
    try:
        kc.login(values['keycloak_admin_username'], values['keycloak_admin_password'])
    except RuntimeError:
        kc.login(values['bootstrap_admin_username'], values['bootstrap_admin_password'])
    realms = kc.send('GET', '/admin/realms')
    configuration = {
        'realm': REALM, 'enabled': True, 'displayName': 'Защищённая инфраструктура',
        'sslRequired': 'none', 'registrationAllowed': False, 'resetPasswordAllowed': False,
        'rememberMe': False, 'loginWithEmailAllowed': False, 'duplicateEmailsAllowed': False,
        'bruteForceProtected': True, 'failureFactor': 5, 'waitIncrementSeconds': 30,
        'maxFailureWaitSeconds': 300, 'accessTokenLifespan': 300,
        'ssoSessionIdleTimeout': 900, 'ssoSessionMaxLifespan': 3600,
        'eventsEnabled': True, 'eventsExpiration': 604800,
        'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False,
        'internationalizationEnabled': True, 'supportedLocales': ['ru', 'en'], 'defaultLocale': 'ru',
    }
    if not any(item['realm'] == REALM for item in realms):
        kc.send('POST', '/admin/realms', configuration)
    else:
        kc.realm('PUT', '', configuration)
    realm = kc.realm('GET')
    client = {
        'clientId': CLIENT, 'name': 'Учебное приложение', 'protocol': 'openid-connect',
        'enabled': True, 'publicClient': False, 'clientAuthenticatorType': 'client-secret',
        'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'redirectUris': ['http://127.0.0.1:18080/auth/callback'],
        'webOrigins': ['http://127.0.0.1:18080'], 'rootUrl': 'http://127.0.0.1:18080',
        'attributes': {'pkce.code.challenge.method': 'S256',
                       'post.logout.redirect.uris': 'http://127.0.0.1:18080/'},
        'defaultClientScopes': ['web-origins', 'acr', 'profile', 'roles', 'basic', 'email'],
    }
    found = kc.realm('GET', '/clients?clientId=' + CLIENT)
    if found:
        if len(found) != 1:
            raise RuntimeError('Найдено несколько клиентов с одинаковым clientId')
        client['id'] = found[0]['id']
        kc.realm('PUT', '/clients/' + client['id'], client)
    else:
        kc.realm('POST', '/clients', client)
        client['id'] = kc.realm('GET', '/clients?clientId=' + CLIENT)[0]['id']
    secret = kc.realm('GET', '/clients/' + client['id'] + '/client-secret')['value']
    values['oidc_client_secret'] = secret
    values['client_uuid'] = client['id']

    ldap = {
        'enabled': 'true', 'importEnabled': 'true', 'vendor': 'other', 'editMode': 'READ_ONLY',
        'syncRegistrations': 'false', 'connectionUrl': ldap_url, 'authType': 'simple',
        'bindDn': BIND_DN, 'bindCredential': values['ldap_bind_password'],
        'usersDn': USERS_DN, 'usernameLDAPAttribute': 'uid', 'rdnLDAPAttribute': 'uid',
        'uuidLDAPAttribute': 'entryUUID', 'userObjectClasses': 'inetOrgPerson,organizationalPerson',
        'searchScope': '2', 'pagination': 'true', 'startTls': 'false',
        'useTruststoreSpi': 'never', 'connectionPooling': 'true', 'connectionTimeout': '5000',
        'readTimeout': '10000', 'fullSyncPeriod': '86400', 'changedSyncPeriod': '900',
        'cachePolicy': 'DEFAULT', 'priority': '0', 'validatePasswordPolicy': 'false', 'trustEmail': 'false',
    }
    components = kc.realm('GET', '/components?type=org.keycloak.storage.UserStorageProvider')
    existing = [item for item in components if item['name'] == 'OpenLDAP InfraSec']
    provider = {'name': 'OpenLDAP InfraSec', 'providerId': 'ldap',
                'providerType': 'org.keycloak.storage.UserStorageProvider', 'parentId': realm['id'],
                'config': {key: [value] for key, value in ldap.items()}}
    if existing:
        if len(existing) != 1:
            raise RuntimeError('Найдено несколько провайдеров OpenLDAP InfraSec')
        provider['id'] = existing[0]['id']
        kc.realm('PUT', '/components/' + provider['id'], provider)
    else:
        kc.realm('POST', '/components', provider)
        provider['id'] = next(item['id'] for item in kc.realm(
            'GET', '/components?type=org.keycloak.storage.UserStorageProvider')
            if item['name'] == 'OpenLDAP InfraSec')
    tests = {}
    for action in ('testConnection', 'testAuthentication'):
        kc.realm('POST', '/testLDAPConnection', {
            'action': action, 'connectionUrl': ldap_url, 'bindDn': BIND_DN,
            'bindCredential': values['ldap_bind_password'], 'authType': 'simple',
            'startTls': 'false', 'useTruststoreSpi': 'never', 'connectionTimeout': '5000',
            'componentId': provider['id'],
        }, expected=(204,))
        tests[action] = 204
    sync = kc.realm('POST', '/user-storage/' + provider['id'] + '/sync?action=triggerFullSync')
    if sync['failed']:
        raise RuntimeError('При синхронизации LDAP возникли ошибки')
    users = []
    for username in values['users']:
        found = kc.realm('GET', '/users?exact=true&username=' + username)
        if len(found) != 1 or found[0].get('federationLink') != provider['id']:
            raise RuntimeError('Пользователь LDAP не импортирован корректно: ' + username)
        users.append({key: found[0][key] for key in ('username', 'id', 'federationLink')})
    all_users = kc.realm('GET', '/users?max=100')
    if any(not item.get('federationLink') for item in all_users):
        raise RuntimeError('В прикладном realm найдены локальные пользователи')

    master = '/admin/realms/master'
    administrators = kc.send('GET', master + '/users?exact=true&username=' + values['keycloak_admin_username'])
    if not administrators:
        kc.send('POST', master + '/users', {
            'username': values['keycloak_admin_username'], 'enabled': True,
            'firstName': 'InfraSec', 'lastName': 'Administrator',
            'email': 'admin@infrasec.test', 'emailVerified': True, 'requiredActions': [],
        })
        admin_id = kc.send('GET', master + '/users?exact=true&username=' + values['keycloak_admin_username'])[0]['id']
        kc.send('PUT', master + '/users/' + admin_id + '/reset-password', {
            'type': 'password', 'value': values['keycloak_admin_password'], 'temporary': False})
        role = kc.send('GET', master + '/roles/admin')
        kc.send('POST', master + '/users/' + admin_id + '/role-mappings/realm', [role])
    # Проверяем нового администратора до отключения временной учётной записи.
    kc.login(values['keycloak_admin_username'], values['keycloak_admin_password'])
    bootstrap = kc.send('GET', master + '/users?exact=true&username=' + values['bootstrap_admin_username'])
    if bootstrap:
        kc.send('PUT', master + '/users/' + bootstrap[0]['id'], {'enabled': False})
    values['bootstrap_disabled'] = True
    save_private(private / 'identity.json', values, replace=True)

    # Сохраняются только выбранные безопасные поля, без client secret и bindCredential.
    result = {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'realm': REALM, 'client': {key: client[key] for key in
           ('clientId', 'protocol', 'publicClient', 'standardFlowEnabled',
            'implicitFlowEnabled', 'directAccessGrantsEnabled', 'serviceAccountsEnabled',
            'redirectUris', 'webOrigins', 'attributes')},
        'ldap': {key: value for key, value in ldap.items() if key != 'bindCredential'},
        'ldap_provider_id': provider['id'], 'connection_tests': tests, 'sync': sync,
        'users': users, 'all_app_users_federated': True, 'bootstrap_admin_disabled': True,
        'permanent_admin_uses_random_password': True,
    }
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        save_private(evidence_dir / 'identity-settings.json', result, replace=True)
    print(json.dumps({'realm': REALM, 'client': CLIENT, 'users_synced': len(users),
                      'ldap_tests': tests, 'bootstrap_admin_disabled': True}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', type=Path, required=True)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--keycloak-url', default='http://127.0.0.1:8085')
    parser.add_argument('--public-url', default='http://127.0.0.1:18081')
    parser.add_argument('--ldap-url', default='ldap://openldap:389')
    parser.add_argument('--evidence-dir', type=Path)
    args = parser.parse_args()
    private = args.private_dir.expanduser().resolve()
    if private == REPOSITORY or REPOSITORY in private.parents:
        raise RuntimeError('Закрытый каталог должен находиться вне репозитория')
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(private, 0o700)
    if args.prepare:
        prepare(private, args.public_url.rstrip('/'))
        return
    values = json.loads((private / 'identity.json').read_text())
    configure(values, private, args.keycloak_url, args.ldap_url, args.evidence_dir)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, RuntimeError) else 'Настройка не выполнена: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
