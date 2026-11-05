"""AppRole и чтение одного пути; токен отзывается при выходе из контекста."""
from contextlib import contextmanager
import hashlib
import requests

from common import SafeError, certificate, https_origin, required

SECRET_PATH = 'secret/data/infrasec/ci/deploy'


class Vault:
    def __init__(self):
        self.base = https_origin('VAULT_ADDR') + '/v1/'
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = certificate('VAULT_CACERT')
        self.token = None
        self.revoked = False

    def call(self, method, path, *, data=None, expected=200):
        headers = {'X-Vault-Token': self.token} if self.token else {}
        try:
            response = self.session.request(method, self.base + path, json=data,
                headers=headers, timeout=(10, 20), allow_redirects=False)
        except requests.RequestException:
            raise SafeError('Не удалось обратиться к Vault по защищённому соединению') from None
        # Ответ никогда не выводится: login содержит токен, KV — секрет.
        if response.status_code != expected:
            raise SafeError(f'Vault: {method} {path}, HTTP {response.status_code}')
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise SafeError('Vault вернул неожиданный формат ответа') from None

    def login(self):
        response = self.call('POST', 'auth/approle/login', data={
            'role_id': required('VAULT_ROLE_ID'), 'secret_id': required('VAULT_SECRET_ID')})
        self.token = response.get('auth', {}).get('client_token')
        if not isinstance(self.token, str) or not self.token:
            raise SafeError('Vault не выдал токен AppRole')

    def read_marker(self):
        result = self.call('GET', SECRET_PATH)
        marker = result.get('data', {}).get('data', {}).get('deploy_marker')
        if not isinstance(marker, str) or len(marker) < 32:
            raise SafeError('В Vault нет ожидаемого учебного deploy_marker')
        return {'key': 'deploy_marker', 'length': len(marker),
                'sha256': hashlib.sha256(marker.encode()).hexdigest(), 'path': SECRET_PATH}

    def revoke(self):
        if self.token:
            self.call('POST', 'auth/token/revoke-self', expected=204)
            self.revoked = True
            self.token = None


@contextmanager
def deploy_marker():
    client = Vault()
    try:
        client.login()
        yield client.read_marker()
    finally:
        try:
            client.revoke()
        finally:
            client.session.close()
