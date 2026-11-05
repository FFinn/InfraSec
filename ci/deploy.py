#!/usr/bin/env python3
"""Применение только Deployment через Kubernetes API с ограниченным токеном."""
import copy
import os
from pathlib import Path
import sys
import time
import requests
import yaml

from common import SafeError, certificate, https_origin, metadata, read_report, required, save_report
from images import validated_deployment_image
from vault_client import deploy_marker

NAMESPACE = 'infrasec'
EXPECTED_DEPLOYMENTS = {'frontend', 'backend'}


class Kubernetes:
    def __init__(self):
        self.base = https_origin('KUBE_API_URL')
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = certificate('KUBE_CA_CERT')
        self.session.headers['Authorization'] = 'Bearer ' + required('KUBE_TOKEN')

    def call(self, method, path, *, data=None, expected=(200,), patch=False):
        headers = {'Content-Type': 'application/strategic-merge-patch+json'} if patch else {}
        try:
            response = self.session.request(method, self.base + path, json=data, headers=headers,
                                            timeout=(10, 25), allow_redirects=False)
        except requests.RequestException:
            raise SafeError('Не удалось обратиться к Kubernetes API по защищённому соединению') from None
        if response.status_code not in expected:
            raise SafeError(f'Kubernetes: {method} {path}, HTTP {response.status_code}')
        try:
            result = response.json()
        except ValueError:
            raise SafeError('Kubernetes API вернул неожиданный формат ответа') from None
        return response.status_code, result


def expected_image():
    built = read_report('build')
    return validated_deployment_image(built, required('CI_REGISTRY_IMAGE'), metadata()['commit'])


def deployments(image, marker_hash):
    documents = list(yaml.safe_load_all(Path('manifests/10-apps.yaml').read_text()))
    result = []
    for document in documents:
        if not document or document.get('kind') != 'Deployment':
            continue
        item = copy.deepcopy(document)
        name = item.get('metadata', {}).get('name')
        namespace = item.get('metadata', {}).get('namespace')
        if item.get('apiVersion') != 'apps/v1' or name not in EXPECTED_DEPLOYMENTS or namespace != NAMESPACE:
            raise SafeError('Deployment не соответствует разрешённому набору ресурсов InfraSec')
        replacements = 0
        for container in item['spec']['template']['spec']['containers']:
            if container.get('image') == 'INFRASEC_APP_IMAGE':
                container['image'] = image
                replacements += 1
        if replacements != 1:
            raise SafeError('Ожидался один контейнер с образом INFRASEC_APP_IMAGE')
        annotations = item['spec']['template'].setdefault('metadata', {}).setdefault('annotations', {})
        annotations['infrasec.dev/ci-commit'] = metadata()['commit']
        annotations['infrasec.dev/pipeline-id'] = metadata()['pipeline_id']
        annotations['infrasec.dev/deploy-marker-sha256'] = marker_hash
        result.append(item)
    if {item['metadata']['name'] for item in result} != EXPECTED_DEPLOYMENTS or len(result) != 2:
        raise SafeError('Нужны ровно два Deployment: frontend и backend')
    return result


def wait_ready(api, name, image, marker_hash):
    path = '/apis/apps/v1/namespaces/' + NAMESPACE + '/deployments/' + name
    deadline = time.monotonic() + 240
    while True:
        _, item = api.call('GET', path)
        spec, status = item['spec'], item.get('status', {})
        desired = spec.get('replicas', 1)
        conditions = {condition['type']: condition for condition in status.get('conditions', [])}
        if conditions.get('Progressing', {}).get('reason') == 'ProgressDeadlineExceeded':
            raise SafeError('Превышен срок развёртывания Deployment ' + name)
        images = {container['image'] for container in spec['template']['spec']['containers']}
        annotation = spec['template']['metadata'].get('annotations', {})
        ready = (status.get('observedGeneration', 0) >= item['metadata']['generation'] and
                 status.get('updatedReplicas', 0) == desired and
                 status.get('availableReplicas', 0) == desired and
                 status.get('readyReplicas', 0) == desired and status.get('replicas', 0) == desired and
                 conditions.get('Available', {}).get('status') == 'True' and image in images and
                 annotation.get('infrasec.dev/deploy-marker-sha256') == marker_hash)
        if ready:
            return {'name': name, 'namespace': NAMESPACE, 'generation': item['metadata']['generation'],
                    'updated_replicas': status['updatedReplicas'],
                    'available_replicas': status['availableReplicas'], 'ready': True, 'image': image}
        if time.monotonic() >= deadline:
            raise SafeError('Не подтверждена готовность Deployment ' + name)
        time.sleep(4)


def main():
    image = expected_image()
    previous = read_report('vault')
    if not previous.get('ok') or not previous.get('token_revoked'):
        raise SafeError('Предыдущая проверка Vault не подтверждена')
    with deploy_marker() as marker:
        summary = dict(marker)
    if summary['sha256'] != previous['secret']['sha256']:
        raise SafeError('deploy_marker изменился между этапами; нужен новый запуск конвейера')
    api = Kubernetes()
    applied = []
    try:
        collection = '/apis/apps/v1/namespaces/' + NAMESPACE + '/deployments'
        for item in deployments(image, summary['sha256']):
            name = item['metadata']['name']
            path = collection + '/' + name
            status, _ = api.call('GET', path, expected=(200, 404))
            if status == 404:
                api.call('POST', collection, data=item, expected=(201,))
            else:
                api.call('PATCH', path, data=item, patch=True)
            applied.append(name)
        ready = [wait_ready(api, name, image, summary['sha256']) for name in applied]
    finally:
        api.session.close()
    save_report('deploy', {'ok': True, 'tls_verified': True, 'vault_token_revoked': True,
        'marker_key': summary['key'], 'marker_sha256': summary['sha256'],
        'kubernetes_resources_changed': ['Deployment/' + name for name in applied], 'deployments': ready})
    print('Развёрнуты frontend и backend. Готовность новых реплик подтверждена.')
    print('Секрет deploy_marker использован для контрольной суммы аннотации; значение не выводилось.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else 'Развёртывание не выполнено: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
