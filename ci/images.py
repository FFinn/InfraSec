"""Проверка неизменяемого адреса образа по отчёту текущей сборки."""
import re

from common import SafeError


def validated_deployment_image(build, registry_image, commit):
    if not isinstance(registry_image, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]+', registry_image):
        raise SafeError('Недопустимое имя реестра приложения')
    expected_tag = registry_image + '/app:' + commit
    digest = build.get('digest')
    if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise SafeError('Нет корректного SHA256 digest собранного образа')
    immutable = registry_image + '/app@' + digest
    if (build.get('ok') is not True or build.get('image') != expected_tag or
            build.get('deployment_image') != immutable):
        raise SafeError('Адрес образа или digest не соответствует текущей сборке')
    return immutable


def deployments_match_image(deployments, image):
    return (isinstance(deployments, list) and len(deployments) == 2 and
            all(isinstance(item, dict) and item.get('ready') is True and
                item.get('namespace') == 'infrasec' and item.get('image') == image for item in deployments) and
            {item.get('name') for item in deployments} == {'frontend', 'backend'})
