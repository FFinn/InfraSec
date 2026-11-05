"""Короткие сообщения ошибок и отчёты без учётных данных."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


class SafeError(Exception):
    pass


def required(name):
    value = os.environ.get(name)
    if not value:
        raise SafeError('Не задана переменная ' + name)
    return value


def https_origin(name):
    value = required(name)
    parts = urlsplit(value)
    if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or
            parts.query or parts.fragment or parts.path not in ('', '/')):
        raise SafeError(name + ' должен быть HTTPS-адресом без дополнительных параметров')
    return value.rstrip('/')


def certificate(name):
    path = Path(required(name))
    if not path.is_file():
        raise SafeError(name + ' должен указывать на файл сертификата CA')
    return str(path)


def metadata():
    commit = required('CI_COMMIT_SHA')
    pipeline = required('CI_PIPELINE_ID')
    if not re.fullmatch(r'[0-9a-f]{40,64}', commit) or not pipeline.isdigit():
        raise SafeError('Неверные идентификаторы запуска GitLab')
    return {'commit': commit, 'pipeline_id': pipeline,
            'recorded_at': datetime.now(timezone.utc).isoformat()}


def save_report(name, value):
    directory = Path('ci-artifacts')
    directory.mkdir(mode=0o700, exist_ok=True)
    value = {**metadata(), **value}
    path = directory / (name + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write('\n')


def read_report(name):
    result = json.loads(Path('ci-artifacts', name + '.json').read_text())
    identifiers = metadata()
    if result.get('commit') != identifiers['commit'] or result.get('pipeline_id') != identifiers['pipeline_id']:
        raise SafeError('Отчёт относится к другому запуску: ' + name)
    return result
