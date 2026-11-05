#!/usr/bin/env python3
"""Подготовить config.toml собственного Runner; регистрация и запуск не выполняются.

Пример:
  python3 scripts/runner_setup.py --runner-file /private/gitlab/runner.json \
      --private-dir /private/runner
  docker compose --env-file /private/runner/runner.env \
      -f ci/runner-compose.yaml up -d

Все пути к реквизитам и результатам должны находиться вне репозитория.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
GITLAB_URL = 'https://devsecops.gitlab.yandexcloud.net'
RUNNER_IMAGE = 'gitlab/gitlab-runner:alpine-v19.3.1'


class SafeError(Exception):
    pass


def external(value, label):
    path = Path(value).expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise SafeError(label + ' должен находиться вне репозитория')
    if '\n' in str(path) or '\r' in str(path):
        raise SafeError(label + ': путь содержит недопустимый перевод строки')
    return path


def read_credentials(path):
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077:
        raise SafeError('runner.json должен быть обычным закрытым файлом с правами 0600 или 0400')
    value = json.loads(path.read_text())
    if (value.get('host') != 'devsecops.gitlab.yandexcloud.net' or
            value.get('url', GITLAB_URL).rstrip('/') != GITLAB_URL):
        raise SafeError('runner.json относится к другому серверу GitLab')
    if not isinstance(value.get('id'), int) or value['id'] <= 0:
        raise SafeError('В runner.json отсутствует корректный id Runner')
    token = value.get('token')
    if not isinstance(token, str) or not token.startswith('glrt-') or re.search(r'\s', token):
        raise SafeError('Нужен authentication token Runner из API user/runners')
    expires = value.get('token_expires_at')
    if expires:
        expiry = datetime.fromisoformat(expires.replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise SafeError('Срок authentication token Runner истёк или не содержит часовой пояс')
    return value


def toml_string(value):
    # Экранирование JSON basic strings совместимо с basic strings TOML.
    return json.dumps(value, ensure_ascii=False)


def configuration(credentials, gateway):
    token = toml_string(credentials['token'])
    hosts = ', '.join(toml_string(name + ':' + gateway)
                      for name in ('infrasec-vault-active.infrasec-vault.svc', 'kubernetes'))
    return f'''# Создано scripts/runner_setup.py; файл содержит закрытый authentication token.
concurrent = 1
check_interval = 3
shutdown_timeout = 30
log_level = "info"
log_format = "json"

[[runners]]
  name = "InfraSec Mac"
  url = "{GITLAB_URL}"
  id = {credentials['id']}
  token = {token}
  executor = "docker"
  limit = 1
  request_concurrency = 1
  output_limit = 4096
  [runners.feature_flags]
    FF_NETWORK_PER_BUILD = true
    FF_DISABLE_UMASK_FOR_DOCKER_EXECUTOR = true
  [runners.docker]
    host = "unix:///var/run/docker.sock"
    image = "python:3.12-slim-bookworm"
    privileged = false
    services_privileged = false
    disable_entrypoint_overwrite = false
    oom_kill_disable = false
    disable_cache = false
    volumes = ["/cache"]
    pull_policy = ["always"]
    memory = "2g"
    memory_swap = "2g"
    cpus = "2"
    security_opt = ["seccomp:unconfined", "apparmor:unconfined"]
    extra_hosts = [{hosts}]
'''


def save_without_replacing(path, content):
    if path.exists():
        if path.read_text() != content:
            raise SafeError(path.name + ' уже существует и отличается; автоматическая перезапись отключена')
        if not stat.S_ISREG(path.stat().st_mode):
            raise SafeError(path.name + ': нужен обычный файл')
        path.chmod(0o600)
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-file', required=True)
    parser.add_argument('--private-dir', required=True)
    parser.add_argument('--docker-host-address', default='192.168.65.254')
    args = parser.parse_args()
    os.umask(0o077)
    source = external(args.runner_file, 'Файл authentication token')
    directory = external(args.private_dir, 'Каталог конфигурации Runner')
    gateway = ipaddress.ip_address(args.docker_host_address)
    if gateway.version != 4 or not gateway.is_private or gateway.is_unspecified or gateway.is_loopback:
        raise SafeError('Адрес Docker host должен быть частным IPv4-адресом шлюза Docker Desktop')
    credentials = read_credentials(source)
    config = configuration(credentials, str(gateway))
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    config_directory = directory / 'config'
    config_directory.mkdir(mode=0o700, exist_ok=True)
    config_directory.chmod(0o700)
    save_without_replacing(config_directory / 'config.toml', config)
    save_without_replacing(directory / 'runner.env', 'INFRASEC_RUNNER_CONFIG_DIR=' + str(config_directory) + '\n')
    print(json.dumps({'ok': True, 'runner_id': credentials['id'], 'runner_image': RUNNER_IMAGE,
        'config_file': str(config_directory / 'config.toml'), 'env_file': str(directory / 'runner.env'),
        'concurrent_jobs': 1, 'job_privileged': False, 'job_memory': '2g', 'job_cpus': 2,
        'job_volumes': ['/cache'], 'docker_socket_in_jobs': False,
        'network_per_build': True, 'rootless_image_workdir_ownership': True,
        'authentication_token_printed': False}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else 'Конфигурация Runner не подготовлена: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
