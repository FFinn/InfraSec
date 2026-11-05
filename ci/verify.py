#!/usr/bin/env python3
"""Сводный отчёт только по результатам задач текущего конвейера."""
import sys
from common import SafeError, read_report, save_report


def main():
    tests = read_report('tests')
    leaks = read_report('gitleaks')
    vault = read_report('vault')
    build = read_report('build')
    deploy = read_report('deploy')
    checks = {
        'application_tests': tests.get('ok') is True and tests.get('tests', 0) >= 16 and
                             tests.get('failures') == tests.get('errors') == tests.get('skipped') == 0,
        'no_secrets_in_git_history': leaks.get('ok') is True and leaks.get('history_findings') == 0 and leaks.get('history_exit_code') == 0,
        'no_secrets_in_working_directory': leaks.get('ok') is True and leaks.get('directory_findings') == 0 and leaks.get('directory_exit_code') == 0,
        'vault_secret_received': vault.get('ok') is True and vault.get('secret', {}).get('key') == 'deploy_marker',
        'vault_token_revoked': vault.get('token_revoked') is True,
        'oci_image_built': build.get('ok') is True and build.get('rootless') is True,
        'application_deployed': deploy.get('ok') is True and len(deploy.get('deployments', [])) == 2 and
                                all(item.get('ready') for item in deploy['deployments']),
        'vault_secret_used_in_deploy': deploy.get('marker_sha256') == vault.get('secret', {}).get('sha256'),
        'deploy_vault_token_revoked': deploy.get('vault_token_revoked') is True,
        'tls_verified': vault.get('tls_verified') is True and deploy.get('tls_verified') is True,
    }
    save_report('verification', {'ok': all(checks.values()), 'checks': checks,
        'tests_passed': tests.get('tests'), 'image': build.get('image'),
        'deployments': deploy.get('deployments'), 'secret_values_in_report': False})
    for name, result in checks.items():
        print(name + ': ' + ('пройдена' if result else 'ошибка'))
    if not all(checks.values()):
        raise SafeError('Не все проверки конвейера завершились успешно')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else 'Сводная проверка не выполнена: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
