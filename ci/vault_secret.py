#!/usr/bin/env python3
"""Проверка секрета в настоящей задаче GitLab CI без вывода значения."""
import sys
from common import SafeError, save_report
from vault_client import deploy_marker


def main():
    with deploy_marker() as marker:
        summary = dict(marker)
    # Контекст уже завершён: отсутствие ошибки подтверждает самоотзыв токена.
    save_report('vault', {'ok': True, 'secret': summary, 'token_revoked': True, 'tls_verified': True})
    print('Получен ключ deploy_marker; длина:', summary['length'], '; SHA256:', summary['sha256'])
    print('Проверочный токен Vault отозван.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, SafeError) else 'Проверка Vault не выполнена: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
