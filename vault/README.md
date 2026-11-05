# Секреты и права доступа

Используется существующий сервер Vault с TLS и KV v2 по пути `secret/`. Скрипт не инициализирует хранилище, не меняет его ключи и не заменяет настройки проверки Kubernetes JWT.

| Компонент | Роль | Доступный путь KV v2 |
|---|---|---|
| Frontend | Kubernetes `infrasec-frontend` | `secret/data/infrasec/app/frontend` |
| Backend | Kubernetes `infrasec-backend` | `secret/data/infrasec/app/backend` |
| GitLab CI | AppRole `infrasec-ci` | `secret/data/infrasec/ci/deploy` |
| Ansible | AppRole `infrasec-ansible` | `secret/data/infrasec/infrastructure/credentials` |

Политики в `policies/` разрешают чтение одного точного пути. Права на другие секреты, изменение данных и просмотр настроек Vault не выдаются. Kubernetes-роли связаны только с `frontend-sa` и `backend-sa` в пространстве имён `infrasec`; аудитория JWT — `vault`.

Политика `default` к новым токенам не добавляется. Агентам разрешены чтение сведений, продление и отзыв собственного токена. CI и Ansible могут проверить и отозвать собственный токен. Предельный срок Kubernetes-токенов Vault — 15 минут; AppRole-токенов — 10 минут, начальный срок — 5 минут. SecretID действует два часа и допускает не более 20 входов. Срок токена Vault не ограничивает срок самого статического API-ключа.

## Первичная настройка

Ключ разблокировки, административный токен и исходные пароли должны находиться вне репозитория. Параметр `--private-dir` обязателен и не допускает каталог внутри проекта. Закрытая папка должна иметь права `0700`, файлы с реквизитами — `0600` или `0400`.

Передайте через окружение:

```bash
export VAULT_ADDR=https://127.0.0.1:18200
export VAULT_CACERT=/absolute/path/outside-repository/vault-ca.crt
export INFRASEC_VAULT_ADMIN_FILE=/absolute/path/outside-repository/vault-init.json
export INFRASEC_OIDC_CLIENT_FILE=/absolute/path/outside-repository/oidc-client.json
export INFRASEC_IDENTITY_FILE=/absolute/path/outside-repository/identity.json
python3 scripts/vault_setup.py \
  --private-dir /absolute/path/outside-repository/infrasec-private \
  --evidence-file artifacts/vault-setup.json
```

Административный JSON содержит поле `root_token` или `token`. Файл клиента — `client_secret` или `oidc_client_secret`, полученный при настройке Keycloak. `INFRASEC_IDENTITY_FILE` необязателен: весь JSON из него помещается в `secret/data/infrasec/infrastructure/identity`. Этот путь не доступен ни приложению, ни CI, ни роли Ansible; он предназначен для административного хранения паролей Keycloak и LDAP.

Скрипт создаёт случайные учебные API-ключи и пароли. Backend и frontend получают один согласованный API-ключ. Секрет клиента берётся из Keycloak и не заменяется другим случайным значением. Повторный запуск сохраняет существующие значения; если секрет клиента в исходном файле изменён, в Vault записывается новая версия. Запись KV защищена проверкой номера версии CAS.

В закрытой папке создаются:

- `app-values.json` — учебные значения для сверки и восстановления;
- `ci-approle.json` и `ansible-approle.json` — раздельные RoleID и SecretID;
- `vault-state.json` — идентификатор конкретного хранилища для защиты от ошибочного повторного использования папки.

Сводка в `--evidence-file` содержит только пути, имена политик и настройки сроков. Значения, токены и SecretID туда не записываются.

## Проверка прав

```bash
python3 scripts/vault_setup.py \
  --private-dir /absolute/path/outside-repository/infrasec-private \
  --verify --evidence-file artifacts/vault-access.json
```

Проверяются чтение своего секрета, запрет записи, запрет чтения остальных путей, срок токена и невозможность входа с SecretID другой роли. Все выданные для проверки токены отзываются. Скрипт возвращает ненулевой код, если хотя бы одна проверка не пройдена.

Для замены истёкших реквизитов выполните ту же команду настройки с `--refresh-approle` вместо `--verify`. Она не меняет значения приложения; действующие прежние SecretID отзываются, новые сохраняются в закрытой папке. После этого обновите защищённые переменные соответствующих CI-задач и источник реквизитов Ansible.

Метод AppRole и его параметры описаны в [официальной документации Vault](https://developer.hashicorp.com/vault/api-docs/auth/approle).
