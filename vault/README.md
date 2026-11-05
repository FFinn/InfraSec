# Секреты и права доступа

Для проекта разворачивается отдельный Vault в серверном режиме HA с Raft и TLS. Три экземпляра используют постоянные тома данных и аудита; режимы `dev` и `standalone` выключены. KV v2 включён по пути `secret/`.

Установку выполняет `scripts/install_vault.sh`, инициализацию и разблокировку — `scripts/initialize_vault.py`. Затем `scripts/vault_setup.py` настраивает KV v2, AppRole, Kubernetes auth, аудит, ACL и роли. Порядок развёртывания описан в [корневом README](../README.md#развёртывание).

Три участника Raft размещены на одной учебной ВМ. При отказе отдельного процесса остаётся кворум, но отказ всей ВМ остановит все три экземпляра; это ограничение учебного размещения.

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
export VAULT_ADDR=https://127.0.0.1:18202
export VAULT_CACERT=/absolute/path/outside-repository/vault-ca.crt
export INFRASEC_VAULT_ADMIN_FILE=/absolute/path/outside-repository/vault-init.json
export INFRASEC_OIDC_CLIENT_FILE=/absolute/path/outside-repository/oidc-client.json
export INFRASEC_IDENTITY_FILE=/absolute/path/outside-repository/identity.json
python3 scripts/vault_setup.py \
  --private-dir /absolute/path/outside-repository/infrasec-private \
  --evidence-file artifacts/checks/vault-setup.json
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
  --verify --evidence-file artifacts/checks/vault-approle-check.json
```

Проверяются чтение своего секрета, запрет записи, запрет чтения остальных путей, срок токена и невозможность входа с SecretID другой роли. Все выданные для проверки токены отзываются. Скрипт возвращает ненулевой код, если хотя бы одна проверка не пройдена.

Для замены истёкших реквизитов выполните ту же команду настройки с `--refresh-approle` вместо `--verify`. Она не меняет значения приложения; действующие прежние SecretID отзываются, новые сохраняются в закрытой папке. После этого обновите защищённые переменные соответствующих CI-задач и источник реквизитов Ansible.

Метод AppRole и его параметры описаны в [официальной документации Vault](https://developer.hashicorp.com/vault/api-docs/auth/approle).

## Восстановление после остановки

После запуска ВМ дождитесь готовности Kubernetes и выполните `scripts/initialize_vault.py` с той же внешней закрытой папкой. Скрипт проверит CA и идентификатор хранилища, разблокирует три существующих экземпляра двумя сохранёнными долями и проверит лидера, кворум и active Service. Новое хранилище поверх сохранённых данных не создаётся.

После отзыва начального root token передайте отдельный действующий токен просмотра через `--admin-file`. Закрытый файл с ним должен находиться вне Git и иметь права `0600`:

```bash
python3 scripts/initialize_vault.py \
  --private-dir /home/ubuntu/devsecops/infrasec-ha-private \
  --admin-file /home/ubuntu/devsecops/infrasec-ha-private/inspector.json \
  --evidence-file artifacts/vault/ha-status.json
```

Токен `infrasec-inspector` действует не более часа. Пока срок не истёк, он позволяет проверить Raft и существующие настройки, но не читать секреты или менять конфигурацию. Для последующего административного восстановления нужен новый токен: процедура [`vault operator generate-root`](https://developer.hashicorp.com/vault/docs/commands/operator/generate-root) требует кворум держателей долей ключа; у этого хранилища — две из трёх долей. Используйте защиту результата OTP или PGP по официальной инструкции. Новый root token также предназначен только для необходимой административной операции и последующего отзыва. Доли ключа не передавайте как аргументы команд или в журналы.

Исходные доли ключа и начальный административный токен не передаются приложениям, Runner или Ansible. Резервные доли следует хранить отдельно; их содержимое нельзя включать в отчёт. Для просмотра безопасных параметров предусмотрен `scripts/inspect_vault.py` — он не читает значения KV.

## Завершение первичной настройки

После всех настроек и проверок подготовьте ограниченный доступ для просмотра. Команда ниже выполняется на компьютере оператора; `INFRASEC_PRIVATE` указывает на внешнюю закрытую папку:

```bash
python3 scripts/finalize_bootstrap.py \
  --init-file "$INFRASEC_PRIVATE/ha-vault/vault-init.json" \
  --ca-file "$INFRASEC_PRIVATE/ha-vault/ca.crt" \
  --inspector-file "$INFRASEC_PRIVATE/ha-vault/inspector.json" \
  --evidence-file artifacts/vault/bootstrap-finalized.json
```

Скрипт создаёт независимый от root токен с политикой [`infrasec-inspector`](policies/infrasec-inspector.hcl), предельным сроком один час и запретом продления. Он проверяет доступ к метаданным и отказ `403` при чтении KV. Без дополнительного флага начальный root token сохраняется действующим.

Когда изменения Vault больше не нужны, повторите эту команду с `--revoke-root`. Скрипт отзовёт начальный root token и проверит отказ `403` при повторном обращении с ним. Доли ключа сохраняются для unseal и восстановления. Значение токена в отчёт не записывается. После отзыва для просмотра используйте внешний `inspector.json`; перед восстановлением после остановки передайте его на DSO-08 по SSH, не меняя права `0600`.
