# Keycloak и LDAP

Отдельный проект Compose запускает Keycloak, PostgreSQL и OpenLDAP. Его контейнеры и тома не пересекаются с предыдущими уроками.

Образы: официальный `quay.io/keycloak/keycloak:26.8.1`, `postgres:17.11-bookworm`, `osixia/openldap:1.5.0`. Наличие версий Keycloak и PostgreSQL проверено в официальных источниках. OpenLDAP — прежний образ учебного стенда; он используется только в закрытой сети контейнеров. Отдельного веб-интерфейса LDAP нет.

## Первый запуск

Команды выполняются в корне проекта на ВМ. Закрытый каталог должен быть вне репозитория. Подставьте свой путь вместо `/home/debian/.local/share/infrasec-private/identity`.

```bash
python3 scripts/identity_setup.py \
  --private-dir /home/debian/.local/share/infrasec-private/identity --prepare

docker compose \
  --env-file /home/debian/.local/share/infrasec-private/identity/identity.env \
  -f identity/compose.yaml up -d

bash identity/apply-ldap-acl.sh \
  /home/debian/.local/share/infrasec-private/identity/identity.env
```

После готовности Keycloak:

```bash
python3 scripts/identity_setup.py \
  --private-dir /home/debian/.local/share/infrasec-private/identity \
  --keycloak-url http://127.0.0.1:8085 \
  --evidence-dir artifacts/identity

python3 identity/verify_ldap.py \
  --env-file /home/debian/.local/share/infrasec-private/identity/identity.env
```

Не сохраняйте вывод `docker compose config`, `docker inspect`, содержимое `identity.env` или `identity.json` в отчёт: эти данные содержат секреты. Подготовленные файлы имеют права `0600`, закрытый каталог — `0700`. LDAP LDIF содержит только солёные хеши паролей и также остаётся вне репозитория.

## Настройки

| Параметр | Значение |
|---|---|
| Realm приложения | `infrasec` |
| Клиент | `infrasec-web`, OpenID Connect, конфиденциальный |
| Разрешённый вход | Authorization Code, PKCE `S256` |
| Адрес возврата | `http://127.0.0.1:18080/auth/callback` |
| Публичный адрес Keycloak | `http://127.0.0.1:18081` через SSH |
| Порт Keycloak на ВМ | `127.0.0.1:8085` |
| LDAP | `ldap://openldap:389`, только в сети Compose |
| Каталог пользователей | `ou=users,dc=infrasec,dc=test` |
| Учётная запись подключения | `cn=keycloak-reader,ou=services,dc=infrasec,dc=test` |
| Режим федерации | `READ_ONLY`, импорт включён, запись регистраций выключена |
| Атрибуты логина / DN / UUID | `uid` / `uid` / `entryUUID` |
| Синхронизация | Полная — раз в сутки, изменений — раз в 15 минут |
| Учебные пользователи | `alice`, `bob` |

Keycloak запускается командой `start` с PostgreSQL. Режим `start-dev` не используется. Данные Keycloak, PostgreSQL, LDAP и конфигурация LDAP сохраняются в томах Docker.

В `infrasec` нет локальных пользователей: обе учётные записи импортированы из LDAP, пароль проверяется каталогом. Для управления создан отдельный администратор `infrasec-admin` в `master`; его случайный пароль хранится только в закрытом файле. Временный `bootstrap-infrasec` отключается после проверки постоянного администратора. Вход в приложение под учётной записью из `master` невозможен, поскольку это другой realm.

ACL LDAP разрешает читателю поиск записей пользователей, запрещает чтение `userPassword` и любые изменения. Анонимный поиск пользователей закрыт. Для проверки записи используется операция над описанием учебной записи; ожидается отказ `insufficientAccessRights (50)`.

Контейнеры PostgreSQL, LDAP и интерфейс управления Keycloak на порту 9000 не публикуют порты на ВМ. Между Keycloak и LDAP в этой версии используется обычный LDAP в отдельной сети Docker. Доступ к Keycloak по HTTP осуществляется через SSH-туннель; TLS для связи приложения с другой ВМ настраивается отдельным прокси. Настройка TLS-прокси не содержится в этом Compose-файле.

Скрипт сохраняет только выбранные безопасные параметры в `artifacts/identity/identity-settings.json`: настройки клиента, федерации, результаты соединения и синхронизации. Значения секретов в этот файл не попадают. `oidc_client_secret` в закрытом `identity.json` передаётся скрипту настройки Vault.

Документация: [запуск Keycloak в контейнере](https://www.keycloak.org/server/containers), [публичный адрес и служебные обращения](https://www.keycloak.org/server/hostname), [федерация LDAP](https://www.keycloak.org/docs/latest/server_admin/index.html#_ldap).
