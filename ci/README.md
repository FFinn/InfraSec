# Конвейер GitLab CI

Конвейер запускается для основной защищённой ветки и защищённой ветки `infrastructure`, в которой работа проверяется перед слиянием. Используется Runner с меткой `infrasec`; имя метки можно изменить переменной `INFRASEC_RUNNER_TAG`.

Этапы:

1. `unit_tests` запускает тесты приложения и требует не менее 16 успешных проверок без пропусков.
2. `gitleaks` проверяет всю историю Git и полное содержимое текущего коммита встроенными правилами. Файлы для второй проверки извлекаются в закрытую временную папку без служебного `.git/config`, где Runner может хранить реквизиты клонирования. Исключения находок и комментарии `gitleaks:allow` не учитываются.
3. `vault_secrets` входит по AppRole, читает `secret/data/infrasec/ci/deploy`, выводит только имя `deploy_marker`, длину и SHA256. Полученный токен отзывается.
4. `build_image` собирает OCI-образ из `app/` с помощью BuildKit без Docker daemon, отправляет его в `$CI_REGISTRY_IMAGE/app:$CI_COMMIT_SHA` и сохраняет неизменяемый digest в отчёт сборки.
5. `deploy_application` использует адрес образа с digest, повторно получает маркер из Vault, проверяет его контрольную сумму и добавляет её в аннотацию пода. Применяются только два Deployment из `manifests/10-apps.yaml`. Готовность новых реплик проверяется через Kubernetes API.
6. `verify_pipeline` сверяет отчёты одного коммита и конвейера. Итоговый JSON не содержит токенов или значений секретов.

## Переменные проекта

| Переменная | Тип и защита | Назначение |
|---|---|---|
| `VAULT_ADDR` | Protected | HTTPS-адрес Vault, для стенда `https://infrasec-vault-active.infrasec-vault.svc:18202` |
| `VAULT_ROLE_ID` | Masked, Protected | RoleID роли `infrasec-ci` |
| `VAULT_SECRET_ID` | Masked, Protected | Ограниченный по времени и числу использований SecretID |
| `VAULT_CACERT` | File, Protected | Открытый сертификат CA для проверки TLS Vault |
| `KUBE_API_URL` | Protected | HTTPS-адрес Kubernetes API |
| `KUBE_TOKEN` | Masked, Protected | Короткоживущий токен отдельного `infrasec-deployer` |
| `KUBE_CA_CERT` | File, Protected | Открытый CA Kubernetes API |

Роль Vault разрешает только чтение указанного пути и отзыв собственного токена. Сервисному аккаунту Kubernetes нужны `get`, `create`, `patch` для Deployment в `infrasec`; права на Secret, RBAC или другие пространства имён не требуются. Для дополнительного ограничения Role может заранее разрешать работу только с созданными Deployment `frontend` и `backend`; тогда операция `create` не нужна.

Переменные `CI_REGISTRY`, `CI_REGISTRY_IMAGE`, `CI_REGISTRY_USER` и `CI_REGISTRY_PASSWORD` предоставляет GitLab. Реквизиты реестра записываются во временный `config.json` с правами `0600`, используются BuildKit и удаляются при завершении задачи. Они не передаются в сборку как аргументы и не сохраняются в образе или артефактах.

Перед развёртыванием оператор создаёт Namespace, ServiceAccount, службы, сетевые правила, CA и `imagePullSecret` для чтения реестра. Это выполняет `scripts/bootstrap_kubernetes.py`. В `manifests/10-apps.yaml` контейнер приложения должен содержать `image: INFRASEC_APP_IMAGE`. Значение заменяется только в памяти на адрес образа текущей сборки с digest. Создание или изменение Secret конвейеру не разрешено.

## Runner и доступ к сети

Runner должен видеть Vault, Kubernetes API и реестр GitLab. На стенде адрес `infrasec-vault-active.infrasec-vault.svc` должен разрешаться в доступный адрес Vault; настройка DNS/hosts выполняется на Runner. Все обращения Python к Vault и Kubernetes проверяют сертификат CA; перенаправления и использование прокси из окружения отключены.

BuildKit работает от непривилегированного пользователя и не монтирует Docker socket. Для вложенных пользовательских пространств имён Runner может потребовать настройки seccomp/AppArmor. Параметр `--oci-worker-no-process-sandbox` соответствует рекомендации GitLab для rootless BuildKit; поэтому Runner используется только доверенным защищённым проектом.

При `CI_DEBUG_TRACE=true` правила запрещают создание конвейера; дополнительная проверка есть перед командами задач. Скрипты не выводят тела ответов Vault/Kubernetes, переменные окружения или конфигурацию Docker. Полные находки Gitleaks не выгружаются: в артефактах остаются только число находок и коды завершения. `--soft-fail` и исключения секретов не используются.

Срок действия AppRole SecretID и токена Kubernetes должен покрывать запуск конвейера. После истечения оператор выпускает новые реквизиты и заменяет защищённые переменные. Начальный root token Vault в GitLab не передаётся.

Документация: [BuildKit в GitLab](https://docs.gitlab.com/ci/docker/using_buildkit/), [Gitleaks](https://github.com/gitleaks/gitleaks), [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle).
