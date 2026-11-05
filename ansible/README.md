# Настройка компонента через Ansible

Плейбук `deploy.yml` входит в Vault через отдельный AppRole, читает `secret/data/infrasec/infrastructure/credentials` и создаёт файл `deploy.conf` на целевой ВМ. Значение `deploy_password` передаётся в файл, затем сверяется его контрольная сумма. Права каталога — `0700`, файла — `0600`.

Все задачи, обрабатывающие учётные данные, используют `no_log: true`; показ различий отключён. Адрес Vault должен использовать HTTPS, сертификат проверяется по указанному CA. После выполнения, в том числе при ошибке основной задачи, временный токен отзывается.

На контроллере нужен Python 3.11 или новее:

```bash
python3 -m venv /absolute/path/outside-repository/ansible-env
/absolute/path/outside-repository/ansible-env/bin/python -m pip install -r ansible/requirements.txt
```

Перед запуском задайте пути, не значения секретов:

```bash
export VAULT_ADDR=https://127.0.0.1:18200
export VAULT_CACERT=/absolute/path/outside-repository/vault-ca.crt
export INFRASEC_ANSIBLE_APPROLE_FILE=/absolute/path/outside-repository/infrasec-private/ansible-approle.json
/absolute/path/outside-repository/ansible-env/bin/ansible-playbook \
  -i /absolute/path/outside-repository/inventory.yml ansible/deploy.yml
```

В закрытом inventory определите группу `infrasec`, SSH-подключение и пользователя целевой ВМ. Параметры SSH берутся из настройки учебного подключения; проверку ключа сервера отключать не нужно. `inventory.example.yml` предназначен для запуска непосредственно на целевой ВМ с локальным подключением. В таком случае контроллеру также нужен Python 3.11 или новее.

Запросы в Vault выполняются на контроллере (`delegate_to: localhost`), а конфигурация записывается на целевой ВМ по пути `/home/ubuntu/devsecops/infrasec/config/deploy.conf`. При необходимости путь задаётся через `-e deploy_directory=/absolute/target/path`, но его нельзя выбирать внутри рабочего Git-репозитория.

Запустите плейбук дважды. На втором запуске файл не должен меняться: в безопасном сообщении будет `Изменена: False`. Сам пароль в выводе отсутствует. Код и журнал успешного запуска не содержат токена или SecretID; они читаются из закрытого JSON-файла, сформированного `scripts/vault_setup.py`.

Используется встроенный [REST-модуль Ansible URI](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/uri_module.html), дополнительные коллекции не нужны. Секреты хранятся в HashiCorp Vault, поэтому пароль для Ansible Vault здесь не требуется.
