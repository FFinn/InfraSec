#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
  echo 'Укажите путь к защищённому identity.env.' >&2
  exit 2
fi
compose_file="$(cd "$(dirname "$0")" && pwd)/compose.yaml"
docker compose --env-file "$1" -f "$compose_file" exec -T openldap \
  ldapmodify -Q -Y EXTERNAL -H ldapi:/// -f /run/infrasec-ldap-acl.ldif
