#!/usr/bin/env bash
# Выполнять на DSO08. Разрешён один адрес обратного SSH-проброса.
set -euo pipefail
bridge_ip="${INFRASEC_K8S_IP:-10.91.0.17}"
case "$bridge_ip" in
  *[!0-9.]*|'') echo 'Неверный IP учебной ВМ' >&2; exit 1;;
esac
configuration="$(mktemp)"
trap 'rm -f "$configuration"' EXIT
printf 'GatewayPorts clientspecified\nPermitListen %s:18443\n' "$bridge_ip" > "$configuration"
sudo install -m 0644 "$configuration" /etc/ssh/sshd_config.d/60-infrasec-bridge.conf
sudo /usr/sbin/sshd -t
sudo systemctl reload ssh
echo 'Разрешён обратный SSH-проброс только на заданный частный адрес и порт 18443.'
