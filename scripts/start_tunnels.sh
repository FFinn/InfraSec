#!/usr/bin/env bash
# Запускать на компьютере оператора; SSH-ключи и конфигурации остаются вне Git.
set -euo pipefail
: "${INFRASEC_IDENTITY_SSH_CONFIG:?Укажите файл SSH-конфигурации DSO07}"
: "${INFRASEC_K8S_SSH_CONFIG:?Укажите файл SSH-конфигурации DSO08}"
root="$(cd "$(dirname "$0")/.." && pwd)"
identity_ip="${INFRASEC_IDENTITY_IP:-10.91.0.36}"
k8s_ip="${INFRASEC_K8S_IP:-10.91.0.17}"
children=()
cleanup() { for child in "${children[@]}"; do kill "$child" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
identity_tunnel() {
  while true; do
    ssh -F "$INFRASEC_IDENTITY_SSH_CONFIG" -o ControlMaster=no -S none \
      -o ExitOnForwardFailure=yes -N \
      -L 127.0.0.1:18081:127.0.0.1:8085 \
      -L "127.0.0.1:18443:$identity_ip:8443" dso07 || true
    sleep 2
  done
}
kubernetes_tunnel() {
  while true; do
    ssh -F "$INFRASEC_K8S_SSH_CONFIG" -o ControlMaster=no -S none \
      -o ExitOnForwardFailure=yes \
      -L 127.0.0.1:18080:127.0.0.1:18080 \
      -L 127.0.0.1:18082:127.0.0.1:18082 \
      -L 127.0.0.1:18202:127.0.0.1:18202 \
      -L 127.0.0.1:16443:127.0.0.1:6443 \
      -R "$k8s_ip:18443:127.0.0.1:18443" dso08 'bash -s' < "$root/scripts/node_forwards.sh" || true
    sleep 2
  done
}
identity_tunnel & children+=("$!")
kubernetes_tunnel & children+=("$!")
wait
