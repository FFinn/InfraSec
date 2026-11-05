#!/usr/bin/env bash
# Выполняется на DSO08 через SSH; повторяет проброс после смены подов.
set -euo pipefail
children=()
cleanup() { for child in "${children[@]}"; do kill "$child" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
forward() {
  while true; do
    kubectl -n "$1" port-forward --address=127.0.0.1 "$2" "$3" || true
    sleep 2
  done
}
forward infrasec service/frontend 18080:8000 & children+=("$!")
forward infrasec service/backend 18082:8000 & children+=("$!")
forward infrasec-vault service/infrasec-vault-active 18202:8200 & children+=("$!")
wait
