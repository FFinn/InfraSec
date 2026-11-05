#!/usr/bin/env bash
# Запускать на учебной ВМ с kubectl, Helm, cert-manager и local-path.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
chart_directory="${VAULT_CHART_DIR:-$HOME/.cache/infrasec/vault-helm-0.31.0}"
expected_commit=da81d965d3968a19a3da9286f0993da5cd0866de
if [[ ! -e "$chart_directory" ]]; then
  mkdir -p "$(dirname "$chart_directory")"
  git clone --depth 1 --branch v0.31.0 https://github.com/hashicorp/vault-helm.git "$chart_directory"
fi
[[ "$(git -C "$chart_directory" rev-parse HEAD)" == "$expected_commit" ]] || {
  echo 'Версия официального чарта отличается от проверенной.' >&2
  exit 1
}
[[ -z "$(git -C "$chart_directory" status --porcelain)" ]] || {
  echo 'В копии официального чарта есть изменения.' >&2
  exit 1
}
kubectl get crd certificates.cert-manager.io >/dev/null
kubectl get storageclass local-path >/dev/null
kubectl apply -f vault/tls.yaml
kubectl -n infrasec-vault wait --for=condition=Ready certificate/infrasec-ca --timeout=120s
kubectl -n infrasec-vault wait --for=condition=Ready certificate/infrasec-vault-server --timeout=120s
helm lint "$chart_directory" -f vault/ha-values.yaml
helm upgrade --install infrasec-vault "$chart_directory" -n infrasec-vault -f vault/ha-values.yaml
for index in 0 1 2; do
  pod="infrasec-vault-$index"
  for attempt in {1..60}; do
    if kubectl -n infrasec-vault get pod "$pod" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  kubectl -n infrasec-vault wait --for=jsonpath='{.status.phase}'=Running "pod/$pod" --timeout=120s
done
echo 'Три экземпляра Vault запущены. Выполните scripts/initialize_vault.py с отдельной закрытой папкой.'
