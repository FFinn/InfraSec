#!/usr/bin/env bash
# Запускать на ВМ с kubectl после успешного rollout обоих приложений.
# Временный namespace создаётся только для этой проверки и удаляется при выходе.
set -euo pipefail

test_namespace="infrasec-check-$(date +%s)-$$"
test_image="$(kubectl -n infrasec get deployment backend -o jsonpath='{.spec.template.spec.containers[0].image}')"
backend_ip="$(kubectl -n infrasec get service backend -o jsonpath='{.spec.clusterIP}')"
[[ "$test_image" =~ ^[A-Za-z0-9][A-Za-z0-9._:/@+-]+$ ]] || exit 1
[[ "$backend_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1

frontend_check() {
  kubectl -n infrasec exec deployment/frontend -c app -- python -c '
import sys
from urllib import error,request
try:
    request.urlopen("http://backend:8000/data",timeout=5)
except error.HTTPError as exc:
    if exc.code == 401:
        print("frontend_to_backend_reachable=true; http_status=401")
        sys.exit(0)
except Exception:
    print("frontend_to_backend_reachable=false")
    sys.exit(1)
print("frontend_to_backend_reachable=false")
sys.exit(1)
'
}

# HTTP 401 подтверждает сетевую доступность, при этом ключ не раскрывается.
frontend_check
kubectl create namespace "$test_namespace" >/dev/null
cleanup() {
  kubectl delete namespace "$test_namespace" --wait=false --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: network-probe
  namespace: ${test_namespace}
  labels:
    app: untrusted-probe
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: ${test_image}
      imagePullPolicy: IfNotPresent
      command: [python, -c, "import time; time.sleep(300)"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests:
          cpu: 10m
          memory: 32Mi
        limits:
          cpu: 100m
          memory: 64Mi
YAML
kubectl -n "$test_namespace" wait --for=condition=Ready pod/network-probe --timeout=90s >/dev/null
kubectl -n "$test_namespace" exec network-probe -c probe -- python -c '
import socket,sys
from urllib import error,request
try:
    request.urlopen("http://"+sys.argv[1]+":8000/data",timeout=5)
except error.HTTPError:
    print("outside_namespace_denied=false")
    sys.exit(1)
except error.URLError as exc:
    if isinstance(exc.reason,(TimeoutError,socket.timeout)):
        print("outside_namespace_denied=true; connection_timed_out=true")
        sys.exit(0)
except (TimeoutError,socket.timeout):
    print("outside_namespace_denied=true; connection_timed_out=true")
    sys.exit(0)
print("outside_namespace_denied=false")
sys.exit(1)
' "$backend_ip"
# Контроль после отрицательной пробы исключает отказ самого backend.
frontend_check
printf '%s\n' 'network_policy_check_passed=true'
