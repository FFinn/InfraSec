#!/bin/sh
set -eu
set +x
umask 077
case "${CI_COMMIT_SHA:-}" in ''|*[!0-9a-f]*) exit 2 ;; esac
case "${CI_PIPELINE_ID:-}" in ''|*[!0-9]*) exit 2 ;; esac
work="$(mktemp -d /tmp/infrasec-gitleaks.XXXXXX)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p ci-artifacts
# Проверяем файлы текущего коммита без служебного .git/config Runner,
# где GitLab может временно записать реквизиты клонирования.
mkdir "$work/source"
git archive --format=tar --output="$work/source.tar" HEAD
tar -xf "$work/source.tar" -C "$work/source"
run_scan() {
  mode="$1"
  set +e
  if [ "$mode" = git ]; then
    gitleaks git --log-opts=--all --config ci/gitleaks.toml \
      --gitleaks-ignore-path /dev/null --ignore-gitleaks-allow \
      --redact=100 --no-banner --no-color --report-format json \
      --report-path "$work/$mode.json" . > "$work/$mode.log" 2>&1
  else
    gitleaks dir --config ci/gitleaks.toml \
      --gitleaks-ignore-path /dev/null --ignore-gitleaks-allow \
      --redact=100 --no-banner --no-color --report-format json \
      --report-path "$work/$mode.json" "$work/source" > "$work/$mode.log" 2>&1
  fi
  result="$?"
  set -e
  if [ "$result" -gt 1 ] || [ ! -f "$work/$mode.json" ]; then
    echo "Gitleaks: ошибка запуска проверки $mode." >&2
    exit 2
  fi
  count="$(grep -c '"RuleID"[[:space:]]*:' "$work/$mode.json" || true)"
  printf '%s\n' "$result" > "$work/$mode.code"
  printf '%s\n' "$count" > "$work/$mode.count"
  echo "Gitleaks $mode: найдено $count; код завершения $result."
}
run_scan git
run_scan dir
git_code="$(cat "$work/git.code")"
dir_code="$(cat "$work/dir.code")"
git_count="$(cat "$work/git.count")"
dir_count="$(cat "$work/dir.count")"
ok=false
if [ "$git_code" -eq 0 ] && [ "$dir_code" -eq 0 ] && [ "$git_count" -eq 0 ] && [ "$dir_count" -eq 0 ]; then ok=true; fi
printf '{"commit":"%s","pipeline_id":"%s","ok":%s,"tool":"gitleaks","version":"8.30.1","history_findings":%s,"directory_findings":%s,"history_exit_code":%s,"directory_exit_code":%s}\n' \
  "$CI_COMMIT_SHA" "$CI_PIPELINE_ID" "$ok" "$git_count" "$dir_count" "$git_code" "$dir_code" > ci-artifacts/gitleaks.json
if [ "$ok" != true ]; then
  echo 'Обнаружены возможные секреты. Полные находки в артефакты не передаются.' >&2
  exit 1
fi
