#!/bin/sh
set -eu
set +x
umask 077
case "${CI_COMMIT_SHA:-}" in ''|*[!0-9a-f]*) exit 2 ;; esac
case "${CI_PIPELINE_ID:-}" in ''|*[!0-9]*) exit 2 ;; esac
case "${CI_REGISTRY:-}" in ''|*[!a-zA-Z0-9.:-]*) exit 2 ;; esac
case "${CI_REGISTRY_IMAGE:-}" in ''|*[!a-zA-Z0-9_./:-]*) exit 2 ;; esac
test -n "${CI_REGISTRY_USER:-}"
test -n "${CI_REGISTRY_PASSWORD:-}"
work="$(mktemp -d /tmp/infrasec-build.XXXXXX)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
export DOCKER_CONFIG="$work/docker"
mkdir -m 700 "$DOCKER_CONFIG"
auth="$(printf '%s:%s' "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" | base64 | tr -d '\n')"
printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$CI_REGISTRY" "$auth" > "$DOCKER_CONFIG/config.json"
chmod 600 "$DOCKER_CONFIG/config.json"
unset auth CI_REGISTRY_PASSWORD
image="$CI_REGISTRY_IMAGE/app:$CI_COMMIT_SHA"
buildctl-daemonless.sh build \
  --frontend dockerfile.v0 \
  --local context="$CI_PROJECT_DIR/app" \
  --local dockerfile="$CI_PROJECT_DIR/app" \
  --opt platform=linux/amd64 \
  --metadata-file "$work/metadata.json" \
  --output "type=image,name=$image,push=true"
digest="$(awk -F '"' '
  /^[[:space:]]*"containerimage[.]digest"[[:space:]]*:/ {
    count++; digest=$4
  }
  END { if (count != 1) exit 2; print digest }
' "$work/metadata.json")"
case "$digest" in sha256:*) ;; *) echo 'BuildKit не вернул SHA256 digest.' >&2; exit 2 ;; esac
hash="${digest#sha256:}"
test "${#hash}" -eq 64
case "$hash" in *[!0-9a-f]*|'') echo 'Некорректный digest BuildKit.' >&2; exit 2 ;; esac
deployment_image="$CI_REGISTRY_IMAGE/app@$digest"
mkdir -p ci-artifacts
printf '{"commit":"%s","pipeline_id":"%s","ok":true,"image":"%s","digest":"%s","deployment_image":"%s","rootless":true}\n' \
  "$CI_COMMIT_SHA" "$CI_PIPELINE_ID" "$image" "$digest" "$deployment_image" > ci-artifacts/build.json
