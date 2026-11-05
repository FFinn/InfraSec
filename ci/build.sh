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
  --output "type=image,name=$image,push=true"
mkdir -p ci-artifacts
printf '{"commit":"%s","pipeline_id":"%s","ok":true,"image":"%s","rootless":true}\n' \
  "$CI_COMMIT_SHA" "$CI_PIPELINE_ID" "$image" > ci-artifacts/build.json
