"""Проверки отчёта BuildKit и использования того же digest при развёртывании."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci'))
from common import SafeError
from images import deployments_match_image, validated_deployment_image

REGISTRY_IMAGE = 'registry.example/project/infrasec'
COMMIT = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64


def build_report():
    return {'ok': True, 'image': REGISTRY_IMAGE + '/app:' + COMMIT,
            'digest': DIGEST, 'deployment_image': REGISTRY_IMAGE + '/app@' + DIGEST}


def test_valid_build_is_deployed_by_digest():
    image = validated_deployment_image(build_report(), REGISTRY_IMAGE, COMMIT)
    assert image == REGISTRY_IMAGE + '/app@' + DIGEST
    deployed = [{'name': name, 'namespace': 'infrasec', 'ready': True, 'image': image}
                for name in ('frontend', 'backend')]
    assert deployments_match_image(deployed, image)


@pytest.mark.parametrize('field,value', [
    ('digest', 'sha256:' + 'c' * 64),
    ('digest', 'sha256:short'),
    ('deployment_image', REGISTRY_IMAGE + '/app@sha256:' + 'c' * 64),
    ('image', REGISTRY_IMAGE + '/app:' + 'c' * 40),
])
def test_inconsistent_build_metadata_is_rejected(field, value):
    report = build_report()
    report[field] = value
    with pytest.raises(SafeError):
        validated_deployment_image(report, REGISTRY_IMAGE, COMMIT)


def test_ready_deployment_with_other_digest_is_rejected():
    image = validated_deployment_image(build_report(), REGISTRY_IMAGE, COMMIT)
    deployed = [{'name': name, 'namespace': 'infrasec', 'ready': True, 'image': image}
                for name in ('frontend', 'backend')]
    deployed[1]['image'] = REGISTRY_IMAGE + '/app@sha256:' + 'c' * 64
    assert not deployments_match_image(deployed, image)


@pytest.mark.parametrize('metadata,expected_code', [
    ({'containerimage.digest': DIGEST}, 0),
    ({'containerimage.config.digest': DIGEST}, 2),
    ({'containerimage.digest': 'sha256:short'}, 1),
])
def test_build_script_reads_fresh_buildkit_metadata(tmp_path, metadata, expected_code):
    # Проверяется настоящий shell-скрипт; вместо сборки образа используется
    # процесс, реализующий только интерфейс --metadata-file BuildKit.
    binary = tmp_path / 'bin'
    binary.mkdir()
    stub = binary / 'buildctl-daemonless.sh'
    stub.write_text('#!/bin/sh\nset -eu\nwhile [ "$#" -gt 0 ]; do\n'
                    '  if [ "$1" = --metadata-file ]; then printf "%s" "$UNIT_METADATA" > "$2"; exit 0; fi\n'
                    '  shift\ndone\nexit 2\n')
    stub.chmod(0o700)
    environment = {**os.environ, 'PATH': str(binary) + os.pathsep + os.environ['PATH'],
                   'CI_COMMIT_SHA': COMMIT, 'CI_PIPELINE_ID': '123',
                   'CI_REGISTRY': 'registry.example', 'CI_REGISTRY_IMAGE': REGISTRY_IMAGE,
                   'CI_REGISTRY_USER': 'unit-test-user', 'CI_REGISTRY_PASSWORD': 'unit-test-password',
                   'CI_PROJECT_DIR': str(tmp_path), 'UNIT_METADATA': json.dumps(metadata, indent=2)}
    result = subprocess.run(['sh', str(ROOT / 'ci/build.sh')], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=15)
    assert result.returncode == expected_code
    output = tmp_path / 'ci-artifacts/build.json'
    if expected_code == 0:
        report = json.loads(output.read_text())
        assert validated_deployment_image(report, REGISTRY_IMAGE, COMMIT) == REGISTRY_IMAGE + '/app@' + DIGEST
    else:
        assert not output.exists()
