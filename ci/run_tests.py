#!/usr/bin/env python3
"""Запуск тестов с проверкой количества и безопасной сводкой."""
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET
from common import save_report

directory = Path('ci-artifacts')
directory.mkdir(exist_ok=True)
report = directory / 'pytest.xml'
completed = subprocess.run([sys.executable, '-m', 'pytest', '-q', 'tests', '--junitxml=' + str(report)])
count = failures = errors = skipped = 0
if report.exists():
    root = ET.parse(report).getroot()
    suites = [root] if root.tag == 'testsuite' else list(root.findall('testsuite'))
    count = sum(int(item.get('tests', '0')) for item in suites)
    failures = sum(int(item.get('failures', '0')) for item in suites)
    errors = sum(int(item.get('errors', '0')) for item in suites)
    skipped = sum(int(item.get('skipped', '0')) for item in suites)
ok = completed.returncode == 0 and count >= 16 and failures == errors == skipped == 0
save_report('tests', {'ok': ok, 'tests': count, 'failures': failures, 'errors': errors, 'skipped': skipped})
raise SystemExit(0 if ok else (completed.returncode or 1))
