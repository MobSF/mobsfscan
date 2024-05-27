"""Test mobsfscan."""
from .setup_test import (
    get_paths,
    scanner,
)

from mobsfscan.formatters import (
    json_fmt,
    sarif,
    sonarqube,
)


EXPECTED = [
    'android_safetynet_api',
    'android_prevent_screenshot',
    'android_certificate_pinning',
    'android_root_detection',
    'android_detect_tapjacking',
    'android_kotlin_logging',
    'android_kotlin_hiddenui',
    'android_logging',
]


def test_patterns_and_semgrep():
    paths = get_paths()
    res = scanner([paths['java'], paths['kotlin']])
    actual = [*res['results']]
    actual.sort()
    EXPECTED.sort()
    assert actual == EXPECTED
    json_output(res)
    sonar_output(res)
    sarif_output(res)


def json_output(res):
    json_out = json_fmt.json_output(None, res, '0.0.0')
    assert json_out is not None


def sonar_output(res):
    sonar_out = sonarqube.sonarqube_output(None, res, '0.0.0')
    assert sonar_out is not None


def sarif_output(res):
    sarif_out = sarif.sarif_output(None, res, '0.0.0', '/tmp/')
    assert sarif_out is not None
