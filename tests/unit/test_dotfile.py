"""Test mobsfscan dotfile."""
from .setup_test import (
    get_paths,
    scanner,
)


SCAN_ONLY = [
    'default_http_client_tls',
    'android_kotlin_hiddenui',
]

# From tests/assets/src/dot_mobsf/.mobsf severity-overrides
SEVERITY_OVERRIDES = {
    'default_http_client_tls': 'ERROR',
    'android_kotlin_hiddenui': 'INFO',
}


def test_mobsfscan_dotfile():
    paths = get_paths()
    files = paths['dot_file']
    res = scanner([files])
    triggered = [*res['results']]
    triggered.sort()
    SCAN_ONLY.sort()
    assert triggered == SCAN_ONLY
    for rule_id, severity in SEVERITY_OVERRIDES.items():
        assert res['results'][rule_id]['metadata']['severity'] == severity
