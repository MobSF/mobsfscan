"""Test mobsfscan dotfile."""
from .setup_test import (
    get_paths,
    scanner,
)


SCAN_ONLY = [
    'default_http_client_tls',
    'android_kotlin_hiddenui',
]


def test_mobsfscan_dotfile():
    paths = get_paths()
    files = paths['dot_file']
    res = scanner([files])
    triggered = [*res['results']]
    triggered.sort()
    SCAN_ONLY.sort()
    assert triggered == SCAN_ONLY
