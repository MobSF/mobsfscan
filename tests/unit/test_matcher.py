"""Test Template rules."""
from .setup_test import (
    get_paths,
    scanner,
)


def test_kotlin():
    paths = get_paths()
    res = scanner([paths['kotlin']])
    assert len(res['results'].keys()) != 0


def test_new_android_kotlin_rules():
    paths = get_paths()
    res = scanner([paths['android_new_rules']])
    expected = {
        'android_kotlin_insecure_tls_version',
        'android_kotlin_weak_tls_cipher_suite',
        'android_kotlin_sensitive_input_keyboard_cache',
        'android_kotlin_custom_xor_crypto',
        'android_kotlin_sensitive_notification',
    }
    assert expected.issubset(res['results'])


def test_ios():
    paths = get_paths()

    res = scanner([paths['objc'], paths['swift']])
    assert len(res['results'].keys()) != 0
