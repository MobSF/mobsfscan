"""Test Template rules."""
from .setup_test import (
    get_paths,
    scanner,
)


def test_kotlin():
    paths = get_paths()
    res = scanner([paths['kotlin']])
    assert len(res['results'].keys()) != 0


def test_ios():
    paths = get_paths()

    res = scanner([paths['objc'], paths['swift']])
    assert len(res['results'].keys()) != 0
