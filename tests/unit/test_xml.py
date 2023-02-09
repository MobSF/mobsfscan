"""Test XML checks rules."""
from .setup_test import (
    get_paths,
    scanner,
)


def test_xml():
    paths = get_paths()
    res = scanner([paths['xml']])
    assert len(res['results'].keys()) == 5
