"""Test XML checks rules."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan

from .setup_test import (
    get_paths,
    scanner,
)


def test_xml():
    paths = get_paths()
    res = scanner([paths['xml']])
    assert len(res['results'].keys()) == 5


def test_multiple_sibling_domain_configs():
    """Issue #87: multiple domain-config blocks must not crash."""
    xml_dir = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'xml'
    res = MobSFScan([str(xml_dir)], True, mp='thread').scan()
    finding = res['results']['android_manifest_domain_config_cleartext']
    paths = [f.get('file_path') or '' for f in finding.get('files') or []]
    assert any('nsc_multiple_domain_config_siblings.xml' in p for p in paths)


def test_sensitive_layout_input_keyboard_cache():
    paths = get_paths()
    res = scanner([paths['android_layout']])
    finding = res['results']['android_layout_sensitive_input_keyboard_cache']
    files = [item['file_path'] for item in finding['files']]
    assert len(files) == 1
    assert files[0].endswith('unsafe_login.xml')
