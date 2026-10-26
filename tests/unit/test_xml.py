"""Test XML checks rules."""
from pathlib import Path

from mobsfscan.manifest import scan_manifest
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
    # #109: XML findings should prefer cwd-relative paths (like source).
    assert not Path(files[0]).is_absolute()


def test_xml_google_key_and_pem_merge_with_source():
    src = (
        Path(__file__).resolve().parents[1]
        / 'assets' / 'src' / 'android_xml_secrets')
    res = MobSFScan([str(src)], True, mp='thread').scan()
    key_files = [
        item['file_path']
        for item in res['results']['google_api_key']['files']]
    assert any(path.endswith('Secrets.java') for path in key_files)
    assert any(path.endswith('strings.xml') for path in key_files)
    pem_files = [
        item['file_path']
        for item in res['results']['private_key_pem']['files']]
    assert any(path.endswith('strings.xml') for path in pem_files)
    assert not any(path.endswith('Secrets.java') for path in pem_files)


def test_unparsable_xml_does_not_reuse_previous_document(tmp_path):
    """Unparsable XML must not be reported with the previous document."""
    manifest = tmp_path / 'AndroidManifest.xml'
    manifest.write_text(
        '<manifest xmlns:android='
        '"http://schemas.android.com/apk/res/android">'
        '<application android:debuggable="true"/>'
        '</manifest>')
    fragment = tmp_path / 'permissions_fragment.xml'
    fragment.write_text(
        '<uses-permission android:name="a"/>'
        '<uses-permission android:name="b"/>')
    res = scan_manifest([manifest, fragment], lambda _: True)
    finding = res['android_manifest_debugging_enabled']
    files = [item['file_path'] for item in finding['files']]
    assert len(files) == 1
    assert files[0].endswith('AndroidManifest.xml')
