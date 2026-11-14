# -*- coding: utf_8 -*-
"""Tests for JavaScript, TypeScript, and Hybrid source analysis."""
from pathlib import Path

from mobsfscan import __version__
from mobsfscan import hybrid
from mobsfscan.formatters import (
    cli,
    gitlab_sast,
    json_fmt,
    sarif,
    sonarqube,
)
from mobsfscan.mobsfscan import MobSFScan

from .setup_test import get_paths


def test_react_native_ts_tsx_rules_and_no_false_missing_bp(
        tmp_path, monkeypatch):
    """Pure JS/TS repo triggers JS rules without missing native BP controls."""
    src_root = get_paths()['javascript'] / 'rn_app'
    monkeypatch.chdir(src_root)

    res = MobSFScan(['.'], True, mp='thread').scan()
    findings = res['results']

    expected_rules = {
        'js_webview_javascript_enabled',
        'js_webview_file_access',
        'js_webview_mixed_content',
        'js_webview_origin_wildcard',
        'js_dom_xss_sink',
        'js_postmessage_wildcard_origin',
        'js_insecure_async_storage',
        'js_mmkv_without_encryption',
        'js_hardcoded_secret',
        'js_deeplink_open_url',
        'js_console_sensitive_log',
        'js_client_side_auth_gate',
        'js_webview_unverified_onmessage',
        'js_cleartext_http_traffic',
    }
    assert expected_rules.issubset(findings.keys())
    assert 'js_dynamic_code_execution' not in findings

    # Severities must be mobsfscan-normalized (ERROR / WARNING / INFO)
    assert findings['js_hardcoded_secret']['metadata']['severity'] == 'ERROR'
    assert findings['js_dom_xss_sink']['metadata']['severity'] == 'WARNING'
    assert findings['js_console_sensitive_log']['metadata']['severity'] == (
        'INFO')

    # __DEV__ console.log on line 13 excluded; only line 14 reported
    log_files = findings['js_console_sensitive_log']['files']
    assert len(log_files) == 1
    assert log_files[0]['file_path'] == 'src/App.tsx'
    assert log_files[0]['match_lines'][0] == 14

    # Pure JS/TS scan must not report missing Android/iOS best practices
    assert not any(
        rid.startswith(('android_', 'ios_')) for rid in findings
    )

    # Verify all formatters accept JS findings cleanly
    assert json_fmt.json_output(None, dict(res), __version__)
    assert sarif.sarif_output(None, dict(res), __version__, ['.'])
    assert sonarqube.sonarqube_output(None, dict(res), __version__)
    assert gitlab_sast.gitlab_sast_output(None, dict(res), __version__)
    html_out = tmp_path / 'report.html'
    cli.cli_output(str(html_out), dict(res), __version__, 'unsafehtml')
    assert html_out.is_file()


def test_crypto_sqlite_tls_keychain_oauth_and_safe_negatives():
    """Test remaining JS/Expo/RN rules and verify safe code does not match."""
    src_root = get_paths()['javascript'] / 'api_rules'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()
    findings = res['results']

    expected = {
        'js_tls_validation_disabled',
        'js_sqlite_injection',
        'js_webview_script_injection',
        'js_weak_crypto',
        'js_crypto_hardcoded_key',
        'js_webview_dynamic_uri',
        'js_keychain_weak_accessibility',
        'js_clipboard_sensitive_data',
        'js_webview_debugging_enabled',
        'js_webview_inject_all_frames',
        'js_webview_allow_all_navigation',
        'js_oauth_insecure_config',
        'js_biometric_without_crypto',
        'js_external_storage_path',
        'js_unencrypted_database',
        'js_persist_sensitive_state',
        'js_debug_tooling_in_release',
        'js_biometric_weak_fallback',
        'js_dynamic_code_execution',
    }
    assert expected.issubset(findings.keys())
    for rule_id in expected:
        matched_paths = [
            f['file_path'] for f in findings[rule_id].get('files', [])
        ]
        assert not any(p.endswith('safe.tsx') for p in matched_paths), rule_id


def test_embedded_html_and_vue_script_blocks():
    """Embedded <script> blocks in HTML and Vue SFCs preserve line numbers."""
    src_root = get_paths()['javascript'] / 'embedded_web'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()
    findings = res['results']
    xss_files = findings['js_dom_xss_sink']['files']
    assert xss_files[0]['file_path'].endswith('index.html')
    assert xss_files[0]['match_lines'] == (5, 5)

    eval_files = findings['js_dynamic_code_execution']['files']
    assert eval_files[0]['file_path'].endswith('View.vue')
    assert eval_files[0]['match_lines'] == (3, 3)


def test_hybrid_configs_cordova_capacitor_expo(monkeypatch):
    """Cordova, Capacitor, and Expo configs report insecure settings."""
    src_root = get_paths()['javascript'] / 'hybrid_configs'
    monkeypatch.chdir(src_root)
    res = MobSFScan(['.'], True, mp='thread').scan()
    findings = res['results']
    expected = {
        'cordova_config_wildcard_access',
        'cordova_config_wildcard_navigation',
        'capacitor_cleartext_traffic',
        'capacitor_wildcard_navigation',
        'expo_config_extra_secrets',
        'expo_updates_cleartext',
        'expo_updates_unsigned',
    }
    assert expected == set(findings.keys())
    extra_finding = findings['expo_config_extra_secrets']
    desc = extra_finding['metadata']['description']
    match_str = extra_finding['files'][0]['match_string']
    assert 'stripeSecretKey' in match_str
    assert 'projectId' not in match_str
    # Secret value itself must not leak into description or match_string
    assert 'sk_test_51Habcdefghijkl' not in desc
    assert 'sk_test_51Habcdefghijkl' not in match_str
    assert findings['cordova_config_wildcard_access']['files'][0][
        'match_lines'] == (3, 3)


def test_hybrid_mixed_repo_and_scan_type_filtering():
    """Mixed RN + Android repo runs both in auto and filters on --type."""
    src_root = get_paths()['javascript'] / 'mixed_repo'

    auto_res = MobSFScan(
        [str(src_root)], True, scan_type='auto', mp='thread',
    ).scan()['results']
    assert 'js_dynamic_code_execution' in auto_res
    assert 'capacitor_cleartext_traffic' in auto_res
    assert 'android_rn_exposed_react_method' in auto_res

    js_only = MobSFScan(
        [str(src_root)], True, scan_type='javascript', mp='thread',
    ).scan()['results']
    assert 'js_dynamic_code_execution' in js_only
    assert 'capacitor_cleartext_traffic' in js_only
    assert 'android_rn_exposed_react_method' not in js_only
    assert not any(rid.startswith('android_') for rid in js_only)

    android_only = MobSFScan(
        [str(src_root)], True, scan_type='android', mp='thread',
    ).scan()['results']
    assert 'android_rn_exposed_react_method' in android_only
    assert 'js_dynamic_code_execution' not in android_only
    assert 'capacitor_cleartext_traffic' not in android_only


def test_mobsf_ignore_comments_in_jsx_js_and_xml():
    """Inline //, {/* */}, and <!-- --> mobsf-ignore comments suppress hits."""
    src_root = get_paths()['javascript'] / 'ignore_comments'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()['results']
    assert 'js_dynamic_code_execution' not in res
    assert 'cordova_config_wildcard_access' not in res
    xss_files = res['js_dom_xss_sink']['files']
    assert len(xss_files) == 1
    assert xss_files[0]['match_lines'] == (6, 6)


def test_cordova_no_path_wildcards_repeated_elements_and_json_lines():
    """Track exact XML/JSON positions and detect http://*, https://* nav."""
    src_root = get_paths()['javascript'] / 'hybrid_locations'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()['results']

    access_hits = res['cordova_config_wildcard_access']['files']
    assert len(access_hits) == 1
    assert access_hits[0]['match_lines'] == (4, 4)

    nav_hits = res['cordova_config_wildcard_navigation']['files']
    assert sorted(h['match_lines'][0] for h in nav_hits) == [7, 8]
    assert {h['match_string'] for h in nav_hits} == {
        '<allow-navigation href="https://*" />',
        '<allow-navigation href="https://*/login" />',
    }

    assert res['capacitor_cleartext_traffic']['files'][0][
        'match_lines'] == (11, 11)
    assert res['capacitor_wildcard_navigation']['files'][0][
        'match_lines'] == (12, 12)

    extra_by_file = {
        Path(f['file_path']).as_posix(): f
        for f in res['expo_config_extra_secrets']['files']
    }
    wrapped_file = next(
        k for k in extra_by_file if k.endswith('hybrid_locations/app.json')
    )
    root_file = next(
        k for k in extra_by_file if k.endswith('sub/app.json')
    )
    assert extra_by_file[wrapped_file]['match_lines'] == (7, 7)
    assert extra_by_file[wrapped_file]['match_string'] == 'extra: apiSecret'
    assert extra_by_file[root_file]['match_lines'] == (4, 4)
    assert extra_by_file[root_file]['match_string'] == 'extra: firebaseApiKey'

    cleartext_lines = sorted(
        f['match_lines'][0]
        for f in res['expo_updates_cleartext']['files']
    )
    assert cleartext_lines == [8, 11]
    unsigned_lines = sorted(
        f['match_lines'][0]
        for f in res['expo_updates_unsigned']['files']
    )
    assert unsigned_lines == [7, 10]

    # A vanished/unreadable config must not discard findings from valid files
    missing_cfg = src_root / 'vanished' / 'config.xml'
    partial = hybrid.scan_hybrid_configs(
        [missing_cfg, src_root / 'capacitor.config.json'],
        lambda _: True,
    )
    assert 'capacitor_cleartext_traffic' in partial


def test_webview_shorthand_dom_xss_multiset_http_and_dev_else():
    """Regression coverage for JSX shorthand, sanitizer RHS, multiSet, HTTP."""
    src_root = get_paths()['javascript'] / 'edge_cases'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()['results']

    for rule_id, expected_lines in (
        ('js_webview_file_access', [1, 2]),
        ('js_dom_xss_sink', [3, 4]),
        ('js_insecure_async_storage', [5]),
        ('js_cleartext_http_traffic', [6, 7]),
        ('js_console_sensitive_log', [11]),
        ('js_postmessage_wildcard_origin', [13]),
        ('js_webview_origin_wildcard', [14]),
        ('js_deeplink_open_url', [15]),
        ('js_debug_tooling_in_release', [19]),
    ):
        files = res[rule_id]['files']
        assert all(f['file_path'].endswith('vuln.tsx') for f in files), rule_id
        assert sorted(f['match_lines'][0] for f in files) == expected_lines


def test_webview_onmessage_handler_scope_and_origin_guards():
    """Flag unverified WebView handlers; skip origin-guarded or unrelated."""
    src_root = get_paths()['javascript'] / 'onmessage_handlers'
    res = MobSFScan([str(src_root)], True, mp='thread').scan()['results']
    hits = res['js_webview_unverified_onmessage']['files']
    assert sorted(h['match_lines'][0] for h in hits) == [
        4, 8, 13, 17, 22, 26, 27, 28, 29,
    ]
