# -*- coding: utf_8 -*-
"""Kotlin Semgrep best-practice inversion (missing controls)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.utils import get_best_practices

from .setup_test import get_paths


KOTLIN_BP_IDS = {
    'android_safetynet',
    'android_prevent_screenshot',
    'android_root_detection',
    'android_tapjacking',
    'android_certificate_transparency',
    'android_ssl_pinning',
}


def test_get_best_practices_kotlin_uses_semgrep_dir():
    ids, rules = get_best_practices('.kt')
    assert ids == KOTLIN_BP_IDS
    assert set(rules) == KOTLIN_BP_IDS
    # Java loader must not pick up kotlin/ subdirectory IDs that differ.
    java_ids, _ = get_best_practices('.java')
    assert 'android_safetynet' not in java_ids
    assert 'android_safetynet_api' in java_ids
    assert 'android_ssl_pinning' not in java_ids
    assert 'android_certificate_pinning' in java_ids


def test_kotlin_missing_controls_reported_when_absent():
    paths = get_paths()
    res = MobSFScan([str(paths['kotlin'])], True, mp='thread').scan()
    for rule_id in KOTLIN_BP_IDS:
        assert rule_id in res['results']
        # Missing controls have metadata only (no file matches).
        assert not res['results'][rule_id].get('files')


def test_kotlin_present_controls_are_inverted_away():
    src = (
        Path(__file__).resolve().parents[1]
        / 'assets' / 'src' / 'kotlin_best_practices_present')
    res = MobSFScan([str(src)], True, mp='thread').scan()
    for rule_id in KOTLIN_BP_IDS:
        assert rule_id not in res['results']
    # Java-only BP IDs must not be reported missing on a Kotlin-only tree.
    for rule_id in (
            'android_safetynet_api',
            'android_certificate_pinning',
            'android_detect_tapjacking'):
        assert rule_id not in res['results']
