# -*- coding: utf_8 -*-
"""Java Semgrep best-practice inversion (missing controls)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.utils import get_best_practices

from .setup_test import get_paths


JAVA_BP_IDS = {
    'android_safetynet_api',
    'android_prevent_screenshot',
    'android_root_detection',
    'android_detect_tapjacking',
    'android_certificate_transparency',
    'android_certificate_pinning',
}


def test_get_best_practices_java_uses_semgrep_dir():
    ids, rules = get_best_practices('.java')
    assert ids == JAVA_BP_IDS
    assert set(rules) == JAVA_BP_IDS
    # Must not pick up kotlin/ subdirectory IDs that differ.
    assert 'android_safetynet' not in ids
    assert 'android_ssl_pinning' not in ids
    assert 'android_tapjacking' not in ids


def test_java_missing_controls_reported_when_absent():
    paths = get_paths()
    res = MobSFScan([str(paths['java'])], True, mp='thread').scan()
    # java_vuln.java already implements certificate transparency.
    present_in_fixture = {'android_certificate_transparency'}
    for rule_id in JAVA_BP_IDS - present_in_fixture:
        assert rule_id in res['results']
        assert not res['results'][rule_id].get('files')
    for rule_id in present_in_fixture:
        assert rule_id not in res['results']


def test_java_present_controls_are_inverted_away():
    src = (
        Path(__file__).resolve().parents[1]
        / 'assets' / 'src' / 'java_best_practices_present')
    res = MobSFScan([str(src)], True, mp='thread').scan()
    for rule_id in JAVA_BP_IDS:
        assert rule_id not in res['results']
