# -*- coding: utf_8 -*-
"""Swift Semgrep best-practice inversion (missing controls)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.utils import get_best_practices


SWIFT_BP_IDS = {
    'ios_jailbreak_detect',
    'ios_custom_keyboard_disabled',
    'ios_keyboard_cache',
    'ios_detect_reversing',
    'ios_cert_pinning',
}


def test_get_best_practices_swift_uses_semgrep_dir():
    ids, rules = get_best_practices('.swift')
    assert ids == SWIFT_BP_IDS
    assert set(rules) == SWIFT_BP_IDS


def test_swift_missing_controls_reported_when_absent():
    # Use a swift file without resilience controls.
    src = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'swift'
    res = MobSFScan([str(src)], True, mp='thread').scan()
    for rule_id in SWIFT_BP_IDS:
        assert rule_id in res['results']
        assert not res['results'][rule_id].get('files')


def test_swift_present_controls_are_inverted_away():
    src = (
        Path(__file__).resolve().parents[1]
        / 'assets' / 'src' / 'swift_best_practices_present')
    res = MobSFScan([str(src)], True, mp='thread').scan()
    for rule_id in SWIFT_BP_IDS:
        assert rule_id not in res['results']


def test_objc_best_practices_still_regex():
    ids, _ = get_best_practices('.m')
    assert 'ios_jailbreak_detect' in ids
    assert 'ios_mach_ports' in ids
