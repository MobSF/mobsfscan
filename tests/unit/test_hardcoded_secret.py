# -*- coding: utf_8 -*-
"""Tests for hardcoded secret rules (#88, #111)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan


def test_ios_hardcoded_secret_skips_lookup_key_names():
    src = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'swift'
    res = MobSFScan([str(src)], True, mp='thread').scan()
    finding = res['results'].get('ios_hardcoded_secret')
    assert finding is not None
    matches = [f.get('match_string') for f in finding.get('files') or []]
    joined = ' '.join(matches).lower()

    assert 'app_version_key' not in joined
    assert 'languagekey' not in joined
    assert 'leadsloggedkey' not in joined

    assert any('password' in (m or '').lower() for m in matches)
    assert any(
        m and (
            m.lower().startswith('key')
            or 'api_key' in m.lower()
            or 'secretkey' in m.lower().replace('_', ''))
        for m in matches)


def test_kotlin_long_hardcoded_key_detected():
    """Issue #88: values longer than 100 chars were false negatives."""
    src = (
        Path(__file__).resolve().parents[1]
        / 'assets' / 'src' / 'kotlin_long_secret')
    res = MobSFScan([str(src)], True, mp='thread').scan()
    finding = res['results'].get('android_kotlin_hardcoded')
    assert finding is not None
    matches = finding.get('files') or []
    assert matches
    assert any('key =' in (m.get('match_string') or '').lower() for m in matches)
    assert any(len(m.get('match_string') or '') > 100 for m in matches)
