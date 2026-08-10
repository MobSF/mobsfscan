# -*- coding: utf_8 -*-
"""Tests for ios_hardcoded_secret false-positive tuning (#111)."""
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
