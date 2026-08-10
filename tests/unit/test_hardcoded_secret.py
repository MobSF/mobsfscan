# -*- coding: utf_8 -*-
"""Tests for hardcoded secret rules (#88, #111)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan


def test_ios_hardcoded_secret_skips_lookup_key_names():
    src = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'swift'
    res = MobSFScan([str(src)], True, mp='thread').scan()
    finding = res['results'].get('ios_hardcoded_secret')
    assert finding is not None
    files = finding.get('files') or []
    lines = {f.get('match_lines', (None, None))[0] for f in files}
    src_text = (src / 'swift.swift').read_text(encoding='utf-8').splitlines()

    # Lookup-style *Key names must not be flagged (#111).
    for lineno in (6, 7, 8):
        assert lineno not in lines
        assert 'Key' in src_text[lineno - 1]

    # Real secrets should be flagged (lines from fixture).
    assert {11, 12, 13, 14}.issubset(lines)
    # Prefer raw source when Semgrep CE redacts match lines.
    assert 'password' in src_text[10].lower()
    assert 'api_key' in src_text[12].lower()
    assert 'secretkey' in src_text[13].lower().replace('_', '')


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
    assert any(
        (m.get('file_path') or '').endswith('LongKey.kt')
        for m in matches)
    # Prefer raw source when Semgrep CE redacts match lines.
    src_text = (src / 'LongKey.kt').read_text(encoding='utf-8')
    assert 'KEY' in src_text
    assert len(src_text) > 100
