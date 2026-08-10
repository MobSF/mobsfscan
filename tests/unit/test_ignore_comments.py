# -*- coding: utf_8 -*-
"""Tests for mobsf-ignore comment suppressions (#104, #107)."""
from pathlib import Path

from mobsfscan.mobsfscan import MobSFScan

from .setup_test import get_paths


def test_line_ignores_rule_parsing():
    assert MobSFScan._line_ignores_rule(
        'x // mobsf-ignore: ios_log', 'ios_log')
    assert MobSFScan._line_ignores_rule(
        'x // mobsf-ignore: ios_log, ios_hardcoded_secret',
        'ios_hardcoded_secret')
    assert not MobSFScan._line_ignores_rule(
        'x // mobsf-ignore: ios_log', 'ios_logging')
    assert not MobSFScan._line_ignores_rule(
        'x // mobsf-ignore: ios_logger', 'ios_log')
    assert not MobSFScan._line_ignores_rule('NSLog("x")', 'ios_log')


def test_multiple_files_same_rule_suppressed():
    """Issue #104: suppressions across files must all apply."""
    paths = get_paths()
    res = MobSFScan([str(paths['dot_file'])], True, mp='thread').scan()
    assert 'android_kotlin_hardcoded' not in res['results']


def test_ios_log_line_level_and_bol_ignore():
    """Issue #107: BOL ignore works; other lines in the file still report."""
    src = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'swift_ignore'
    scan = MobSFScan([str(src)], True, mp='thread')
    res = scan.scan()
    files = res['results']['ios_log']['files']
    # Two suppressed NSLog lines removed; unsuppressed NSLog + os_log remain
    assert len(files) == 2
    lines = sorted(f['match_lines'][0] for f in files)
    assert lines == [5, 6]
    src_text = (src / 'IgnoreLog.swift').read_text(encoding='utf-8')
    assert 'NSLog("still reported")' in src_text
    assert 'os_log("also reported")' in src_text
    for match in files:
        assert not scan.suppress_pm_comments(match, 'ios_log')
