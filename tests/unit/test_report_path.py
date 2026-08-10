# -*- coding: utf_8 -*-
"""Tests for cwd-relative finding path normalization (#109)."""
from pathlib import Path

from mobsfscan.utils import report_path


def test_report_path_relativizes_under_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / 'app' / 'src' / 'AndroidManifest.xml'
    nested.parent.mkdir(parents=True)
    nested.write_text('<manifest/>')
    assert report_path(nested) == 'app/src/AndroidManifest.xml'
    assert report_path(Path('app/src/AndroidManifest.xml')) == (
        'app/src/AndroidManifest.xml')


def test_report_path_keeps_outside_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = Path('/tmp/Info.plist')
    assert report_path(outside) == '/tmp/Info.plist'
