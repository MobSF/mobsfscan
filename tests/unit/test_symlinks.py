"""Symlinks in the scanned tree must not be followed."""
import json
import os

import pytest

from mobsfscan.mobsfscan import MobSFScan

SECRET = 'outside-tree-secret-value-0451'

MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:debuggable="true" android:allowBackup="true"/>
</manifest>"""

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>"""


def link(target, path):
    try:
        os.symlink(target, path)
    except (OSError, NotImplementedError):
        pytest.skip('Symlinks not supported')


@pytest.fixture
def repo(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / '.env').write_text(f'APP_SECRET_KEY="{SECRET}"\n')
    (outside / 'AndroidManifest.xml').write_text(MANIFEST)
    (outside / 'Info.plist').write_text(INFO_PLIST)
    repo = tmp_path / 'repo'
    (repo / 'src').mkdir(parents=True)
    (repo / 'src' / 'Real.m').write_text('NSString *password = "hunter2";\n')
    link(outside / '.env', repo / 'src' / 'Config.m')
    link(outside / 'AndroidManifest.xml', repo / 'AndroidManifest.xml')
    link(outside / 'Info.plist', repo / 'Info.plist')
    link(outside, repo / 'linked_dir')
    return repo, outside


def test_symlinked_files_not_scanned(repo):
    repo, outside = repo
    res = MobSFScan([str(repo)], True, mp='thread').scan()
    report = json.dumps(res)
    assert SECRET not in report
    assert str(outside.resolve()) not in report
    assert 'Config.m' not in report
    assert not any(rule.startswith('android_manifest_')
                   for rule in res['results'])
    assert not any(rule.startswith('ios_ats_') for rule in res['results'])
    # Regular files are still scanned.
    files = res['results']['ios_hardcoded_secret']['files']
    assert [f['file_path'].rsplit('/', 1)[-1] for f in files] == ['Real.m']
