# -*- coding: utf_8 -*-
"""Tests for iOS App Transport Security Info.plist analysis."""
from pathlib import Path
from plistlib import loads

from mobsfscan.ios_plist import check_transport_security
from mobsfscan.mobsfscan import MobSFScan


EXPECTED_ATS_RULES = {
    'ios_ats_arbitrary_loads',
    'ios_ats_arbitrary_loads_for_media',
    'ios_ats_arbitrary_loads_in_web_content',
    'ios_ats_local_networking',
    'ios_ats_insecure_http_loads',
    'ios_ats_weak_tls',
    'ios_ats_tls12',
    'ios_ats_forward_secrecy_disabled',
    'ios_ats_certificate_transparency_disabled',
}


def test_ats_info_plist_scan():
    src = Path(__file__).resolve().parents[1] / 'assets' / 'src' / 'ios_plist'
    res = MobSFScan([str(src)], True, scan_type='ios', mp='thread').scan()
    assert set(res['results']) == EXPECTED_ATS_RULES
    insecure = res['results']['ios_ats_insecure_http_loads']
    assert 'insecure.example' in insecure['metadata']['description']
    assert 'localhost' not in insecure['metadata']['description']
    # Same path normalization as XML (#109): prefer cwd-relative paths.
    files = insecure.get('files') or []
    assert files
    assert files[0]['file_path'].endswith('Info.plist')
    assert not Path(files[0]['file_path']).is_absolute()


def test_ats_safe_plist_has_no_findings():
    plist = loads(b"""<?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict>
      <key>NSAppTransportSecurity</key><dict>
        <key>NSAllowsArbitraryLoads</key><false/>
        <key>NSExceptionDomains</key><dict>
          <key>secure.example</key><dict>
            <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.3</string>
            <key>NSExceptionRequiresForwardSecrecy</key><true/>
            <key>NSRequiresCertificateTransparency</key><true/>
          </dict>
        </dict>
      </dict>
    </dict></plist>""")
    assert check_transport_security('/tmp/Info.plist', plist) == []


def test_non_info_plist_is_not_scanned(tmp_path):
    plist = tmp_path / 'Settings.plist'
    plist.write_bytes(b'<?xml version="1.0"?><plist><dict/></plist>')
    scan = MobSFScan([str(tmp_path)], True, scan_type='ios', mp='thread')
    assert scan.plists == []
