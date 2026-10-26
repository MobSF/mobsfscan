"""HTML report must escape values that come from the scanned project."""
from mobsfscan.formatters.cli import cli_output, format_table
from mobsfscan.mobsfscan import MobSFScan

PAYLOAD = '<img src=x onerror=alert(1)>'

INFO_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSExceptionDomains</key>
    <dict>
      <key>{PAYLOAD.replace('<', '&lt;').replace('>', '&gt;')}</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
      </dict>
    </dict>
  </dict>
</dict></plist>"""


def finding(description):
    return {
        'metadata': {
            'id': 'rule',
            'description': description,
            'severity': 'ERROR',
            'cwe': ['cwe-79', '<b>'],
        },
        'files': [{
            'file_path': 'src/<i>.java',
            'match_position': (1, 2),
            'match_lines': (3, 3),
            'match_string': '<script>x</script>',
        }],
    }


def test_info_plist_domain_escaped_in_html_report(tmp_path):
    src = tmp_path / 'app'
    src.mkdir()
    (src / 'Info.plist').write_text(INFO_PLIST)
    res = MobSFScan([str(src)], False, scan_type='ios', mp='thread').scan()
    desc = res['results']['ios_ats_insecure_http_loads']['metadata'][
        'description']
    assert PAYLOAD in desc
    report = tmp_path / 'report.html'
    cli_output(str(report), res, '0', 'unsafehtml')
    html = report.read_text()
    assert PAYLOAD not in html
    assert '&lt;img src=x onerror=alert(1)&gt;' in html


def test_every_cell_escaped_in_html():
    html = format_table('<rule>', finding(f'host?{PAYLOAD}'), 'unsafehtml')
    assert PAYLOAD not in html
    for raw in ('<rule>', '<b>', '<i>', '<script>'):
        assert raw not in html
    # The nested files table and the <pre> wrapper are still markup.
    assert html.count('<table>') == 2
    assert '<pre>&lt;script&gt;x&lt;/script&gt;</pre>' in html


def test_text_formats_unchanged():
    out = format_table('rule', finding(PAYLOAD), 'fancy_grid')
    assert PAYLOAD in out
    assert '<script>x</script>' in out
