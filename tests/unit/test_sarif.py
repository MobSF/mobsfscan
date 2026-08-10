# -*- coding: utf_8 -*-
"""Tests for SARIF rule naming and dashboard metadata."""
import json

from mobsfscan.formatters.sarif import (
    build_tags,
    format_rule_name,
    sarif_output,
    security_severity_score,
)


def test_format_rule_name_uses_description_and_cwe():
    name = format_rule_name('ios_cert_pinning', {
        'description': (
            'This app does not have Certificate Pinning '
            'implemented in code.'),
        'cwe': 'CWE-295: Improper Certificate Validation',
    })
    assert name == (
        'This app does not have Certificate Pinning '
        'implemented in code (CWE-295)')


def test_format_rule_name_falls_back_to_id():
    assert format_rule_name('ios_cert_pinning', {}) == 'IosCertPinning'


def test_security_severity_prefers_cvss_then_severity():
    assert security_severity_score({'cvss': 7.4}) == '7.4'
    assert security_severity_score({'severity': 'ERROR'}) == '9.0'
    assert security_severity_score({'severity': 'WARNING'}) == '5.5'
    assert security_severity_score({'severity': 'INFO'}) == '2.0'


def test_build_tags_from_metadata():
    tags = build_tags({
        'cwe': 'CWE-295: Improper Certificate Validation',
        'owasp-mobile': 'M3: Insecure Communication',
        'masvs': 'MSTG-NETWORK-1',
    })
    assert tags[0] == 'security'
    assert 'external/cwe/cwe-295' in tags
    assert 'owasp-mobile/m3' in tags
    assert 'masvs/network-1' in tags
    assert len(tags) <= 10


def test_sarif_includes_dashboard_fields(tmp_path):
    scan_results = {
        'results': {
            'ios_cert_pinning': {
                'metadata': {
                    'description': (
                        'This app does not have Certificate Pinning '
                        'implemented in code.'),
                    'severity': 'INFO',
                    'cwe': 'CWE-295: Improper Certificate Validation',
                    'owasp-mobile': 'M3: Insecure Communication',
                    'masvs': 'MASVS-NETWORK-1',
                    'reference': 'https://example.com',
                },
            },
        },
    }
    outfile = tmp_path / 'out.sarif'
    sarif_output(str(outfile), scan_results, '0.4.6', ['app'])
    out = json.loads(outfile.read_text())
    rule = out['runs'][0]['tool']['driver']['rules'][0]
    result = out['runs'][0]['results'][0]

    assert rule['id'] == 'ios_cert_pinning'
    assert rule['name'] == (
        'This app does not have Certificate Pinning '
        'implemented in code (CWE-295)')
    assert rule['shortDescription']['text'] == rule['name']
    assert 'Certificate Pinning' in rule['fullDescription']['text']
    assert 'Reference: https://example.com' in rule['help']['text']
    assert rule['defaultConfiguration']['level'] == 'note'
    assert rule['properties']['security-severity'] == '2.0'
    assert rule['properties']['precision'] == 'medium'
    assert 'security' in rule['properties']['tags']
    assert 'external/cwe/cwe-295' in rule['properties']['tags']
    assert result['properties']['security-severity'] == '2.0'
    assert 'IosCertPinning' not in rule['name']
