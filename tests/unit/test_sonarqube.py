# -*- coding: utf_8 -*-
"""Tests for SonarQube generic issue formatter (10.3+)."""
import json

from mobsfscan.formatters.sonarqube import (
    IMPACT_SEVERITY_MAP,
    SEVERITY_MAP,
    sonarqube_output,
)


def test_severity_maps():
    assert SEVERITY_MAP['ERROR'] == 'CRITICAL'
    assert SEVERITY_MAP['WARNING'] == 'MAJOR'
    assert IMPACT_SEVERITY_MAP['ERROR'] == 'HIGH'
    assert IMPACT_SEVERITY_MAP['INFO'] == 'LOW'


def test_sonarqube_new_format_shape():
    scan_results = {
        'results': {
            'ios_cert_pinning': {
                'metadata': {
                    'description': (
                        'This app does not have Certificate Pinning '
                        'implemented in code.'),
                    'severity': 'INFO',
                    'cwe': 'CWE-295: Improper Certificate Validation',
                },
                'files': [],
            },
            'webview_mixed_content': {
                'metadata': {
                    'description': (
                        'WebView is configured with '
                        'MIXED_CONTENT_ALWAYS_ALLOW.'),
                    'severity': 'ERROR',
                    'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information',
                },
                'files': [
                    {
                        'file_path': 'app/MainActivity.java',
                        'match_lines': [10, 12],
                        'match_position': [4, 40],
                        'match_string': 'MIXED_CONTENT_ALWAYS_ALLOW',
                    },
                    {
                        'file_path': 'app/Other.java',
                        'match_lines': [5, 5],
                        'match_string': 'setMixedContentMode',
                    },
                ],
            },
        },
    }
    raw = sonarqube_output(None, scan_results, '0.4.6')
    report = json.loads(raw)

    assert set(report.keys()) == {'rules', 'issues'}
    assert 'mobsfscan_version' not in report
    assert len(report['rules']) == 2
    assert len(report['issues']) == 2

    rules_by_id = {r['id']: r for r in report['rules']}
    pinning = rules_by_id['ios_cert_pinning']
    assert pinning['engineId'] == 'mobsfscan'
    assert pinning['type'] == 'VULNERABILITY'
    assert pinning['severity'] == 'INFO'
    assert pinning['cleanCodeAttribute'] == 'TRUSTWORTHY'
    assert pinning['impacts'] == [{
        'softwareQuality': 'SECURITY',
        'severity': 'LOW',
    }]
    assert 'Certificate Pinning' in pinning['name']
    assert pinning['description'].startswith('This app does not')

    mixed = rules_by_id['webview_mixed_content']
    assert mixed['severity'] == 'CRITICAL'
    assert mixed['impacts'][0]['severity'] == 'HIGH'

    issues_by_rule = {i['ruleId']: i for i in report['issues']}
    missing = issues_by_rule['ios_cert_pinning']
    assert missing['primaryLocation']['filePath'] == '.'
    assert missing['primaryLocation']['textRange']['startLine'] == 1
    assert 'secondaryLocations' not in missing

    vuln = issues_by_rule['webview_mixed_content']
    assert vuln['effortMinutes'] == 60
    primary = vuln['primaryLocation']
    assert primary['filePath'] == 'app/MainActivity.java'
    assert primary['textRange'] == {
        'startLine': 10,
        'endLine': 12,
        'startColumn': 4,
        'endColumn': 40,
    }
    assert 'MIXED_CONTENT_ALWAYS_ALLOW' in primary['message']
    assert len(vuln['secondaryLocations']) == 1
    assert vuln['secondaryLocations'][0]['filePath'] == 'app/Other.java'


def test_sonarqube_empty_results():
    report = json.loads(sonarqube_output(None, {'results': {}}, '0.0.0'))
    assert report == {'rules': [], 'issues': []}
