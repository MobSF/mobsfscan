# -*- coding: utf_8 -*-
"""Tests for GitLab SAST report formatter."""
import json

from mobsfscan.formatters.gitlab_sast import (
    SCHEMA_VERSION,
    gitlab_sast_output,
    gitlab_severity,
)


def test_gitlab_severity_mapping():
    assert gitlab_severity('ERROR') == 'Critical'
    assert gitlab_severity('WARNING') == 'Medium'
    assert gitlab_severity('INFO') == 'Info'


def test_gitlab_sast_report_shape(tmp_path):
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
                    'reference': 'https://example.com/pinning',
                },
                'files': [{
                    'file_path': 'app/Network.swift',
                    'match_lines': [12, 14],
                    'match_position': [1, 20],
                    'match_string': 'URLSession',
                }],
            },
            'webview_mixed_content': {
                'metadata': {
                    'description': (
                        'WebView is configured with '
                        'MIXED_CONTENT_ALWAYS_ALLOW.'),
                    'severity': 'ERROR',
                    'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information',
                    'owasp-mobile': 'M3: Insecure Communication',
                    'masvs': 'MSTG-NETWORK-1',
                    'reference': 'https://example.com/mixed',
                },
                'files': [{
                    'file_path': 'app/Web.java',
                    'match_lines': [10, 10],
                    'match_position': [5, 40],
                    'match_string': 'setMixedContentMode',
                }],
            },
        },
    }
    outfile = tmp_path / 'gl-sast-report.json'
    gitlab_sast_output(str(outfile), scan_results, '0.4.6')
    report = json.loads(outfile.read_text())

    assert report['version'] == SCHEMA_VERSION
    assert report['scan']['type'] == 'sast'
    assert report['scan']['scanner']['id'] == 'mobsfscan'
    assert report['scan']['scanner']['version'] == '0.4.6'
    assert len(report['vulnerabilities']) == 2

    by_file = {v['location']['file']: v for v in report['vulnerabilities']}
    pinning = by_file['app/Network.swift']
    assert pinning['severity'] == 'Info'
    assert 'Certificate Pinning' in pinning['name']
    assert pinning['location']['start_line'] == 12
    assert pinning['location']['end_line'] == 14
    types = {i['type'] for i in pinning['identifiers']}
    assert 'mobsfscan_rule_id' in types
    assert 'cwe' in types
    assert 'owasp_mobile' in types
    assert 'masvs' in types
    assert pinning['links'][0]['url'] == 'https://example.com/pinning'

    mixed = by_file['app/Web.java']
    assert mixed['severity'] == 'Critical'
    assert mixed['identifiers'][0]['value'] == 'webview_mixed_content'


def test_gitlab_sast_missing_control_location(tmp_path):
    scan_results = {
        'results': {
            'ios_cert_pinning': {
                'metadata': {
                    'description': 'Missing certificate pinning.',
                    'severity': 'INFO',
                    'cwe': 'cwe-295',
                },
            },
        },
    }
    outfile = tmp_path / 'gl-sast-report.json'
    gitlab_sast_output(str(outfile), scan_results, '0.4.6')
    report = json.loads(outfile.read_text())
    vuln = report['vulnerabilities'][0]
    assert vuln['location']['file'] == '.'
    assert vuln['location']['start_line'] == 1
