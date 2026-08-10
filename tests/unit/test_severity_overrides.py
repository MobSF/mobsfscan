# -*- coding: utf_8 -*-
"""Tests for .mobsf severity-overrides (#108)."""
from mobsfscan.mobsfscan import MobSFScan
from mobsfscan.utils import (
    get_config,
    normalize_severity_overrides,
)


def test_normalize_severity_overrides():
    assert normalize_severity_overrides(None) == {}
    assert normalize_severity_overrides(['ios_log']) == {}
    assert normalize_severity_overrides({
        'ios_log': 'error',
        'android_logging': ' WARNING ',
        'bad': 'critical',
        '': 'ERROR',
    }) == {
        'ios_log': 'ERROR',
        'android_logging': 'WARNING',
    }


def test_get_config_reads_severity_overrides(tmp_path):
    cfg = tmp_path / '.mobsf'
    cfg.write_text(
        '---\n'
        '- severity-overrides:\n'
        '    ios_log: ERROR\n'
        '    android_logging: warning\n',
        encoding='utf-8')
    options = get_config([str(tmp_path)], False)
    assert options['severity_overrides'] == {
        'ios_log': 'ERROR',
        'android_logging': 'WARNING',
    }


def test_post_override_severities_before_filter(tmp_path):
    cfg = tmp_path / 'custom.mobsf'
    cfg.write_text(
        '---\n'
        '- severity-overrides:\n'
        '    ios_log: ERROR\n'
        '  severity-filter:\n'
        '  - ERROR\n',
        encoding='utf-8')
    scan = MobSFScan([str(tmp_path)], True, config=str(cfg))
    scan.result = {
        'results': {
            'ios_log': {
                'metadata': {
                    'description': 'logs',
                    'severity': 'INFO',
                },
            },
            'other_rule': {
                'metadata': {
                    'description': 'x',
                    'severity': 'WARNING',
                },
            },
        },
        'errors': [],
    }
    scan.post_override_severities()
    assert scan.result['results']['ios_log']['metadata']['severity'] == 'ERROR'
    scan.post_ignore_rules_by_severity()
    assert 'ios_log' in scan.result['results']
    assert 'other_rule' not in scan.result['results']


def test_severity_override_ignored_for_missing_rule(tmp_path):
    cfg = tmp_path / '.mobsf'
    cfg.write_text(
        '---\n'
        '- severity-overrides:\n'
        '    missing_rule: ERROR\n',
        encoding='utf-8')
    scan = MobSFScan([str(tmp_path)], True, config=str(cfg))
    scan.result = {
        'results': {
            'ios_log': {
                'metadata': {'severity': 'INFO'},
            },
        },
        'errors': [],
    }
    scan.post_override_severities()
    assert scan.result['results']['ios_log']['metadata']['severity'] == 'INFO'
