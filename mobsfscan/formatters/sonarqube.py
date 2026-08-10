# -*- coding: utf_8 -*-
"""SonarQube generic issue format (SonarQube 10.3+).

See:
https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/importing-external-issues/generic-issue-import-format
"""
import json

from mobsfscan.formatters.sarif import format_rule_name


SEVERITY_MAP = {
    'ERROR': 'CRITICAL',
    'WARNING': 'MAJOR',
    'INFO': 'INFO',
}

IMPACT_SEVERITY_MAP = {
    'ERROR': 'HIGH',
    'WARNING': 'MEDIUM',
    'INFO': 'LOW',
}


def standard_severity(severity):
    return SEVERITY_MAP.get((severity or '').upper(), 'MAJOR')


def impact_severity(severity):
    return IMPACT_SEVERITY_MAP.get((severity or '').upper(), 'MEDIUM')


def build_rule(rule_id, issue_dict):
    """Build a SonarQube generic-issue rule object."""
    meta = issue_dict.get('metadata') or {}
    description = meta.get('description') or rule_id
    severity = meta.get('severity')
    return {
        'id': rule_id,
        'name': format_rule_name(rule_id, meta),
        'description': description,
        'engineId': 'mobsfscan',
        'cleanCodeAttribute': 'TRUSTWORTHY',
        'type': 'VULNERABILITY',
        'severity': standard_severity(severity),
        'impacts': [{
            'softwareQuality': 'SECURITY',
            'severity': impact_severity(severity),
        }],
    }


def build_locations(issue_dict):
    """Return primary location and optional secondary locations."""
    meta = issue_dict.get('metadata') or {}
    description = meta.get('description') or ''
    files = issue_dict.get('files') or []

    if not files:
        primary = {
            'message': description,
            'filePath': '.',
            'textRange': {
                'startLine': 1,
                'endLine': 1,
            },
        }
        return primary, []

    locations = []
    for file_item in files:
        message = description
        match_string = file_item.get('match_string')
        if match_string:
            message = f'{description} [{match_string}]'
        text_range = {
            'startLine': int(file_item['match_lines'][0]),
            'endLine': int(file_item['match_lines'][1]),
        }
        match_pos = file_item.get('match_position')
        if match_pos and len(match_pos) == 2:
            text_range['startColumn'] = int(match_pos[0])
            text_range['endColumn'] = int(match_pos[1])
        locations.append({
            'message': message,
            'filePath': file_item.get('file_path') or '.',
            'textRange': text_range,
        })
    return locations[0], locations[1:]


def build_issue(rule_id, issue_dict):
    """Build a SonarQube generic-issue issue object."""
    primary, secondary = build_locations(issue_dict)
    issue = {
        'ruleId': rule_id,
        'primaryLocation': primary,
    }
    if secondary:
        issue['secondaryLocations'] = secondary
    # Rough effort by severity
    severity = (issue_dict.get('metadata') or {}).get('severity', '').upper()
    issue['effortMinutes'] = {
        'ERROR': 60,
        'WARNING': 30,
        'INFO': 15,
    }.get(severity, 30)
    return issue


def sonarqube_output(outfile, scan_results, version):
    """Return SonarQube generic issues JSON (rules + issues)."""
    del version  # kept for CLI signature compatibility
    rules = []
    issues = []
    for rule_id, issue_dict in (scan_results.get('results') or {}).items():
        rules.append(build_rule(rule_id, issue_dict))
        issues.append(build_issue(rule_id, issue_dict))

    report = {
        'rules': rules,
        'issues': issues,
    }
    jout = json.dumps(
        report,
        sort_keys=True,
        indent=2,
        separators=(',', ': '))
    if outfile:
        with open(outfile, 'w') as of:
            of.write(jout)
    else:
        print(jout)
    return jout
