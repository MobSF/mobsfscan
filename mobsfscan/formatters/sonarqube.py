# -*- coding: utf_8 -*-
"""Sonarqube output format."""

from mobsfscan.formatters.json_fmt import json_output


def get_sonarqube_issue(mobsfscan_issue):
    sonarqube_severity_mapping = {
        'ERROR': 'CRITICAL',
        'WARNING': 'MAJOR',
        'INFO': 'INFO',
    }
    secondary_locations = []
    issue_data = mobsfscan_issue['metadata']
    # Handle missing controls
    if not mobsfscan_issue.get('files'):
        text_range = {
            'startLine': 1,
            'endLine': 0,
        }
        location = {
            'message': issue_data['description'],
            'filePath': '',
            'textRange': text_range,
        }
        primary_location = location
    else:
        for ix, file in enumerate(mobsfscan_issue['files']):
            text_range = {
                'startLine': file['match_lines'][0],
                'endLine': file['match_lines'][1],
            }
            location = {
                'message': issue_data['description'],
                'filePath': file['file_path'],
                'textRange': text_range,
            }

            if 'match_string' in file:
                location['message'] += ' [%s]' % file['match_string']

            if ix == 0:
                primary_location = location
            else:
                secondary_locations.append(location)
    issue = {
        'engineId': 'mobsfscan',
        'type': 'VULNERABILITY',
        'severity': sonarqube_severity_mapping[issue_data['severity']],
        'primaryLocation': primary_location,
    }
    if secondary_locations:
        issue['secondaryLocations'] = secondary_locations
    return issue


def sonarqube_output(outfile, scan_results, version):
    """Sonarqube JSON Output."""
    sonarqube_issues = []
    for k, v in scan_results['results'].items():
        issue = get_sonarqube_issue(v)
        issue['ruleId'] = k
        sonarqube_issues.append(issue)
    sonarqube_report = {
        'issues': sonarqube_issues,
    }
    return json_output(outfile, sonarqube_report, version)
