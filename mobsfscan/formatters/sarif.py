# -*- coding: utf_8 -*-
"""Sarif output format.

Based on https://github.com/microsoft/bandit-sarif-formatter/
blob/master/bandit_sarif_formatter/formatter.py

Copyright (c) Microsoft.  All Rights Reserved.
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
"""
from datetime import datetime
from pathlib import PurePath
import urllib.parse as urlparse

import sarif_om as om

from jschema_to_python.to_json import to_json


TS_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def level_from_severity(severity):
    if severity == 'high':
        return 'error'
    elif severity == 'warning':
        return 'warning'
    elif severity == 'info':
        return 'note'
    else:
        return 'none'


def to_uri(file_path):
    pure_path = PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        posix_path = pure_path.as_posix()  # Replace backslashes with slashes.
        return urlparse.quote(posix_path)  # %-encode special characters.


def get_rule_name(rule_id):
    normalized = []
    noms = rule_id.split('_')
    for nom in noms:
        normalized.append(nom.capitalize())
    return ''.join(normalized)


def add_results(scan_results, run):
    if run.results is None:
        run.results = []
    res = {}
    res.update(scan_results.get('results', []))
    rules = {}
    rule_indices = {}

    for rule_id, issue_dict in res.items():
        if 'files' not in issue_dict:
            # no missing controls in sarif
            continue
        result = create_result(rule_id, issue_dict, rules, rule_indices)
        run.results.append(result)

    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values())


def create_result(rule_id, issue_dict, rules, rule_indices):
    if rule_id in rules:
        rule = rules[rule_id]
        rule_index = rule_indices[rule_id]
    else:
        doc = issue_dict['metadata'].get('ref')
        if not doc:
            doc = ('https://mobile-security.gitbook.io/'
                   'mobile-security-testing-guide/')
        rule = om.ReportingDescriptor(
            id=rule_id,
            name=get_rule_name(rule_id),
            help_uri=doc,
        )
        rule_index = len(rules)
        rules[rule_id] = rule
        rule_indices[rule_id] = rule_index

    locations = []
    for item in issue_dict['files']:
        physical_location = om.PhysicalLocation(
            artifact_location=om.ArtifactLocation(
                uri=to_uri(item['file_path'])),
        )
        physical_location.region = om.Region(
            start_line=item['match_lines'][0],
            end_line=item['match_lines'][1],
            start_column=item['match_position'][0],
            end_column=item['match_position'][1],
            snippet=om.ArtifactContent(text=item['match_string']),
        )
        locations.append(om.Location(physical_location=physical_location))

    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(text=issue_dict['metadata']['description']),
        level=level_from_severity(issue_dict['metadata']['severity']),
        locations=locations,
        properties={
            'owasp-mobile': issue_dict['metadata']['owasp-mobile'],
            'masvs': issue_dict['metadata']['masvs'],
            'cwe': issue_dict['metadata']['cwe'],
            'cvss': issue_dict['metadata']['cvss'],
        },
    )


def sarif_output(outfile, scan_results, mobsfscan_version):
    log = om.SarifLog(
        schema_uri=('https://raw.githubusercontent.com/oasis-tcs/'
                    'sarif-spec/master/Schemata/sarif-schema-2.1.0.json'),
        version='2.1.0',
        runs=[
            om.Run(
                tool=om.Tool(driver=om.ToolComponent(
                    name='mobsfscan',
                    information_uri='https://github.com/MobSF/mobsfscan',
                    semantic_version=mobsfscan_version,
                    version=mobsfscan_version),
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                    ),
                ],
            ),
        ],
    )
    run = log.runs[0]
    add_results(scan_results, run)
    json_out = to_json(log)
    if outfile:
        with open(outfile, 'w') as of:
            of.write(json_out)
    else:
        print(json_out)
    return json_out
