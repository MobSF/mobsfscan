# -*- coding: utf_8 -*-
"""SARIF output formatter for MobSF scan results.

Based on https://github.com/microsoft/
bandit-sarif-formatter/blob/master/
bandit_sarif_formatter/formatter.py
MIT License, Copyright (c) Microsoft Corporation.

Enriched for GitHub Code Scanning, GitLab SARIF import, and SonarQube.
"""
from datetime import datetime, timezone
from pathlib import Path, PurePath
import re
import urllib.parse as urlparse

import sarif_om as om

from jschema_to_python.to_json import to_json

TS_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
_CWE_ID_RE = re.compile(r'(?i)\bCWE-?(\d+)\b')
_MAX_RULE_NAME = 255
_MAX_TAGS = 10
_DEFAULT_HELP = ('https://mobile-security.gitbook.io/'
                 'mobile-security-testing-guide/')


def level_from_severity(severity):
    return {
        'ERROR': 'error',
        'WARNING': 'warning',
        'INFO': 'note',
    }.get((severity or '').upper(), 'none')


def security_severity_score(metadata=None):
    """GitHub/GitLab security-severity (0.1-10.0). Prefer CVSS when present."""
    metadata = metadata or {}
    cvss = metadata.get('cvss')
    if cvss is not None:
        try:
            score = float(cvss)
        except (TypeError, ValueError):
            # Non-numeric CVSS in rule metadata; use severity map below.
            score = None
        if score is not None and 0.1 <= score <= 10.0:
            return f'{score:.1f}'
    return {
        'ERROR': '9.0',
        'WARNING': '5.5',
        'INFO': '2.0',
    }.get((metadata.get('severity') or '').upper(), '5.0')


def precision_from_severity(severity):
    return {
        'ERROR': 'high',
        'WARNING': 'high',
        'INFO': 'medium',
    }.get((severity or '').upper(), 'medium')


def to_uri(file_path):
    """Prefer repo-relative paths for GHAS/GitLab; fall back to path/URI."""
    pure_path = PurePath(file_path)
    if pure_path.is_absolute():
        try:
            rel = Path(file_path).resolve().relative_to(Path.cwd().resolve())
            return urlparse.quote(rel.as_posix())
        except (ValueError, OSError):
            return pure_path.as_uri()
    return urlparse.quote(pure_path.as_posix())


def _cwe_id(cwe):
    """Return normalized CWE-NNN id from metadata, if present."""
    if not cwe:
        return None
    match = _CWE_ID_RE.search(str(cwe).split(':', 1)[0])
    if not match:
        return None
    return f'CWE-{match.group(1)}'


def _first_sentence(text):
    """Return a short title from the first sentence of description."""
    if not text:
        return ''
    cleaned = ' '.join(str(text).strip().split())
    for sep in ('. ', '? ', '! '):
        if sep in cleaned:
            cleaned = cleaned.split(sep, 1)[0]
            break
    else:
        cleaned = cleaned.rstrip('.?!')
    return cleaned.strip()


def _slug_tag(prefix, value):
    """Build a compact tag like owasp-mobile/m3 from expanded or raw values."""
    if not value:
        return None
    raw = str(value).split(':', 1)[0].strip().lower()
    raw = raw.replace('mstg-', '').replace('masvs-', '')
    raw = re.sub(r'[^a-z0-9\-]+', '-', raw).strip('-')
    if not raw:
        return None
    return f'{prefix}/{raw}'


def build_tags(metadata=None):
    """Build SARIF tags (max 10 for GitLab) from available metadata."""
    metadata = metadata or {}
    tags = ['security']
    cwe_id = _cwe_id(metadata.get('cwe'))
    if cwe_id:
        tags.append(f'external/cwe/{cwe_id.lower()}')
    for prefix, key in (
            ('owasp-mobile', 'owasp-mobile'),
            ('masvs', 'masvs')):
        tag = _slug_tag(prefix, metadata.get(key))
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:_MAX_TAGS]


def format_rule_name(rule_id, metadata=None):
    """Build a human-readable SARIF rule name for dashboards.

    Prefers the check description (unique per rule) and appends the CWE id
    when available. Capped at 255 chars for GitLab.
    """
    metadata = metadata or {}
    title = _first_sentence(metadata.get('description'))
    if not title:
        title = ''.join(word.capitalize() for word in rule_id.split('_'))

    cwe_id = _cwe_id(metadata.get('cwe'))
    if cwe_id and cwe_id not in title.upper():
        title = f'{title} ({cwe_id})'
    if len(title) > _MAX_RULE_NAME:
        title = title[:_MAX_RULE_NAME - 1].rstrip() + '…'
    return title


def add_results(path, scan_results, run):
    if run.results is None:
        run.results = []
    res = scan_results.get('results', {})
    rules = {}
    rule_indices = {}

    for rule_id, issue_dict in res.items():
        rule_results = create_rule_results(
            path, rule_id, issue_dict, rules, rule_indices)
        run.results.extend(rule_results)

    if rules:
        run.tool.driver.rules = list(rules.values())


def create_rule_results(path, rule_id, issue_dict, rules, rule_indices):
    rule_results = []
    rule, rule_index = rules.get(rule_id), rule_indices.get(rule_id)
    if not rule:
        meta = issue_dict.get('metadata') or {}
        doc = meta.get('reference') or meta.get('ref') or _DEFAULT_HELP
        description = meta.get('description') or format_rule_name(rule_id, meta)
        short_title = format_rule_name(rule_id, meta)
        level = level_from_severity(meta.get('severity'))
        help_text = description
        if doc:
            help_text = f'{description}\n\nReference: {doc}'
        rule = om.ReportingDescriptor(
            id=rule_id,
            name=short_title,
            short_description=om.MultiformatMessageString(text=short_title),
            full_description=om.MultiformatMessageString(text=description),
            help=om.MultiformatMessageString(text=help_text),
            help_uri=doc,
            default_configuration=om.ReportingConfiguration(level=level),
            properties={
                'tags': build_tags(meta),
                'precision': precision_from_severity(meta.get('severity')),
                'security-severity': security_severity_score(meta),
                'problem.severity': level if level != 'none' else 'warning',
            })
        rule_index = len(rules)
        rules[rule_id] = rule
        rule_indices[rule_id] = rule_index

    for item in issue_dict.get('files', []):
        location = create_location(item)
        rule_results.append(create_result(rule, rule_index, issue_dict, [location]))

    if not issue_dict.get('files'):
        default_location = om.Location(
            physical_location=om.PhysicalLocation(
                artifact_location=om.ArtifactLocation(uri=to_uri(path[0])),
                region=om.Region(
                    start_line=1,
                    end_line=1,
                    start_column=1,
                    end_column=1,
                    snippet=om.ArtifactContent(text='Missing Best Practice'))))
        rule_results.append(create_result(
            rule, rule_index, issue_dict, [default_location]))

    return rule_results


def create_location(item):
    return om.Location(
        physical_location=om.PhysicalLocation(
            artifact_location=om.ArtifactLocation(uri=to_uri(item['file_path'])),
            region=om.Region(
                start_line=item['match_lines'][0],
                end_line=item['match_lines'][1],
                start_column=item['match_position'][0],
                end_column=item['match_position'][1],
                snippet=om.ArtifactContent(text=item['match_string']))))


def create_result(rule, rule_index, issue_dict, locations):
    meta = issue_dict.get('metadata') or {}
    score = security_severity_score(meta)
    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(text=meta.get('description') or rule.name),
        level=level_from_severity(meta.get('severity')),
        locations=locations,
        properties={
            'owasp-mobile': meta.get('owasp-mobile'),
            'masvs': meta.get('masvs'),
            'cwe': meta.get('cwe'),
            'reference': meta.get('reference') or meta.get('ref'),
            'security-severity': score,
        })


def sarif_output(outfile, scan_results, mobsfscan_version, path):
    log = om.SarifLog(
        schema_uri=('https://raw.githubusercontent.com/'
                    'oasis-tcs/sarif-spec/master/Schemata/'
                    'sarif-schema-2.1.0.json'),
        version='2.1.0',
        runs=[om.Run(
            tool=om.Tool(driver=om.ToolComponent(
                name='mobsfscan',
                information_uri='https://github.com/MobSF/mobsfscan',
                semantic_version=mobsfscan_version,
                version=mobsfscan_version,
            )),
            invocations=[om.Invocation(
                end_time_utc=datetime.now(timezone.utc).strftime(TS_FORMAT),
                execution_successful=True,
            )])])
    run = log.runs[0]
    add_results(path, scan_results, run)
    json_out = to_json(log)

    if outfile:
        with open(outfile, 'w') as of:
            of.write(json_out)
    else:
        print(json_out)

    return json_out
