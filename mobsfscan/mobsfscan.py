# -*- coding: utf_8 -*-
"""The MobSF cli: mobsfscan."""
from pathlib import Path
from linecache import getline

from libsast import (
    Scanner,
    standards,
)

from mobsfscan import settings
from mobsfscan.utils import (
    get_best_practices,
    get_config,
)


class MobSFScan:
    def __init__(self, paths, json, config=False) -> None:
        self.conf = get_config(paths, config)
        self.options = {
            'match_rules': None,
            'sgrep_rules': None,
            'sgrep_extensions': None,
            'match_extensions': None,
            'ignore_filenames': self.conf['ignore_filenames'],
            'ignore_extensions': self.conf['ignore_extensions'],
            'ignore_paths': self.conf['ignore_paths'],
            'ignore_rules': self.conf['ignore_rules'],
            'severity_filter': self.conf['severity_filter'],
            'show_progress': not json,
        }
        self.paths = paths
        self.result = {
            'results': {},
            'errors': [],
        }
        self.best_practices = None
        self.standards = standards.get_standards()
        self.get_extensions()

    def rules_selector(self, suffix):
        """Get rule extensions from suffix."""
        if suffix in ['.java', '.kt']:
            if suffix == '.java':
                self.best_practices = '.java'
            else:
                self.best_practices = '.kt'
            self.options['match_rules'] = settings.ANDROID_RULES_DIR.as_posix()
            self.options['sgrep_rules'] = settings.SGREP_RULES_DIR.as_posix()
            self.options['sgrep_extensions'] = {'.java'}
            self.options['match_extensions'] = {'.kt'}
        elif suffix in {'.swift', '.m'}:
            if suffix == '.swift':
                self.best_practices = '.swift'
            else:
                self.best_practices = '.m'
            self.options['match_rules'] = settings.IOS_RULES_DIR.as_posix()
            self.options['match_extensions'] = {'.m', '.swift'}

    def get_extensions(self) -> set:
        """Get extensions to scan."""
        scan_suffix = {'.java', '.kt', '.swift', '.m'}
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                for pfile in pobj.rglob('*'):
                    if pfile.suffix not in scan_suffix:
                        continue
                    return self.rules_selector(pfile.suffix)
            else:
                if pobj.suffix not in scan_suffix:
                    continue
                return self.rules_selector(pobj.suffix)

    def scan(self) -> dict:
        """Start Scan."""
        scanner = Scanner(self.options, self.paths)
        result = scanner.scan()
        if result:
            self.format_output(result)
        return self.result

    def format_output(self, results) -> dict:
        """Format to mobsfscan friendly output."""
        self.format_semgrep(results.get('semantic_grep'))
        # TODO: When we support kotlin semgrep, this needs rework
        self.format_pattern(results.get('pattern_matcher'))
        self.missing_controls()
        self.post_ignore_rules()
        self.post_ignore_rules_by_severity()
        self.post_ignore_files()

    def format_semgrep(self, sgrep_output):
        """Format semgrep output."""
        if not sgrep_output:
            return
        self.result['errors'] = sgrep_output['errors']
        for rule_id in sgrep_output['matches']:
            for finding in sgrep_output['matches'][rule_id]['files']:
                finding.pop('metavars', None)
        self.result['results'] = sgrep_output['matches']

    def format_pattern(self, matcher_out):
        """Format Pattern Matcher output."""
        if not matcher_out:
            return
        self.result['results'].update(matcher_out)

    def missing_controls(self):
        """Check for missing controls."""
        if not self.best_practices:
            return
        ids, rules = get_best_practices(self.best_practices)
        result_keys = self.result['results'].keys()
        deleted = set()
        for rule_id in ids:
            if rule_id in result_keys:
                # Control Present
                deleted.add(rule_id)
                del self.result['results'][rule_id]
        # Add Missing
        missing = ids.difference(result_keys)
        for rule_id in missing:
            if rule_id in deleted:
                continue
            self.result['results'][rule_id] = {}
            res = self.result['results'][rule_id]
            details = rules[rule_id]
            res['metadata'] = details['metadata']
            res['metadata']['description'] = details['message']
            res['metadata']['severity'] = details['severity']
            self.expand_mappings(res)

    def expand_mappings(self, meta):
        """Expand libsast standard mappings for missing controls."""
        meta_keys = meta['metadata'].keys()
        for mkey in meta_keys:
            if mkey not in self.standards.keys():
                continue
            to_expand = meta['metadata'][mkey]
            expanded = self.standards[mkey].get(to_expand)
            if expanded:
                meta['metadata'][mkey] = expanded

    def post_ignore_rules(self):
        """Ignore findings by rules."""
        for rule_id in self.options['ignore_rules']:
            if rule_id in self.result['results']:
                del self.result['results'][rule_id]

    def post_ignore_rules_by_severity(self):
        """Filter findings by rule severity."""
        del_keys = set()
        for rule_id, details in self.result['results'].items():
            issue_severity = details.get('metadata').get('severity')
            if issue_severity not in self.options['severity_filter']:
                del_keys.add(rule_id)
        for rid in del_keys:
            if rid in self.result['results']:
                del self.result['results'][rid]

    def suppress_pm_comments(self, obj, rule_id):
        """Suppress pattern matcher."""
        file_path = obj['file_path']
        lines = obj['match_lines']
        if lines[0] != lines[1]:
            # Skip multiline for now
            return False
        match_line = getline(file_path, lines[0])
        if 'mobsf-ignore:' in match_line and rule_id in match_line:
            return True
        return False

    def post_ignore_files(self):
        """Ignore file by rule."""
        del_keys = set()
        for rule_id, details in self.result['results'].items():
            files = details.get('files')
            if not files:
                continue
            tmp_files = files.copy()
            for file in files:
                mstr = file.get('match_string')
                if 'mobsf-ignore:' in mstr and rule_id in mstr:
                    tmp_files.remove(file)
                elif self.suppress_pm_comments(file, rule_id):
                    tmp_files.remove(file)
                if len(tmp_files) == 0:
                    del_keys.add(rule_id)
            details['files'] = tmp_files
        # Remove Rule IDs marked for deletion.
        for rid in del_keys:
            if rid in self.result['results']:
                del self.result['results'][rid]
