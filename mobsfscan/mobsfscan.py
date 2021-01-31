# -*- coding: utf_8 -*-
"""The MobSF cli: mobsfscan."""
from libsast import Scanner

from mobsfscan import settings
from mobsfscan.utils import (
    get_config,
)


class MobSFScan:
    def __init__(self, paths, json, config=False) -> None:
        conf = get_config(paths, config)
        self.options = {
            'match_rules': settings.PATTERN_RULES_DIR,
            'match_extensions': conf['scan_extensions'],
            'ignore_filenames': conf['ignore_filenames'],
            'ignore_extensions': conf['ignore_extensions'],
            'ignore_paths': conf['ignore_paths'],
            'ignore_rules': conf['ignore_rules'],
            'suppress_findings': conf['suppress_findings'],
            'show_progress': not json,
        }
        self.paths = paths
        self.result = {
            'results': {},
        }

    def scan(self) -> dict:
        """Start Scan."""
        scanner = Scanner(self.options, self.paths)
        result = scanner.scan()
        if result:
            self.format_output(result)
        return self.result

    def format_output(self, results) -> dict:
        """Format to mobsfscan friendly output."""
        self.format_matches(results['pattern_matcher'])
        self.post_ignore_rules()
        self.post_ignore_findings()

    def format_matches(self, matcher_out):
        """Format Pattern Matcher output."""
        self.result['results'] = matcher_out

    def post_ignore_rules(self):
        """Ignore findings by rules."""
        for rule_id in self.options['ignore_rules']:
            if rule_id in self.result['results']:
                del self.result['results'][rule_id]

    def is_suppressed(self, rule_id, obj):
        """Check if finding is suppressed."""
        suppressions = self.options['suppress_findings'].get(rule_id)
        if not suppressions:
            return False
        for ignore in suppressions:
            if ',' not in ignore:
                # Invalid format, just ignore
                return False
            parts = ignore.split(',')
            if not len(parts) > 1:
                # Invalid, line nos not provided
                return False
            name = parts[0]
            lines = parts[1:]
            lines = [lno.strip() for lno in lines]
            mline = obj['match_lines']
            is_name = name in obj['file_path']
            is_line = str(mline[0]) in lines or str(mline[1]) in lines
            if is_name and is_line:
                return True
        return False

    def is_cross_pollution(self, rule_id, obj):
        """Check if finding is cross pollution."""
        andr = rule_id.startswith('android_')
        iosr = rule_id.startswith('ios_')
        andext = obj['file_path'].endswith(('.java', '.kt'))
        iosext = obj['file_path'].endswith(('.swift', '.m'))
        if andr and iosext:
            return True
        if iosr and andext:
            return True
        return False

    def post_ignore_findings(self):
        """Ignore file by rule."""
        del_keys = set()
        for rule_id, details in self.result['results'].items():
            files = details.get('files')
            if not files:
                continue
            tmp_files = files.copy()
            for file_ in files:
                if self.is_suppressed(rule_id, file_):
                    tmp_files.remove(file_)
                if self.is_cross_pollution(rule_id, file_):
                    tmp_files.remove(file_)
                if len(tmp_files) == 0:
                    del_keys.add(rule_id)
            details['files'] = tmp_files
        # Remove Rule IDs marked for deletion.
        for rid in del_keys:
            if rid in self.result['results']:
                del self.result['results'][rid]
