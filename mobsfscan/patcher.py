"""Libsast Patcher for supporting rules with metadata."""
from copy import deepcopy

from libsast.core_matcher.pattern_matcher import PatternMatcher


def add_finding(self, file_path, rule, matches):
    """Add Code Analysis Findings."""
    for match in matches:
        crule = deepcopy(rule)
        file_details = {
            'file_path': file_path.as_posix(),
            'match_string': match[0],
            'match_position': match[1],
            'match_lines': match[2],
        }
        if rule['id'] in self.findings:
            self.findings[rule['id']]['files'].append(file_details)
        else:
            metadata = crule['metadata']
            metadata['description'] = crule['message']
            metadata['severity'] = crule['severity']
            self.findings[rule['id']] = {
                'files': [file_details],
                'metadata': metadata,
            }


def patch_libsast():
    """Patch Libsast."""
    PatternMatcher.add_finding = add_finding
