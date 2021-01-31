#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""Settings."""
from pathlib import Path

MOBSFSCAN_CONFIG_FILE = '.mobsf'
BASE_DIR = Path(__file__).resolve().parent
PATTERN_RULES_DIR = (
    BASE_DIR / 'rules' / 'pattern_matcher'
).as_posix()

SCAN_EXTENSIONS = {
    '.java', '.kt', '.swift', '.m',
}
IGNORE_FILENAMES = {
    '.DS_Store',
}
IGNORE_EXTENSIONS = {
    '.apk',
    '.zip',
    '.ipa',
}
IGNORE_PATHS = {
    '__MACOSX',
    'node_modules',
    'bower_components',
    'fixtures',
    'jquery',
    'spec',
    'example',
    '.git',
    '.svn',
}
