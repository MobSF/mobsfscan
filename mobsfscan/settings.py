#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""Settings."""
from pathlib import Path

MOBSFSCAN_CONFIG_FILE = '.mobsf'
BASE_DIR = Path(__file__).resolve().parent
SGREP_RULES_DIR = (
    BASE_DIR / 'rules' / 'semgrep'
)
ANDROID_RULES_DIR = (
    BASE_DIR / 'rules' / 'patterns' / 'android'
)
IOS_RULES_DIR = (
    BASE_DIR / 'rules' / 'patterns' / 'ios'
)
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
    'fixtures',
    'spec',
    '.git',
    '.svn',
}
BEST_PRACTICES_DIR = (
    BASE_DIR / 'rules' / 'semgrep' / 'best_practices'
)
BEST_PRACTICES_FILE = 'best_practices.yaml'

SEVERITY_FILTER = (
    'INFO',
    'WARNING',
    'ERROR',
)
