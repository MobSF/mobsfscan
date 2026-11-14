#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""Settings."""
from pathlib import Path

MOBSFSCAN_CONFIG_FILE = '.mobsf'
BASE_DIR = Path(__file__).resolve().parent
SGREP_RULES_DIR = (
    BASE_DIR / 'rules' / 'semgrep'
)
TS_RULES_DIR = (
    BASE_DIR / 'rules' / 'treesitter'
)
IOS_RULES_DIR = (
    BASE_DIR / 'rules' / 'patterns' / 'ios'
)
JS_SCAN_EXTENSIONS = {
    '.js',
    '.jsx',
    '.ts',
    '.tsx',
    '.mjs',
    '.cjs',
    '.vue',
    '.svelte',
    '.html',
    '.htm',
}
IGNORE_FILENAMES = {
    '.DS_Store',
    '*.min.js',
    'bootstrap.js',
    'bootstrap.min.js',
    'cordova.js',
    'cordova_plugins.js',
    'jquery.js',
    'jquery.min.js',
    'phonegap.js',
    'polyfills.js',
    'runtime.js',
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
    'node_modules',
    '.expo',
    '.next',
    '.gradle',
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
