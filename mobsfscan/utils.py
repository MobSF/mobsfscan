# -*- coding: utf_8 -*-
"""Logger Config."""
import socket
import unicodedata
from urllib.parse import urlparse
from pathlib import Path

import mobsfscan.settings as config
from mobsfscan.logger import init_logger

import yaml


logger = init_logger(__name__)


def report_path(path):
    """Prefer cwd-relative POSIX paths in findings (matches Semgrep/source).

    Absolute paths cause duplicate findings in ASOC/VM tools when the same
    project is scanned from different working directories (#109).
    """
    p = Path(path)
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return p.as_posix()


def filter_none(user_list):
    """Filter and remove None values from user supplied config."""
    if not user_list:
        return None
    return list(filter(lambda item: item is not None, user_list))


VALID_SEVERITIES = {'INFO', 'WARNING', 'ERROR'}


def normalize_severity_overrides(raw):
    """Parse severity-overrides map; return {rule_id: SEVERITY}."""
    if not raw or not isinstance(raw, dict):
        return {}
    overrides = {}
    for rule_id, severity in raw.items():
        if rule_id is None or severity is None:
            continue
        rid = str(rule_id).strip()
        sev = str(severity).strip().upper()
        if not rid:
            continue
        if sev not in VALID_SEVERITIES:
            logger.warning(
                'Invalid severity `%s` for rule `%s` in '
                'severity-overrides. Use INFO, WARNING, or ERROR.',
                severity, rid)
            continue
        overrides[rid] = sev
    return overrides


def get_config(base_path, config_file):
    options = {
        'ignore_filenames': config.IGNORE_FILENAMES,
        'ignore_extensions': config.IGNORE_EXTENSIONS,
        'ignore_paths': config.IGNORE_PATHS,
        'ignore_rules': set(),
        'severity_filter': config.SEVERITY_FILTER,
        'severity_overrides': {},
    }
    if config_file:
        cfile = Path(config_file)
    else:
        cfile = Path(base_path[0]) / config.MOBSFSCAN_CONFIG_FILE
    if cfile.is_file() and cfile.exists():
        extras = read_yaml(cfile)
        root = validate_config(extras, options)
        if not root:
            logger.warning('Invalid YAML, ignoring config from .mobsf')
            return options
        usr_ignore_files = filter_none(root.get('ignore-filenames'))
        usr_igonre_paths = filter_none(root.get('ignore-paths'))
        usr_ignore_rules = filter_none(root.get('ignore-rules'))
        usr_severity_filter = filter_none(root.get('severity-filter'))
        usr_severity_overrides = normalize_severity_overrides(
            root.get('severity-overrides'))
        if usr_ignore_files:
            options['ignore_filenames'].update(usr_ignore_files)
        if usr_igonre_paths:
            options['ignore_paths'].update(usr_igonre_paths)
        if usr_ignore_rules:
            options['ignore_rules'].update(usr_ignore_rules)
        if usr_severity_filter:
            options['severity_filter'] = usr_severity_filter
        if usr_severity_overrides:
            options['severity_overrides'] = usr_severity_overrides
    return options


def validate_config(extras, options):
    """Validate user supplied config file."""
    if not extras:
        return False
    if isinstance(extras, dict):
        root = extras
    else:
        root = extras[0]
    valid = True
    for key, value in root.items():
        opt_key = key.replace('-', '_')
        if opt_key not in options.keys():
            valid = False
            logger.warning('The config `%s` is not supported.', key)
            continue
        if opt_key == 'severity_overrides':
            if not isinstance(value, dict):
                valid = False
                logger.warning(
                    'The value `%s` for the config `%s` is invalid.'
                    ' Only a mapping of rule_id: severity is supported.',
                    value, key)
            continue
        if not isinstance(value, list):
            valid = False
            logger.warning('The value `%s` for the config `%s` is invalid.'
                           ' Only list of value(s) are supported.', value, key)
    if not valid:
        return False
    return root


def read_yaml(file_obj, text=False):
    """Read Yaml."""
    try:
        if text:
            return yaml.safe_load(file_obj)
        return yaml.safe_load(file_obj.read_text('utf-8', 'ignore'))
    except yaml.YAMLError:
        logger.error('Failed to parse YAML')
    except Exception:
        logger.exception('Error parsing YAML')
    return None


def get_best_practices(extensions):
    """Get best practices for one or more extensions.

    Best-practice rules match control *presence*. MobSFScan.missing_controls()
    inverts them: delete when present, report when missing across the scan.
    """
    if isinstance(extensions, str):
        extensions = [extensions]
    ids = set()
    all_rules = {}
    for extension in extensions:
        if extension == '.java':
            java_dir = config.BEST_PRACTICES_DIR / 'java'
            for yml in java_dir.rglob('*.yaml'):
                rules = read_yaml(yml)
                if not rules or 'rules' not in rules:
                    continue
                for rule in rules['rules']:
                    all_rules[rule['id']] = rule
                    ids.add(rule['id'])
        elif extension == '.kt':
            kt_dir = config.BEST_PRACTICES_DIR / 'kotlin'
            for yml in kt_dir.rglob('*.yaml'):
                rules = read_yaml(yml)
                if not rules or 'rules' not in rules:
                    continue
                for rule in rules['rules']:
                    all_rules[rule['id']] = rule
                    ids.add(rule['id'])
        elif extension == '.swift':
            swift_dir = config.BEST_PRACTICES_DIR / 'swift'
            for yml in swift_dir.rglob('*.yaml'):
                rules = read_yaml(yml)
                if not rules or 'rules' not in rules:
                    continue
                for rule in rules['rules']:
                    all_rules[rule['id']] = rule
                    ids.add(rule['id'])
        elif extension == '.m':
            bp = config.IOS_RULES_DIR / 'objectivec' / 'best_practices.yaml'
            rules = read_yaml(bp)
            if not rules:
                continue
            for rule in rules:
                all_rules[rule['id']] = rule
                ids.add(rule['id'])
    return ids, all_rules


def is_number(s):
    if not s:
        return False
    if s == 'NaN':
        return False
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def valid_host(host):
    """Check if host is valid."""
    try:
        prefixs = ('http://', 'https://')
        if not host.startswith(prefixs):
            host = f'http://{host}'
        parsed = urlparse(host)
        domain = parsed.netloc
        path = parsed.path
        if len(domain) == 0:
            # No valid domain
            return False
        if len(path) > 0:
            # Only host is allowed
            return False
        if ':' in domain:
            # IPv6
            return False
        # Local network
        invalid_prefix = (
            '127.',
            '192.',
            '10.',
            '172.',
            '169',
            '0.',
            'localhost')
        if domain.startswith(invalid_prefix):
            return False
        ip = socket.gethostbyname(domain)
        if ip.startswith(invalid_prefix):
            # Resolve dns to get IP
            return False
        return True
    except Exception:
        return False
