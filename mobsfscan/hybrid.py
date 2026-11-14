# -*- coding: utf_8 -*-
"""Cordova, Capacitor, and Expo hybrid configuration checks."""
import json

from xmltodict import parse

from mobsfscan.logger import init_logger
from mobsfscan.manifest import add_finding, mobsfscan_format
from mobsfscan.utils import report_path


logger = init_logger(__name__)
MAX_CONFIG_BYTES = 5 * 1024 * 1024
EXPO_CONFIG_FILES = {
    'app.json',
    'app.config.json',
    'app.config',
    'app.manifest',
}
HYBRID_CONFIG_FILES = {'config.xml', 'capacitor.config.json'} | EXPO_CONFIG_FILES
_WILDCARD_NAV_HREFS = {'*', 'http://*/*', 'https://*/*'}
_SECRET_ENDSWITH = (
    'api', 'key', 'secret', 'token', 'username',
    'user_name', 'user', 'pass', 'password',
    'private_key', 'access_key',
)
_SECRET_CONTAINS = (
    'api_', 'key_', 'aws', 's3_', '_s3', 'secret_',
    'bearer', 'jwt', 'certificate"', 'credential',
    'azure', 'webhook', 'twilio_', 'bitcoin',
    '_auth', 'firebase', 'oauth', 'authorization',
    'private', 'pwd', 'session', 'token_', 'gcp',
)
_SECRET_NOT_CONTAINS = (
    'label_', 'text', 'hint', 'msg_', 'create_',
    'message', 'new', 'confirm', 'activity_',
    'forgot', 'dashboard_', 'current_', 'signup',
    'sign_in', 'signin', 'title_', 'welcome_',
    'change_', 'this_', 'the_', 'placeholder',
    'invalid_', 'btn_', 'action_', 'prompt_',
    'lable', 'hide_', 'old', 'update', 'error',
    'empty', 'txt_', 'lbl_',
)


def is_secret_key(key):
    """Return True if a config key name looks like a credential or secret."""
    key_lower = key.lower()
    if any(skip in key_lower for skip in _SECRET_NOT_CONTAINS):
        return False
    return (
        any(key_lower.endswith(sfx) for sfx in _SECRET_ENDSWITH)
        or any(part in key_lower for part in _SECRET_CONTAINS)
    )


def _line_of_substring(text, needle):
    """Return 1-indexed line number of needle in text."""
    idx = text.find(needle)
    if idx == -1:
        return 1
    return text.count('\n', 0, idx) + 1


def _read_bounded_text(cfg_path):
    """Read UTF-8 text if file size is within MAX_CONFIG_BYTES."""
    if cfg_path.stat().st_size > MAX_CONFIG_BYTES:
        return None
    return cfg_path.read_text(encoding='utf-8', errors='ignore')


def _iter_xml_elements(node):
    """Yield (local_tag_name, attrs_dict) pairs across an xmltodict tree."""
    if isinstance(node, list):
        for item in node:
            yield from _iter_xml_elements(item)
        return
    if not isinstance(node, dict):
        return
    for raw_tag, child in node.items():
        if raw_tag.startswith('@'):
            continue
        local_tag = raw_tag.split(':')[-1].lower()
        if isinstance(child, dict):
            yield local_tag, child
            yield from _iter_xml_elements(child)
        elif isinstance(child, list):
            for entry in child:
                if isinstance(entry, dict):
                    yield local_tag, entry
                    yield from _iter_xml_elements(entry)


def _find_widget_root(parsed):
    """Return the Cordova <widget> mapping if present, else None."""
    if not isinstance(parsed, dict):
        return None
    for raw_tag, val in parsed.items():
        if raw_tag.split(':')[-1].lower() == 'widget' and isinstance(val, dict):
            return val
    return None


def check_cordova_config(cfg_path, reported_path):
    """Check Cordova / PhoneGap config.xml for wildcard access/navigation."""
    findings = []
    raw = _read_bounded_text(cfg_path)
    if not raw:
        return findings
    try:
        parsed = parse(raw)
    except Exception:
        return findings
    widget = _find_widget_root(parsed)
    if widget is None:
        return findings
    for tag, attrs in _iter_xml_elements(widget):
        if tag == 'access' and str(attrs.get('@origin', '')).strip() == '*':
            add_finding(
                findings,
                reported_path,
                'cordova_config_wildcard_access',
                line=_line_of_substring(raw, '<access'),
            )
        elif tag == 'allow-navigation':
            href = str(attrs.get('@href', '')).strip()
            if href in _WILDCARD_NAV_HREFS:
                add_finding(
                    findings,
                    reported_path,
                    'cordova_config_wildcard_navigation',
                    dynamic=(href,),
                    line=_line_of_substring(raw, '<allow-navigation'),
                )
    return findings


def check_capacitor_config(cfg_path, reported_path):
    """Check Capacitor capacitor.config.json for cleartext or wildcard nav."""
    findings = []
    raw = _read_bounded_text(cfg_path)
    if not raw:
        return findings
    try:
        data = json.loads(raw)
    except Exception:
        return findings
    server = data.get('server') if isinstance(data, dict) else None
    if not isinstance(server, dict):
        return findings
    url_val = str(server.get('url', '')).lower()
    if server.get('cleartext') is True or url_val.startswith('http://'):
        needle = 'cleartext' if 'cleartext' in raw else 'url'
        add_finding(
            findings,
            reported_path,
            'capacitor_cleartext_traffic',
            line=_line_of_substring(raw, needle),
        )
    allow_nav = server.get('allowNavigation')
    if isinstance(allow_nav, list) and any(
            '*' in str(item) for item in allow_nav):
        add_finding(
            findings,
            reported_path,
            'capacitor_wildcard_navigation',
            line=_line_of_substring(raw, 'allowNavigation'),
        )
    return findings


def _load_expo_config(cfg_path):
    """Return (raw_text, expo_dict) for an Expo JSON config, or (None, None)."""
    raw = _read_bounded_text(cfg_path)
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
    except Exception:
        return None, None
    if not isinstance(data, dict):
        return None, None
    name_low = cfg_path.name.lower()
    if name_low == 'app.json':
        expo = data.get('expo')
        return (raw, expo) if isinstance(expo, dict) else (None, None)
    if name_low == 'app.config.json' and isinstance(data.get('expo'), dict):
        return raw, data['expo']
    return raw, data


def _iter_secret_keys(obj, prefix=''):
    """Yield dotted key paths whose string values look like secrets."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            name = f'{prefix}{key}'
            if isinstance(val, (dict, list)):
                yield from _iter_secret_keys(val, f'{name}.')
            elif (isinstance(val, str)
                    and len(val) >= 8
                    and is_secret_key(str(key))):
                yield name
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_secret_keys(item, prefix)


def check_expo_config(cfg_path, reported_path):
    """Check Expo app config / manifest for extra secrets and OTA updates."""
    findings = []
    raw, data = _load_expo_config(cfg_path)
    if data is None:
        return findings
    secret_keys = sorted(set(_iter_secret_keys(data.get('extra'))))
    if secret_keys:
        add_finding(
            findings,
            reported_path,
            'expo_config_extra_secrets',
            dynamic=(', '.join(secret_keys[:10]),),
            line=_line_of_substring(raw, '"extra"'),
        )
    updates = data.get('updates')
    if not isinstance(updates, dict) or updates.get('enabled') is False:
        return findings
    url = str(updates.get('url', ''))
    if url.lower().startswith('http://'):
        add_finding(
            findings,
            reported_path,
            'expo_updates_cleartext',
            line=_line_of_substring(raw, '"url"'),
        )
    if url and not updates.get('codeSigningCertificate'):
        add_finding(
            findings,
            reported_path,
            'expo_updates_unsigned',
            line=_line_of_substring(raw, '"updates"'),
        )
    return findings


def scan_hybrid_configs(config_paths, validate_func):
    """Scan Cordova, Capacitor, and Expo config files."""
    findings = []
    for cfg_path in config_paths:
        try:
            if not validate_func(cfg_path):
                continue
        except Exception:
            logger.warning('Failed to validate config file: %s', cfg_path)
            continue
        reported = report_path(cfg_path)
        name_low = cfg_path.name.lower()
        if name_low == 'config.xml':
            findings.extend(check_cordova_config(cfg_path, reported))
        elif name_low == 'capacitor.config.json':
            findings.extend(check_capacitor_config(cfg_path, reported))
        elif name_low in EXPO_CONFIG_FILES:
            findings.extend(check_expo_config(cfg_path, reported))
    return mobsfscan_format(findings)
