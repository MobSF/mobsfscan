# -*- coding: utf_8 -*-
"""Cordova, Capacitor, and Expo hybrid configuration checks."""
import json
import re
from xml.parsers import expat

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
_EXPO_ROOT_MARKER_KEYS = {
    'slug',
    'sdkVersion',
    'runtimeVersion',
    'platforms',
    'orientation',
    'ios',
    'android',
    'scheme',
    'newArchEnabled',
    'jsEngine',
    'updates',
    'extra',
}
_NON_EXPO_APP_JSON_KEYS = {
    'addons',
    'buildpacks',
    'formation',
    'stack',
}
_WILDCARD_NAV_RE = re.compile(
    r'^(?:\*|(?:\*|https?)://\*(?::(?:\*|\d+))?(?:/.*)?)$',
    re.IGNORECASE,
)
_JSON_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,"]+',
)
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


def _is_wildcard_nav_href(href):
    """Return True if a Cordova allow-navigation href allows arbitrary hosts."""
    return bool(_WILDCARD_NAV_RE.match(href))


def _read_bounded_text(cfg_path):
    """Read UTF-8 text if file size is within MAX_CONFIG_BYTES."""
    try:
        if cfg_path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return cfg_path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        logger.warning('Failed to read config file: %s', cfg_path)
        return None


def _forbid_entities(*_args):
    """Reject XML entity declarations."""
    raise ValueError('XML entity declarations are not supported')


def _parse_cordova_elements(raw):
    """Return (tag, norm_attrs, line) tuples inside a Cordova <widget> root."""
    parser = expat.ParserCreate()
    parser.EntityDeclHandler = _forbid_entities
    elements = []
    state = {'depth': 0, 'is_widget': False}

    def start_element(name, attrs):
        local_tag = name.split(':')[-1].lower()
        if state['depth'] == 0:
            state['is_widget'] = local_tag == 'widget'
        state['depth'] += 1
        if not state['is_widget']:
            return
        norm_attrs = {
            k.split(':')[-1].lower(): str(v)
            for k, v in attrs.items()
        }
        elements.append((local_tag, norm_attrs, parser.CurrentLineNumber))

    def end_element(_name):
        state['depth'] -= 1

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.Parse(raw, True)
    return elements


def _parse_json_value(tokens, pos, path, lines):
    """Advance past one RFC-8259 JSON value, recording key line numbers."""
    tok, line = tokens[pos]
    if tok == '{':
        return _parse_json_object(tokens, pos + 1, path, lines)
    if tok == '[':
        return _parse_json_array(tokens, pos + 1, path, lines)
    lines.setdefault(path, line)
    return pos + 1


def _parse_json_object(tokens, pos, path, lines):
    """Advance past a JSON object body and record each property's line."""
    if tokens[pos][0] == '}':
        return pos + 1
    while pos < len(tokens):
        key_tok, key_line = tokens[pos]
        key = json.loads(key_tok)
        key_path = path + (key,)
        lines[key_path] = key_line
        pos = _parse_json_value(tokens, pos + 2, key_path, lines)
        if tokens[pos][0] == ',':
            pos += 1
            continue
        return pos + 1
    return pos


def _parse_json_array(tokens, pos, path, lines):
    """Advance past a JSON array body and index element positions."""
    if tokens[pos][0] == ']':
        return pos + 1
    idx = 0
    while pos < len(tokens):
        elem_path = path + (idx,)
        lines[elem_path] = tokens[pos][1]
        pos = _parse_json_value(tokens, pos, elem_path, lines)
        idx += 1
        if tokens[pos][0] == ',':
            pos += 1
            continue
        return pos + 1
    return pos


def _load_json_with_lines(cfg_path):
    """Parse JSON file and return (data, {key_path_tuple: line_no})."""
    raw = _read_bounded_text(cfg_path)
    if not raw:
        return None, {}
    try:
        data = json.loads(raw)
    except Exception:
        return None, {}
    lines = {}
    try:
        tokens = []
        line_no = 1
        last_idx = 0
        for match in _JSON_TOKEN_RE.finditer(raw):
            start = match.start()
            line_no += raw.count('\n', last_idx, start)
            last_idx = start
            tokens.append((match.group(0), line_no))
        if tokens:
            _parse_json_value(tokens, 0, (), lines)
    except Exception:
        lines = {}
    return data, lines


def check_cordova_config(cfg_path, reported_path):
    """Check Cordova / PhoneGap config.xml for wildcard access/navigation."""
    findings = []
    raw = _read_bounded_text(cfg_path)
    if not raw:
        return findings
    try:
        elements = _parse_cordova_elements(raw)
    except Exception:
        return findings
    for tag, attrs, line in elements:
        if tag == 'access' and attrs.get('origin', '').strip() == '*':
            add_finding(
                findings,
                reported_path,
                'cordova_config_wildcard_access',
                line=line,
            )
        elif tag == 'allow-navigation':
            href = attrs.get('href', '').strip()
            if _is_wildcard_nav_href(href):
                add_finding(
                    findings,
                    reported_path,
                    'cordova_config_wildcard_navigation',
                    line=line,
                    reference=f'<allow-navigation href="{href}" />',
                )
    return findings


def check_capacitor_config(cfg_path, reported_path):
    """Check Capacitor capacitor.config.json for cleartext or wildcard nav."""
    findings = []
    data, lines = _load_json_with_lines(cfg_path)
    server = data.get('server') if isinstance(data, dict) else None
    if not isinstance(server, dict):
        return findings
    cleartext_on = server.get('cleartext') is True
    url_http = str(server.get('url', '')).lower().startswith('http://')
    if cleartext_on or url_http:
        prop_path = ('server', 'cleartext') if cleartext_on else (
            'server', 'url')
        add_finding(
            findings,
            reported_path,
            'capacitor_cleartext_traffic',
            line=lines.get(prop_path, lines.get(('server',), 1)),
        )
    allow_nav = server.get('allowNavigation')
    if isinstance(allow_nav, list) and any(
            '*' in str(item) for item in allow_nav):
        add_finding(
            findings,
            reported_path,
            'capacitor_wildcard_navigation',
            line=lines.get(
                ('server', 'allowNavigation'),
                lines.get(('server',), 1),
            ),
        )
    return findings


def _is_root_expo_app_json(data):
    """Return True if an unwrapped app.json looks like an Expo app config."""
    keys = set(data.keys())
    if keys & _NON_EXPO_APP_JSON_KEYS:
        return False
    if not (keys & _EXPO_ROOT_MARKER_KEYS):
        return False
    extra = data.get('extra')
    updates = data.get('updates')
    has_expo_markers = bool(
        keys & (_EXPO_ROOT_MARKER_KEYS - {'extra', 'updates'}),
    )
    has_expo_extra = isinstance(extra, dict) and 'eas' in extra
    has_expo_updates = isinstance(updates, dict) and (
        'url' in updates
        or 'codeSigningCertificate' in updates
        or 'fallbackToCacheTimeout' in updates
    )
    return has_expo_markers or has_expo_extra or has_expo_updates


def _load_expo_config(cfg_path):
    """Return (expo_dict, lines_map, root_prefix) for an Expo JSON config."""
    data, lines = _load_json_with_lines(cfg_path)
    if not isinstance(data, dict):
        return None, {}, ()
    name_low = cfg_path.name.lower()
    if isinstance(data.get('expo'), dict):
        return data['expo'], lines, ('expo',)
    if name_low == 'app.json':
        if _is_root_expo_app_json(data):
            return data, lines, ()
        return None, {}, ()
    return data, lines, ()


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
    data, lines, root_prefix = _load_expo_config(cfg_path)
    if data is None:
        return findings
    secret_keys = sorted(set(_iter_secret_keys(data.get('extra'))))
    if secret_keys:
        keys_ref = 'extra: ' + ', '.join(secret_keys[:10])
        add_finding(
            findings,
            reported_path,
            'expo_config_extra_secrets',
            line=lines.get(root_prefix + ('extra',), 1),
            reference=keys_ref,
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
            line=lines.get(
                root_prefix + ('updates', 'url'),
                lines.get(root_prefix + ('updates',), 1),
            ),
        )
    if url and not updates.get('codeSigningCertificate'):
        add_finding(
            findings,
            reported_path,
            'expo_updates_unsigned',
            line=lines.get(root_prefix + ('updates',), 1),
        )
    return findings


def scan_hybrid_configs(config_paths, validate_func):
    """Scan Cordova, Capacitor, and Expo config files."""
    findings = []
    for cfg_path in config_paths:
        try:
            if not validate_func(cfg_path):
                continue
            reported = report_path(cfg_path)
            name_low = cfg_path.name.lower()
            if name_low == 'config.xml':
                findings.extend(check_cordova_config(cfg_path, reported))
            elif name_low == 'capacitor.config.json':
                findings.extend(check_capacitor_config(cfg_path, reported))
            elif name_low in EXPO_CONFIG_FILES:
                findings.extend(check_expo_config(cfg_path, reported))
        except Exception:
            logger.warning('Failed to scan config file: %s', cfg_path)
            continue
    return mobsfscan_format(findings)
