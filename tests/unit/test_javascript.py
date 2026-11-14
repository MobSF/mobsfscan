# -*- coding: utf_8 -*-
"""Tests for JavaScript, TypeScript, and Hybrid source analysis."""
import json

from mobsfscan import __version__
from mobsfscan.formatters import (
    cli,
    gitlab_sast,
    json_fmt,
    sarif,
    sonarqube,
)
from mobsfscan.mobsfscan import MobSFScan


def test_react_native_ts_tsx_rules_and_no_false_missing_bp(
        tmp_path, monkeypatch):
    """Pure JS/TS repo triggers JS rules without missing native BP controls."""
    monkeypatch.chdir(tmp_path)
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'App.tsx').write_text(
        'import { WebView } from "react-native-webview";\n'
        'import AsyncStorage from '
        '"@react-native-async-storage/async-storage";\n'
        'import { MMKV } from "react-native-mmkv";\n'
        'import { Linking } from "react-native";\n'
        'const API_KEY = "sk_live_9876543210abcdef123456";\n'
        'const store = new MMKV();\n'
        'export function Screen({ deepLink, html, isPremium }) {\n'
        '  if (!isPremium) { return null; }\n'
        '  const keyName = "auth_token";\n'
        '  AsyncStorage.setItem(keyName, API_KEY);\n'
        '  Linking.openURL(deepLink);\n'
        '  frame.contentWindow.postMessage(API_KEY, "*");\n'
        '  if (__DEV__) { console.log("dev secret:", API_KEY); }\n'
        '  console.log("prod secret_token:", API_KEY);\n'
        '  const onMsg = (ev) => JSON.parse(ev.nativeEvent.data);\n'
        '  fetch("http://api.insecure.example.com/v1");\n'
        '  return (\n'
        '    <WebView\n'
        '      javaScriptEnabled={true}\n'
        '      allowUniversalAccessFromFileURLs={true}\n'
        '      mixedContentMode="always"\n'
        '      originWhitelist={["*"]}\n'
        '      dangerouslySetInnerHTML={{ __html: html }}\n'
        '    />\n'
        '  );\n'
        '}\n',
        encoding='utf-8',
    )

    # node_modules and vendor minified bundles must be ignored
    nm = tmp_path / 'node_modules' / 'pkg'
    nm.mkdir(parents=True)
    (nm / 'bad.js').write_text('eval(untrusted);\n', encoding='utf-8')
    (src / 'vendor.min.js').write_text('eval(minified);\n', encoding='utf-8')
    (src / 'jquery.js').write_text('eval(jq);\n', encoding='utf-8')

    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()
    findings = res['results']

    expected_rules = {
        'js_webview_javascript_enabled',
        'js_webview_file_access',
        'js_webview_mixed_content',
        'js_webview_origin_wildcard',
        'js_dom_xss_sink',
        'js_postmessage_wildcard_origin',
        'js_insecure_async_storage',
        'js_mmkv_without_encryption',
        'js_hardcoded_secret',
        'js_deeplink_open_url',
        'js_console_sensitive_log',
        'js_client_side_auth_gate',
        'js_webview_unverified_onmessage',
        'js_cleartext_http_traffic',
    }
    assert expected_rules.issubset(findings.keys())
    assert 'js_dynamic_code_execution' not in findings

    # Severities must be mobsfscan-normalized (ERROR / WARNING / INFO)
    assert findings['js_hardcoded_secret']['metadata']['severity'] == 'ERROR'
    assert findings['js_dom_xss_sink']['metadata']['severity'] == 'WARNING'
    assert findings['js_console_sensitive_log']['metadata']['severity'] == (
        'INFO')

    # __DEV__ console.log on line 13 excluded; only line 14 reported
    log_files = findings['js_console_sensitive_log']['files']
    assert len(log_files) == 1
    assert log_files[0]['file_path'] == 'src/App.tsx'
    assert log_files[0]['match_lines'][0] == 14

    # Pure JS/TS scan must not report missing Android/iOS best practices
    assert not any(
        rid.startswith(('android_', 'ios_')) for rid in findings
    )

    # Verify all formatters accept JS findings cleanly
    assert json_fmt.json_output(None, dict(res), __version__)
    assert sarif.sarif_output(None, dict(res), __version__, [str(tmp_path)])
    assert sonarqube.sonarqube_output(None, dict(res), __version__)
    assert gitlab_sast.gitlab_sast_output(None, dict(res), __version__)
    html_out = tmp_path / 'report.html'
    cli.cli_output(str(html_out), dict(res), __version__, 'unsafehtml')
    assert html_out.is_file()


def test_crypto_sqlite_tls_keychain_oauth_and_safe_negatives(tmp_path):
    """Test remaining JS/Expo/RN rules and verify safe code does not match."""
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'vuln.tsx').write_text(
        'cordova.plugin.http.setServerTrustMode("nocheck", a, b);\n'
        'db.executeSql(`SELECT * FROM users WHERE id=${id}`);\n'
        'webview.injectJavaScript(`setUser("${name}")`);\n'
        'const h = CryptoJS.MD5(password);\n'
        'const c = CryptoJS.DES.encrypt(data, "s3cr3tk3y");\n'
        'const w1 = <WebView source={{ uri: deepLinkUrl }} />;\n'
        'Keychain.setGenericPassword(u, p, '
        '{ accessible: Keychain.ACCESSIBLE.ALWAYS });\n'
        'Clipboard.setString(user.password);\n'
        'const w2 = <WebView webviewDebuggingEnabled={true} />;\n'
        'const w3 = <WebView injectedJavaScriptForMainFrameOnly={false} />;\n'
        'const w4 = <WebView onShouldStartLoadWithRequest={() => true} />;\n'
        'useAuthRequest({ responseType: ResponseType.Token, '
        'usePKCE: false }, d);\n'
        'const ok = await LocalAuthentication.authenticateAsync();\n'
        'const p = RNFS.ExternalStorageDirectoryPath + "/t.txt";\n'
        'const realm = new Realm({ schema: [Note] });\n'
        'const cfg = { key: "root", storage: AsyncStorage, '
        'whitelist: ["auth"] };\n'
        'Reactotron.configure({}).useReactNative().connect();\n'
        'const bio = { allowDeviceCredentials: true };\n'
        'setTimeout("refresh(" + id + ")", 100);\n',
        encoding='utf-8',
    )
    (src / 'safe.tsx').write_text(
        'db.executeSql("SELECT * FROM users WHERE id=?", [id]);\n'
        'webview.injectJavaScript("window.ready = true;");\n'
        'const s = crypto.createHash("sha256");\n'
        'const e = CryptoJS.AES.encrypt(data, keyFromKeychain);\n'
        'const w = <WebView source={{ uri: "https://example.com" }} />;\n'
        'Keychain.setGenericPassword(u, p, { accessible: '
        'Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY });\n'
        'Clipboard.setString(orderId);\n'
        'const wd = <WebView webviewDebuggingEnabled={__DEV__} />;\n'
        'useAuthRequest({ responseType: ResponseType.Code, '
        'usePKCE: true }, d);\n'
        'const p = RNFS.DocumentDirectoryPath + "/t.txt";\n'
        'const realm = new Realm({ schema: [Note], encryptionKey: key });\n'
        'const cfg = { key: "root", storage: createSecureStore(), '
        'whitelist: ["auth"] };\n'
        'setTimeout(() => refresh(id), 100);\n',
        encoding='utf-8',
    )

    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()
    findings = res['results']

    expected = {
        'js_tls_validation_disabled',
        'js_sqlite_injection',
        'js_webview_script_injection',
        'js_weak_crypto',
        'js_crypto_hardcoded_key',
        'js_webview_dynamic_uri',
        'js_keychain_weak_accessibility',
        'js_clipboard_sensitive_data',
        'js_webview_debugging_enabled',
        'js_webview_inject_all_frames',
        'js_webview_allow_all_navigation',
        'js_oauth_insecure_config',
        'js_biometric_without_crypto',
        'js_external_storage_path',
        'js_unencrypted_database',
        'js_persist_sensitive_state',
        'js_debug_tooling_in_release',
        'js_biometric_weak_fallback',
        'js_dynamic_code_execution',
    }
    assert expected.issubset(findings.keys())
    for rule_id in expected:
        matched_paths = [
            f['file_path'] for f in findings[rule_id].get('files', [])
        ]
        assert not any(p.endswith('safe.tsx') for p in matched_paths), rule_id


def test_embedded_html_and_vue_script_blocks(tmp_path):
    """Embedded <script> blocks in HTML and Vue SFCs preserve line numbers."""
    www = tmp_path / 'www'
    www.mkdir()
    (www / 'index.html').write_text(
        '<!doctype html>\n'
        '<html>\n'
        '<body>\n'
        '<script>\n'
        'document.getElementById("out").innerHTML = location.hash;\n'
        '</script>\n'
        '</body>\n'
        '</html>\n',
        encoding='utf-8',
    )
    (www / 'View.vue').write_text(
        '<template><div>Hello</div></template>\n'
        '<script lang="ts">\n'
        'eval(window.name);\n'
        '</script>\n',
        encoding='utf-8',
    )
    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()
    findings = res['results']
    xss_files = findings['js_dom_xss_sink']['files']
    assert xss_files[0]['file_path'].endswith('index.html')
    assert xss_files[0]['match_lines'] == (5, 5)

    eval_files = findings['js_dynamic_code_execution']['files']
    assert eval_files[0]['file_path'].endswith('View.vue')
    assert eval_files[0]['match_lines'] == (3, 3)


def test_hybrid_configs_cordova_capacitor_expo(tmp_path, monkeypatch):
    """Cordova, Capacitor, and Expo configs report insecure settings."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'config.xml').write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<widget id="com.example.hybrid">\n'
        '  <access origin="*" />\n'
        '  <allow-navigation href="*" />\n'
        '</widget>\n',
        encoding='utf-8',
    )
    (tmp_path / 'capacitor.config.json').write_text(
        json.dumps({
            'appId': 'com.example.hybrid',
            'server': {
                'cleartext': True,
                'allowNavigation': ['*.example.com'],
            },
        }, indent=2),
        encoding='utf-8',
    )
    (tmp_path / 'app.json').write_text(
        json.dumps({
            'expo': {
                'name': 'demo',
                'extra': {
                    'eas': {'projectId': 'abc'},
                    'stripeSecretKey': 'sk_test_51Habcdefghijkl',
                },
                'updates': {
                    'url': 'http://updates.example.com/manifest',
                },
            },
        }, indent=2),
        encoding='utf-8',
    )
    # Non-Cordova config.xml and non-Expo app.json in subdirs must not match
    other = tmp_path / 'backend'
    other.mkdir()
    (other / 'config.xml').write_text('<settings><x/></settings>\n')
    (other / 'app.json').write_text('{"name": "heroku-app"}\n')

    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()
    findings = res['results']
    expected = {
        'cordova_config_wildcard_access',
        'cordova_config_wildcard_navigation',
        'capacitor_cleartext_traffic',
        'capacitor_wildcard_navigation',
        'expo_config_extra_secrets',
        'expo_updates_cleartext',
        'expo_updates_unsigned',
    }
    assert expected == set(findings.keys())
    desc = findings['expo_config_extra_secrets']['metadata']['description']
    assert 'stripeSecretKey' in desc
    assert 'projectId' not in desc
    # Secret value itself must not leak into description
    assert 'sk_test_51Habcdefghijkl' not in desc
    assert findings['cordova_config_wildcard_access']['files'][0][
        'match_lines'] == (3, 3)


def test_hybrid_mixed_repo_and_scan_type_filtering(tmp_path):
    """Mixed RN + Android repo runs both in auto and filters on --type."""
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'index.js').write_text(
        'eval(dynamicPayload);\n',
        encoding='utf-8',
    )
    (tmp_path / 'capacitor.config.json').write_text(
        '{"server": {"cleartext": true}}\n',
        encoding='utf-8',
    )
    android_dir = tmp_path / 'android'
    android_dir.mkdir()
    (android_dir / 'BridgeModule.java').write_text(
        'import java.io.FileInputStream;\n'
        'public class BridgeModule {\n'
        '  @ReactMethod\n'
        '  public void readFile(String p) throws Exception {\n'
        '    new FileInputStream(p);\n'
        '  }\n'
        '}\n',
        encoding='utf-8',
    )

    auto_res = MobSFScan(
        [str(tmp_path)], True, scan_type='auto', mp='thread').scan()['results']
    assert 'js_dynamic_code_execution' in auto_res
    assert 'capacitor_cleartext_traffic' in auto_res
    assert 'android_rn_exposed_react_method' in auto_res

    js_only = MobSFScan(
        [str(tmp_path)], True, scan_type='javascript', mp='thread',
    ).scan()['results']
    assert 'js_dynamic_code_execution' in js_only
    assert 'capacitor_cleartext_traffic' in js_only
    assert 'android_rn_exposed_react_method' not in js_only
    assert not any(rid.startswith('android_') for rid in js_only)

    android_only = MobSFScan(
        [str(tmp_path)], True, scan_type='android', mp='thread',
    ).scan()['results']
    assert 'android_rn_exposed_react_method' in android_only
    assert 'js_dynamic_code_execution' not in android_only
    assert 'capacitor_cleartext_traffic' not in android_only


def test_mobsf_ignore_comments_in_jsx_js_and_xml(tmp_path):
    """Inline //, {/* */}, and <!-- --> mobsf-ignore comments suppress hits."""
    (tmp_path / 'Screen.tsx').write_text(
        'export function Screen({ html, other }) {\n'
        '  eval(other); // mobsf-ignore: js_dynamic_code_execution\n'
        '  return (\n'
        '    <div>\n'
        '      <p dangerouslySetInnerHTML={{ __html: html }} /> '
        '{/* mobsf-ignore: js_dom_xss_sink*/}\n'
        '      <span dangerouslySetInnerHTML={{ __html: other }} />\n'
        '    </div>\n'
        '  );\n'
        '}\n',
        encoding='utf-8',
    )
    (tmp_path / 'config.xml').write_text(
        '<widget id="x">\n'
        '  <access origin="*" /><!-- mobsf-ignore: '
        'cordova_config_wildcard_access-->\n'
        '</widget>\n',
        encoding='utf-8',
    )
    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()['results']
    assert 'js_dynamic_code_execution' not in res
    assert 'cordova_config_wildcard_access' not in res
    xss_files = res['js_dom_xss_sink']['files']
    assert len(xss_files) == 1
    assert xss_files[0]['match_lines'] == (6, 6)


def test_cordova_no_path_wildcards_repeated_elements_and_json_lines(tmp_path):
    """Track exact XML/JSON positions and detect http://*, https://* nav."""
    (tmp_path / 'config.xml').write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<widget id="com.example.app">\n'
        '  <access origin="https://api.example.com" /> '
        '<!-- mobsf-ignore: cordova_config_wildcard_access -->\n'
        '  <access origin="*" />\n'
        '  <allow-navigation href="https://trusted.example.com/*" />\n'
        '  <allow-navigation href="http://*" /> '
        '<!-- mobsf-ignore: cordova_config_wildcard_navigation -->\n'
        '  <allow-navigation href="https://*" />\n'
        '</widget>\n',
        encoding='utf-8',
    )
    (tmp_path / 'capacitor.config.json').write_text(
        '{\n'
        '  "plugins": {\n'
        '    "Other": {\n'
        '      "cleartext": false,\n'
        '      "url": "https://safe.example.com",\n'
        '      "allowNavigation": []\n'
        '    }\n'
        '  },\n'
        '  "server": {\n'
        '    "cleartext": false,\n'
        '    "url": "http://dev.example.com",\n'
        '    "allowNavigation": ["*.example.com"]\n'
        '  }\n'
        '}\n',
        encoding='utf-8',
    )
    (tmp_path / 'app.json').write_text(
        '{\n'
        '  "unrelated": {\n'
        '    "extra": {},\n'
        '    "updates": { "url": "https://safe.example.com" }\n'
        '  },\n'
        '  "expo": {\n'
        '    "extra": {\n'
        '      "apiSecret": "super_secret_val_123"\n'
        '    },\n'
        '    "updates": {\n'
        '      "url": "http://ota.example.com/manifest"\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding='utf-8',
    )
    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()['results']

    access_hits = res['cordova_config_wildcard_access']['files']
    assert len(access_hits) == 1
    assert access_hits[0]['match_lines'] == (4, 4)

    nav_hits = res['cordova_config_wildcard_navigation']['files']
    assert len(nav_hits) == 1
    assert nav_hits[0]['match_lines'] == (7, 7)
    assert nav_hits[0]['match_string'] == '<allow-navigation href="https://*" />'

    assert res['capacitor_cleartext_traffic']['files'][0][
        'match_lines'] == (11, 11)
    assert res['capacitor_wildcard_navigation']['files'][0][
        'match_lines'] == (12, 12)
    assert res['expo_config_extra_secrets']['files'][0][
        'match_lines'] == (7, 7)
    assert res['expo_updates_cleartext']['files'][0][
        'match_lines'] == (11, 11)
    assert res['expo_updates_unsigned']['files'][0][
        'match_lines'] == (10, 10)


def test_webview_shorthand_dom_xss_multiset_http_and_dev_else(tmp_path):
    """Regression coverage for JSX shorthand, sanitizer RHS, multiSet, HTTP."""
    (tmp_path / 'vuln.tsx').write_text(
        'const w1 = <WebView allowFileAccess />;\n'
        'const w2 = <WebView allowUniversalAccessFromFileURLs />;\n'
        'el.innerHTML = unsanitizedHtml;\n'
        'el.innerHTML = DOMPurify.sanitize(prefix) + untrustedHtml;\n'
        'AsyncStorage.multiSet([["theme", "dark"], ["auth_token", tok]]);\n'
        'fetch("http://localhost.attacker.example/api");\n'
        'fetch("http://www.w3.org.attacker.example/p");\n'
        'if (__DEV__) {\n'
        '  console.log(secret);\n'
        '} else {\n'
        '  console.log(token);\n'
        '}\n',
        encoding='utf-8',
    )
    (tmp_path / 'safe.tsx').write_text(
        'const w = <WebView allowFileAccess={false} />;\n'
        'el.innerHTML = DOMPurify.sanitize(untrustedHtml);\n'
        'el.innerHTML = sanitizeHtml(untrustedHtml);\n'
        'el.innerHTML = goog.html.SafeHtml.unwrapTrustedHTML(h);\n'
        'el.innerHTML = "<b>static</b>";\n'
        'AsyncStorage.setItem("theme", "secret_dark_mode");\n'
        'AsyncStorage.multiSet([["theme", "auth_token_value_only"]]);\n'
        'fetch("http://localhost:8080/api");\n'
        'const svgNs = "http://www.w3.org/2000/svg";\n',
        encoding='utf-8',
    )
    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()['results']

    for rule_id, expected_lines in (
        ('js_webview_file_access', [1, 2]),
        ('js_dom_xss_sink', [3, 4]),
        ('js_insecure_async_storage', [5]),
        ('js_cleartext_http_traffic', [6, 7]),
        ('js_console_sensitive_log', [11]),
    ):
        files = res[rule_id]['files']
        assert all(f['file_path'].endswith('vuln.tsx') for f in files), rule_id
        assert sorted(f['match_lines'][0] for f in files) == expected_lines


def test_webview_onmessage_handler_scope_and_origin_guards(tmp_path):
    """Flag unverified WebView handlers; skip origin-guarded or unrelated."""
    (tmp_path / 'handlers.tsx').write_text(
        'export function BadHandlers() {\n'
        '  const onMessage = (ev) => {\n'
        '    console.log(ev.nativeEvent.url);\n'
        '    handle(ev.nativeEvent.data);\n'
        '  };\n'
        '  return (\n'
        '    <WebView onMessage={(e) => run(e.nativeEvent.data)} />\n'
        '  );\n'
        '}\n'
        'export function GoodHandlers() {\n'
        '  const onMessage = (ev) => {\n'
        '    if (ev.nativeEvent.url !== "https://trusted.example.com") {\n'
        '      return;\n'
        '    }\n'
        '    handle(ev.nativeEvent.data);\n'
        '  };\n'
        '  const handleWebViewMessage = (ev) => {\n'
        '    if (new URL(ev.nativeEvent.url).origin === TRUSTED_ORIGIN) {\n'
        '      handle(ev.nativeEvent.data);\n'
        '    }\n'
        '  };\n'
        '  const onBridgeMessage = (ev) => {\n'
        '    const { url } = ev.nativeEvent;\n'
        '    if (!url.startsWith("https://trusted.example.com/")) return;\n'
        '    handle(ev.nativeEvent.data);\n'
        '  };\n'
        '  const onScroll = (ev) => track(ev.nativeEvent.data);\n'
        '  return (\n'
        '    <Camera onBarCodeRead={(e) => scan(e.nativeEvent.data)} />\n'
        '  );\n'
        '}\n',
        encoding='utf-8',
    )
    res = MobSFScan([str(tmp_path)], True, mp='thread').scan()['results']
    hits = res['js_webview_unverified_onmessage']['files']
    assert sorted(h['match_lines'][0] for h in hits) == [4, 7]
