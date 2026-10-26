"""Tests for the new detection rules.

Path traversal, ZipSlip, intent redirection, mutable PendingIntents,
deep link to WebView, OAuth custom schemes, local sockets,
external-storage databases, secret material, SSZipArchive and the
WKWebView script message handler.
"""
from .setup_test import (
    get_paths,
    scanner,
)

ANDROID_JAVA_NEW_RULES = {
    'android_provider_path_traversal',
    'android_zip_slip',
    'android_intent_redirection',
    'android_pending_intent_not_immutable',
    'android_deeplink_to_webview',
    'android_local_server_socket',
    'android_db_on_external_storage',
    'android_oauth_custom_scheme_redirect',
    'google_api_key',
    'private_key_pem',
}

ANDROID_KOTLIN_NEW_RULES = {
    'android_kotlin_provider_path_traversal',
    'android_kotlin_zip_slip',
    'android_kotlin_intent_redirection',
    'android_kotlin_pending_intent_not_immutable',
    'android_kotlin_deeplink_to_webview',
    'android_kotlin_local_server_socket',
    'android_kotlin_db_on_external_storage',
    'android_kotlin_oauth_custom_scheme_redirect',
}

IOS_NEW_RULES = {
    'ios_oauth_callback_custom_scheme',
    'ios_wkwebview_script_message_handler',
    'ios_ssziparchive_unzip',
    'ios_sszip_unzip',
}


def test_new_android_java_rules():
    paths = get_paths()
    res = scanner([paths['android_new_rules']])
    assert ANDROID_JAVA_NEW_RULES.issubset(res['results'])


def test_new_android_kotlin_rules():
    paths = get_paths()
    res = scanner([paths['android_new_rules']])
    assert ANDROID_KOTLIN_NEW_RULES.issubset(res['results'])


def test_new_ios_rules():
    paths = get_paths()
    res = scanner([paths['swift'], paths['objc']])
    assert IOS_NEW_RULES.issubset(res['results'])
