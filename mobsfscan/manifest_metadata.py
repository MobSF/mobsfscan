
# -*- coding: utf_8 -*-
"""Android Manifest and NSC metadata."""
metadata = {
    'android_manifest_allow_backup': {
        'message': (
            'This flag allows anyone to backup your application'
            ' data via adb. It allows users who have enabled '
            'USB debugging to copy application data off of the device.'),
        'severity': 'WARNING',
        'reference': 'android:allowBackup=true',
        'metadata': {
            'cwe': 'cwe-921',
            'owasp-mobile': 'm1',
            'masvs': 'storage-8',
            'reference': (
                'https://github.com/MobSF/owasp-mstg/blob/'
                'master/Document/0x05d-Testing-Data-Storage.md'
                '#static-analysis-7'),
        },
    },
    'android_manifest_missing_explicit_allow_backup': {
        'message': (
            'The flag [android:allowBackup] should be set to false.'
            ' By default it is set to true and allows anyone to '
            'backup your application data via adb. It allows users'
            ' who have enabled USB debugging to copy application'
            ' data off of the device.'),
        'severity': 'WARNING',
        'reference': 'android:allowBackup not set',
        'metadata': {
            'cwe': 'cwe-921',
            'owasp-mobile': 'm1',
            'masvs': 'storage-8',
            'reference': (
                'https://github.com/MobSF/owasp-mstg/blob/'
                'master/Document/0x05d-Testing-Data-Storage.md'
                '#static-analysis-7'),
        },
    },
    'android_manifest_usescleartext': {
        'message': (
            'The app intends to use cleartext network traffic, '
            'such as cleartext HTTP, FTP stacks, DownloadManager,'
            ' and MediaPlayer. The default value for apps that '
            'target API level 27 or lower is "true". Apps that '
            'target API level 28 or higher default to "false". '
            'The key reason for avoiding cleartext traffic is '
            'the lack of confidentiality, authenticity, and '
            'protections against tampering; a network attacker '
            'can eavesdrop on transmitted data and also modify '
            'it without being detected.'),
        'severity': 'ERROR',
        'reference': 'android:usesCleartextTraffic=true',
        'metadata': {
            'cwe': 'cwe-319',
            'owasp-mobile': 'm3',
            'masvs': 'network-1',
            'reference': (
                'https://github.com/MobSF/owasp-mstg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md#testing-for-cleartext-traffic'),
        },
    },
    'android_manifest_debugging_enabled': {
        'message': (
            'Debugging was enabled on the app which makes it '
            'easier for reverse engineers to hook a debugger '
            'to it. This allows dumping a stack trace and '
            'accessing debugging helper classes.'),
        'severity': 'ERROR',
        'reference': 'android:debuggable=true',
        'metadata': {
            'cwe': 'cwe-489',
            'owasp-mobile': 'm10',
            'masvs': 'code-2',
            'reference': (
                'https://github.com/MobSF/owasp-mstg/blob/'
                'master/Document/0x05i-Testing-Code-Quality-'
                'and-Build-Settings.md#testing-whether-the'
                '-app-is-debuggable-mstg-code-2'),
        },
    },
    'android_manifest_test_only': {
        'message': (
            'App may expose functionality or data outside of '
            'itself that would cause a security hole.'),
        'severity': 'WARNING',
        'reference': 'android:testOnly=true',
        'metadata': {
            'cwe': 'cwe-489',
            'owasp-mobile': 'm10',
            'masvs': 'code-2',
            'reference': (
                'https://github.com/MobSF/owasp-mstg/blob/'
                'master/Document/0x05i-Testing-Code-Quality'
                '-and-Build-Settings.md'),
        },
    },
    'android_manifest_insecure_minsdk_warning': {
        'message': (
            'App supports Android version {}, API Level: {}. '
            'This application can be installed on an older '
            'version of android that has multiple unfixed '
            'vulnerabilities. Support an Android version '
            '>= 10, API 29 to receive reasonable security '
            'updates.'),
        'severity': 'WARNING',
        'reference': 'android:minSdkVersion<29',
        'metadata': {
            'cwe': 'cwe-1104',
            'owasp-mobile': 'm1',
            'masvs': 'platform-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05a-Platform-Overview.md'),
        },
    },
    'android_manifest_insecure_minsdk_error': {
        'message': (
            'App supports Android version {}, API Level: {}. '
            'This application can be installed on an older '
            'version of android that has multiple unfixed '
            'vulnerabilities. These devices won\'t receive '
            'reasonable security updates from Google. '
            'Support an Android version >= 10, API 29 to '
            'receive reasonable security updates.'),
        'severity': 'ERROR',
        'reference': 'android:minSdkVersion<29',
        'metadata': {
            'cwe': 'cwe-1104',
            'owasp-mobile': 'm1',
            'masvs': 'platform-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05a-Platform-Overview.md'),
        },
    },
    'android_manifest_well_known_assetlinks': {
        'message': (
            'App Link asset verification URL ({}) not found or '
            'configured incorrectly. (Status code: {}). '
            'App Links allow users to redirect from a '
            'web URL/email to the mobile app. If this file '
            'is missing or incorrectly configured for the '
            'App Link host/domain, a malicious app can '
            'hijack such URLs. This may '
            'lead to phishing attacks, leak sensitive data '
            'in the URI, such as PII, OAuth tokens, magic '
            'link/password reset tokens and more. You must '
            'verify the App Link domain by hosting the '
            'assetlinks.json file and enabling verification '
            'via [android:autoVerify="true"] in the '
            'Activity intent-filter.'),
        'severity': 'ERROR',
        'reference': 'assetlinks.json file not found for android:host',
        'metadata': {
            'cwe': 'cwe-284',
            'owasp-mobile': 'm1',
            'masvs': 'platform-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05a-Platform-Overview.md'),
        },
    },
    'android_task_hijacking1': {
        'message': (
            'The Activity should not be having the launch '
            'mode attribute set to "singleTask". It is then '
            'possible for other applications to place a '
            'malicious activity on top of the activity stack '
            'resulting in Task Hijacking/StrandHogg 1.0 '
            'vulnerability. This makes the application an easy '
            'target for phishing attacks. The vulnerability can '
            'be remediated by setting the launch mode attribute '
            'to "singleInstance" or by setting an empty '
            'taskAffinity (taskAffinity="") attribute. You can '
            'also update the target SDK version ({}) of the app to '
            '28 or higher to fix this issue at platform level.'),
        'severity': 'ERROR',
        'reference': 'launchMode=singleTask and targetSdk<28',
        'metadata': {
            'cwe': 'cwe-1021',
            'owasp-mobile': 'm1',
            'masvs': 'platform-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05a-Platform-Overview.md'),
        },
    },
    'android_task_hijacking2': {
        'message': (
            'Activity is found to be vulnerable to '
            'StrandHogg 2.0 task hijacking vulnerability. '
            'When vulnerable, it is possible for other '
            'applications to place a malicious activity '
            'on top of the activity stack of the vulnerable '
            'application. This makes the application an easy '
            'target for phishing attacks. The vulnerability can '
            'be remediated by setting the launch mode attribute '
            'to "singleInstance" and by setting an empty '
            'taskAffinity (taskAffinity=""). You can also update '
            'the target SDK version ({}) of the app to 29 or higher '
            'to fix this issue at platform level.'),
        'severity': 'ERROR',
        'reference': ('Activity exported, targetSdk<29 and '
                      'launchMode != singleInstance or '
                      'taskAffinity is not empty'),
        'metadata': {
            'cwe': 'cwe-1021',
            'owasp-mobile': 'm1',
            'masvs': 'platform-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05a-Platform-Overview.md'),
        },
    },
    # Network Security Config
    # Base config
    'android_manifest_base_config_cleartext': {
        'message': (
            'App allows clear text HTTP communication. '
            'Disable this for production endpoints.'),
        'severity': 'ERROR',
        'reference': 'base_config: cleartextTrafficPermitted=true',
        'metadata': {
            'cwe': 'cwe-319',
            'owasp-mobile': 'm3',
            'masvs': 'network-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md#testing-for-cleartext-traffic'),
        },
    },
    'android_manifest_base_config_trust_user_certs': {
        'message': (
            'The network security base configuration trusts any '
            'certificate installed by the user. This can help '
            'increase the risk of MITM attacks.'),
        'severity': 'ERROR',
        'reference': 'base_config: certificate src=user',
        'metadata': {
            'cwe': 'cwe-295',
            'owasp-mobile': 'm3',
            'masvs': 'network-3',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md#analyzing-custom-trust-anchors'),
        },
    },
    'android_manifest_base_config_bypass_pinning': {
        'message': (
            'The network security base configuration '
            'disables certificate pinning'),
        'severity': 'WARNING',
        'reference': 'base_config: overridePins=true',
        'metadata': {
            'cwe': 'cwe-295',
            'owasp-mobile': 'm3',
            'masvs': 'network-3',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md'),
        },
    },
    # Domain config
    'android_manifest_domain_config_cleartext': {
        'message': (
            'A domain or multiple domains are explicitly '
            'configured to allow plain text traffic. '
            'Ensure that it is not a production endpoint(s).'),
        'severity': 'INFO',
        'reference': 'domain_config: cleartextTrafficPermitted=true',
        'metadata': {
            'cwe': 'cwe-319',
            'owasp-mobile': 'm3',
            'masvs': 'network-1',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md#testing-for-cleartext-traffic'),
        },
    },
    'android_manifest_domain_config_trust_user_certs': {
        'message': (
            'The network security configuration for certain '
            'endpoints trusts any certificate installed by '
            'the user. This can help increase the risk of '
            'MITM attacks. Ensure that these endpoints are '
            'not used in production environment.'),
        'severity': 'WARNING',
        'reference': 'domain_config: certificate src=user',
        'metadata': {
            'cwe': 'cwe-295',
            'owasp-mobile': 'm3',
            'masvs': 'network-3',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md#analyzing-custom-trust-anchors'),
        },
    },
    'android_manifest_domain_config_bypass_pinning': {
        'message': (
            'The network security configuration for certain '
            'endpoints disables certificate pinning'),
        'severity': 'WARNING',
        'reference': 'domain_config: overridePins=true',
        'metadata': {
            'cwe': 'cwe-295',
            'owasp-mobile': 'm3',
            'masvs': 'network-3',
            'reference': (
                'https://github.com/OWASP/owasp-mastg/blob/'
                'master/Document/0x05g-Testing-Network-'
                'Communication.md'),
        },
    },
}
