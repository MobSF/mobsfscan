# -*- coding: utf_8 -*-
"""Parse Android Manifest and NSC."""
from operator import itemgetter
from copy import deepcopy

from xmltodict import parse

import requests

from concurrent.futures import ThreadPoolExecutor

from mobsfscan.logger import init_logger
from mobsfscan.manifest_metadata import metadata
from mobsfscan.utils import (
    is_number,
    valid_host,
)

logger = init_logger(__name__)
ANDROID_8_0_LEVEL = 26
ANDROID_9_0_LEVEL = 28
ANDROID_10_0_LEVEL = 29
ANDROID_API_LEVEL_MAP = {
    '1': '1.0',
    '2': '1.1',
    '3': '1.5',
    '4': '1.6',
    '5': '2.0-2.1',
    '8': '2.2-2.2.3',
    '9': '2.3-2.3.2',
    '10': '2.3.3-2.3.7',
    '11': '3.0',
    '12': '3.1',
    '13': '3.2-3.2.6',
    '14': '4.0-4.0.2',
    '15': '4.0.3-4.0.4',
    '16': '4.1-4.1.2',
    '17': '4.2-4.2.2',
    '18': '4.3-4.3.1',
    '19': '4.4-4.4.4',
    '20': '4.4W-4.4W.2',
    '21': '5.0-5.0.2',
    '22': '5.1-5.1.1',
    '23': '6.0-6.0.1',
    '24': '7.0',
    '25': '7.1-7.1.2',
    '26': '8.0',
    '27': '8.1',
    '28': '9',
    '29': '10',
    '30': '11',
    '31': '12',
    '32': '12L',
    '33': '13',
    '34': '14',
    '35': '15',
    '36': '16',
    '37': '17',  # Guess work
    '38': '18',
    '39': '19',
    '40': '20',
}


def scan_manifest(xml_paths, validate_func):
    """Scan android manifest xml."""
    results = []
    p = None
    for xml_path in xml_paths:
        try:
            if not validate_func(xml_path):
                continue
            p = parse(xml_path.read_text())
        except Exception:
            logger.warning('Failed to parse XML: %s', xml_path)
        if p:
            findings = do_checks(
                xml_path.resolve().as_posix(), p)
            if findings:
                results.extend(findings)
    return mobsfscan_format(results)


def mobsfscan_format(results):
    """Convert results to mobsfscan format."""
    final = {}
    for res in results:
        find_details = {
            'file_path': res['file'],
            'match_position': (1, 1),
            'match_lines': (1, 1),
            'match_string': res['reference'],
        }
        if final.get(res['id']):
            # Append files
            final[res['id']]['files'].append(find_details)
        else:
            # First occurance
            meta = deepcopy(res['metadata'])
            meta['description'] = res['message']
            meta['severity'] = res['severity']
            final[res['id']] = {
                'files': [find_details],
                'metadata': meta,
            }
    # Preserve order
    for rl in final:
        to_sort = final[rl]['files']
        final[rl]['files'] = sorted(
            to_sort,
            key=itemgetter(
                'file_path', 'match_string', 'match_lines'))
    return final


def do_checks(xml_path, p):
    """Run checks on android manifest and network security config."""
    findings = []
    if p.get('manifest') and p.get('manifest').get('application'):
        # Android Manifest
        min_sdk = None
        target_sdk = None
        app = p.get('manifest').get('application')
        allow_backup = app.get('@android:allowBackup')
        clear_text = app.get('@android:usesCleartextTraffic')
        debuggable = app.get('@android:debuggable')
        test_only = app.get('@android:testOnly')
        if p.get('manifest').get('uses-sdk'):
            uses_sdk = p.get('manifest').get('uses-sdk')
            min_sdk = uses_sdk.get('@android:minSdkVersion')
            target_sdk = uses_sdk.get('@android:targetSdkVersion')
            if not target_sdk:
                target_sdk = min_sdk
        findings = android_manifest_checks(
            xml_path,
            min_sdk,
            allow_backup,
            clear_text,
            debuggable,
            test_only)
        al = AppLinksCheck(findings, xml_path)
        al.browsable_activity_check(app)
        th = TaskHijackingChecks(findings, xml_path, target_sdk)
        th.strandhogg_check(app)
    elif p.get('network-security-config'):
        # Network Security Config
        nsc = NetworkSecurityChecks(findings, xml_path)
        nsc.network_security_checks(p)
    return findings


def add_finding(findings, xml_file, rule_id, dynamic=None):
    """Append Findings."""
    meta = deepcopy(metadata[rule_id])
    meta['id'] = rule_id
    meta['file'] = xml_file
    if dynamic:
        meta['message'] = meta['message'].format(*dynamic)
    findings.append(meta)


def android_manifest_checks(xml_path,
                            min_sdk,
                            allow_backup,
                            clear_text,
                            debuggable,
                            test_only):
    """Android Manifest Checks."""
    findings = []
    try:
        if int(min_sdk) < ANDROID_8_0_LEVEL:
            add_finding(
                findings,
                xml_path,
                'android_manifest_insecure_minsdk_error',
                (ANDROID_API_LEVEL_MAP.get(min_sdk), min_sdk))
        elif int(min_sdk) < ANDROID_10_0_LEVEL:
            add_finding(
                findings,
                xml_path,
                'android_manifest_insecure_minsdk_warning',
                (ANDROID_API_LEVEL_MAP.get(min_sdk), min_sdk))
    except (ValueError, TypeError):
        pass
    if allow_backup and allow_backup == 'true':
        add_finding(
            findings,
            xml_path,
            'android_manifest_allow_backup')
    if not allow_backup:
        add_finding(
            findings,
            xml_path,
            'android_manifest_missing_explicit_allow_backup')
    if clear_text and clear_text == 'true':
        add_finding(
            findings,
            xml_path,
            'android_manifest_usescleartext')
    if debuggable and debuggable == 'true':
        add_finding(
            findings,
            xml_path,
            'android_manifest_debugging_enabled')
    if test_only and test_only == 'true':
        add_finding(
            findings,
            xml_path,
            'android_manifest_test_only')
    return findings


class NetworkSecurityChecks:

    def __init__(self, findings, xml_path):
        self.findings = findings
        self.xml_path = xml_path

    def clear_text_traffic_permitted(self, conf, typ):
        """Check for clear text traffic."""
        if typ == 'base':
            r = 'android_manifest_base_config_cleartext'
        elif typ == 'domain':
            r = 'android_manifest_domain_config_cleartext'
        else:
            return
        ctt = conf.get('@cleartextTrafficPermitted')
        if ctt and ctt == 'true':
            add_finding(self.findings, self.xml_path, r)

    def trust_cert_and_cert_pinning_bypass(self, cert, typ):
        """Check for trust user certs and cert pinning bypass."""
        if typ == 'base':
            trule = 'android_manifest_base_config_trust_user_certs'
            prule = 'android_manifest_base_config_bypass_pinning'
        elif typ == 'domain':
            trule = 'android_manifest_domain_config_trust_user_certs'
            prule = 'android_manifest_domain_config_bypass_pinning'
        else:
            return
        src = cert.get('@src')
        op = cert.get('@overridePins')
        # Trust user certs
        if src and src == 'user':
            add_finding(self.findings, self.xml_path, trule)
        # Bypass Pinning
        if src and op and src == 'user' and op == 'true':
            add_finding(self.findings, self.xml_path, prule)

    def cert_instance_check(self, config, typ):
        """Check for cert instance."""
        certs = config.get('trust-anchors').get('certificates')
        if isinstance(certs, dict):
            # Single cert instance
            self.trust_cert_and_cert_pinning_bypass(
                certs, typ)
        elif isinstance(certs, list):
            for cert in certs:
                # Multiple certs instance
                self.trust_cert_and_cert_pinning_bypass(
                    cert, typ)

    def network_security_checks(self, parsed_xml):
        """Android Network Security Config checks."""
        # Base Config
        if parsed_xml.get('network-security-config').get('base-config'):
            typ = 'base'
            base_conf = parsed_xml.get(
                'network-security-config').get('base-config')
            # Clear text traffic
            self.clear_text_traffic_permitted(base_conf, typ)
            if (base_conf.get('trust-anchors')
                    and base_conf.get('trust-anchors').get('certificates')):
                # Trust user certs
                self.cert_instance_check(base_conf, typ)

        # Domain config
        if parsed_xml.get('network-security-config').get('domain-config'):
            typ = 'domain'
            domain_conf = parsed_xml.get(
                'network-security-config').get('domain-config')
            # Domain config clear text
            self.clear_text_traffic_permitted(domain_conf, typ)
            if domain_conf.get('domain-config'):
                # Nested domain config clear text
                self.clear_text_traffic_permitted(
                    domain_conf.get('domain-config'), typ)
            if (domain_conf.get('trust-anchors')
                    and domain_conf.get('trust-anchors').get('certificates')):
                # Trust user certs
                self.cert_instance_check(domain_conf, typ)


class AppLinksCheck:

    def __init__(self, findings, xml_path):
        self.findings = findings
        self.xml_path = xml_path

    def check_in_intents(self, activity):
        """Check for browsable activities in Intents."""
        if not activity:
            return
        intents = activity.get('intent-filter')
        if isinstance(intents, dict):
            self.assetlinks_check(intents)
        elif isinstance(intents, list):
            for intent in intents:
                self.assetlinks_check(intent)

    def browsable_activity_check(self, app):
        """Check in Activity intents."""
        # Activities and Alias
        for item in ('activity', 'activity-alias'):
            activities = app.get(item)
            if isinstance(activities, dict):
                self.check_in_intents(activities)
            elif isinstance(activities, list):
                for act in activities:
                    self.check_in_intents(act)

    def check_url(self, w_url):
        """Check URL."""
        rcode = 0
        iden = 'sha256_cert_fingerprints'
        rule = 'android_manifest_well_known_assetlinks'
        status = True
        try:
            r = requests.get(
                w_url,
                allow_redirects=False,
                timeout=5)
            if not (str(r.status_code).startswith('2')
                    and iden in str(r.json())):
                status = False
                rcode = r.status_code
        except Exception:
            status = False
        if not status:
            add_finding(
                self.findings,
                self.xml_path,
                rule,
                (w_url, rcode))

    def assetlinks_check(self, intent):
        """Well known assetlink check."""
        well_known_path = '/.well-known/assetlinks.json'
        well_knowns = set()

        applink_data = intent.get('data')
        if isinstance(applink_data, dict):
            applink_data = [applink_data]
        elif not isinstance(applink_data, list):
            return
        for applink in applink_data:
            host = applink.get('@android:host')
            port = applink.get('@android:port')
            scheme = applink.get('@android:scheme')
            # Collect possible well-known paths
            if (scheme
                    and scheme in ('http', 'https')
                    and host
                    and host != '*'):
                host = host.replace('*.', '').replace('#', '')
                if not valid_host(host):
                    continue
                if port and is_number(port):
                    c_url = f'{scheme}://{host}:{port}{well_known_path}'
                else:
                    c_url = f'{scheme}://{host}{well_known_path}'
                well_knowns.add(c_url)
        with ThreadPoolExecutor() as executor:
            futures = []
            for w_url in well_knowns:
                futures.append(
                    executor.submit(self.check_url, w_url))
            for future in futures:
                future.result()


class TaskHijackingChecks:

    def __init__(self, findings, xml_path, target_sdk):
        self.findings = findings
        self.xml_path = xml_path
        self.target_sdk = target_sdk

    def strandhogg_check(self, app):
        """Task Hijacking check."""
        # Activities and Alias
        for item in ('activity', 'activity-alias'):
            activities = app.get(item)
            if isinstance(activities, dict):
                self.task_hijacking_checks(activities)
            elif isinstance(activities, list):
                for act in activities:
                    self.task_hijacking_checks(act)

    def task_hijacking_checks(self, activity):
        """Android Task Hijacking Checks."""
        # StrandHogg 1.0
        try:
            target_sdk = int(self.target_sdk)
        except Exception:
            target_sdk = ANDROID_8_0_LEVEL
        launch_mode = activity.get('@android:launchMode')
        if (target_sdk < ANDROID_9_0_LEVEL
                and launch_mode == 'singleTask'):
            add_finding(
                self.findings,
                self.xml_path,
                'android_task_hijacking1',
                (target_sdk,))
        # StrandHogg 2.0
        exported_act = activity.get('@android:exported')
        if not exported_act:
            exported_act = 'false'
        task_affinity = activity.get('@android:taskAffinity')
        if not task_affinity:
            task_affinity = ''
        if (target_sdk < ANDROID_10_0_LEVEL
                and exported_act == 'true'
                and (launch_mode != 'singleInstance' or task_affinity != '')):
            add_finding(
                self.findings,
                self.xml_path,
                'android_task_hijacking2',
                (target_sdk,))
