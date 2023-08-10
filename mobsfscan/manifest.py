# -*- coding: utf_8 -*-
"""Parse Android Manifest and NSC."""
from operator import itemgetter
from copy import deepcopy

from xmltodict import parse

from mobsfscan.logger import init_logger
from mobsfscan.manifest_metadata import metadata


logger = init_logger(__name__)
ANDROID_MIN_SDK = 27


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
        app = p.get('manifest').get('application')
        allow_backup = app.get('@android:allowBackup')
        clear_text = app.get('@android:usesCleartextTraffic')
        debuggable = app.get('@android:debuggable')
        test_only = app.get('@android:testOnly')
        if p.get('manifest').get('uses-sdk'):
            uses_sdk = p.get('manifest').get('uses-sdk')
            min_sdk = uses_sdk.get('@android:minSdkVersion')
        findings = android_manifest_checks(
            xml_path,
            min_sdk,
            allow_backup,
            clear_text,
            debuggable,
            test_only)
    elif p.get('network-security-config'):
        # Network Security Config
        nsc_finds = network_security_checks(xml_path, p)
        if nsc_finds:
            findings.extend(nsc_finds)
    return findings


def add_finding(findings, xml_file, rule_id):
    """Append Findings."""
    meta = deepcopy(metadata[rule_id])
    meta['id'] = rule_id
    meta['file'] = xml_file
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
        conv = int(min_sdk)
        if conv < ANDROID_MIN_SDK:
            add_finding(
                findings,
                xml_path,
                'android_manifest_insecure_minsdk')
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


def clear_text_traffic_permitted(xml_path, conf, nsc_finds, typ):
    if typ == 'base':
        r = 'android_manifest_base_config_cleartext'
    elif typ == 'domain':
        r = 'android_manifest_domain_config_cleartext'
    ctt = conf.get('@cleartextTrafficPermitted')
    if ctt and ctt == 'true':
        add_finding(nsc_finds, xml_path, r)


def trust_cert_and_cert_pinning_bypass(xml_path, cert, nsc_finds, typ):
    if typ == 'base':
        trule = 'android_manifest_base_config_trust_user_certs'
        prule = 'android_manifest_base_config_bypass_pinning'
    elif typ == 'domain':
        trule = 'android_manifest_domain_config_trust_user_certs'
        prule = 'android_manifest_domain_config_bypass_pinning'
    src = cert.get('@src')
    op = cert.get('@overridePins')
    # Trust user certs
    if src and src == 'user':
        add_finding(nsc_finds, xml_path, trule)
    # Bypass Pinning
    if src and op and src == 'user' and op == 'true':
        add_finding(nsc_finds, xml_path, prule)


def cert_instance_check(xml_path, config, nsc_finds, typ):
    certs = config.get('trust-anchors').get('certificates')
    if isinstance(certs, dict):
        # Single cert instance
        trust_cert_and_cert_pinning_bypass(
            xml_path, certs, nsc_finds, typ)
    elif isinstance(certs, list):
        for cert in certs:
            # Multiple certs instance
            trust_cert_and_cert_pinning_bypass(
                xml_path, cert, nsc_finds, typ)


def network_security_checks(xml_path, parsed_xml):
    """Android Network Security Config checks."""
    nsc_finds = []
    # Base Config
    if parsed_xml.get('network-security-config').get('base-config'):
        typ = 'base'
        base_conf = parsed_xml.get(
            'network-security-config').get('base-config')
        # Clear text traffic
        clear_text_traffic_permitted(xml_path, base_conf, nsc_finds, typ)
        if (base_conf.get('trust-anchors')
                and base_conf.get('trust-anchors').get('certificates')):
            # Trust user certs
            cert_instance_check(xml_path, base_conf, nsc_finds, typ)

    # Domain config
    if parsed_xml.get('network-security-config').get('domain-config'):
        typ = 'domain'
        domain_conf = parsed_xml.get(
            'network-security-config').get('domain-config')
        # Domain config clear text
        clear_text_traffic_permitted(xml_path, domain_conf, nsc_finds, typ)
        if domain_conf.get('domain-config'):
            # Nested domain config clear text
            clear_text_traffic_permitted(
                xml_path, domain_conf.get('domain-config'), nsc_finds, typ)
        if (domain_conf.get('trust-anchors')
                and domain_conf.get('trust-anchors').get('certificates')):
            # Trust user certs
            cert_instance_check(xml_path, domain_conf, nsc_finds, typ)
    return nsc_finds
