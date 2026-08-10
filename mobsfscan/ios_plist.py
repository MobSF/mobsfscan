# -*- coding: utf_8 -*-
"""Analyze iOS App Transport Security settings in Info.plist."""
from plistlib import load

from mobsfscan.logger import init_logger
from mobsfscan.manifest import add_finding, mobsfscan_format
from mobsfscan.utils import report_path


logger = init_logger(__name__)
_WEAK_TLS = {'TLSv1.0', 'TLSv1.1'}
_TLS_12 = 'TLSv1.2'


def _enabled(value):
    """Return whether a plist boolean-like value is enabled."""
    return value is True or str(value).upper() in {'TRUE', 'YES', '1'}


def _disabled(value):
    """Return whether an explicitly configured value is disabled."""
    return value is False or str(value).upper() in {'FALSE', 'NO', '0'}


def scan_plists(plist_paths, validate_func):
    """Scan Info.plist files for App Transport Security exceptions."""
    findings = []
    for plist_path in plist_paths:
        try:
            if not validate_func(plist_path):
                continue
            with plist_path.open('rb') as plist_file:
                plist = load(plist_file)
        except Exception:
            logger.warning('Failed to parse plist: %s', plist_path)
            continue
        findings.extend(
            check_transport_security(
                report_path(plist_path),
                plist,
            ),
        )
    return mobsfscan_format(findings)


def check_transport_security(plist_path, plist):
    """Return findings for insecure ATS settings in one plist."""
    findings = []
    ats = plist.get('NSAppTransportSecurity')
    if not isinstance(ats, dict):
        return findings

    global_rules = {
        'NSAllowsArbitraryLoads': 'ios_ats_arbitrary_loads',
        'NSAllowsArbitraryLoadsForMedia': (
            'ios_ats_arbitrary_loads_for_media'
        ),
        'NSAllowsArbitraryLoadsInWebContent': (
            'ios_ats_arbitrary_loads_in_web_content'
        ),
        'NSAllowsLocalNetworking': 'ios_ats_local_networking',
    }
    for key, rule_id in global_rules.items():
        if _enabled(ats.get(key)):
            add_finding(findings, plist_path, rule_id)

    domains = ats.get('NSExceptionDomains') or {}
    if not isinstance(domains, dict):
        return findings
    for domain, config in domains.items():
        if not isinstance(config, dict):
            continue
        _check_exception_domain(findings, plist_path, str(domain), config)
    return findings


def _check_exception_domain(findings, plist_path, domain, config):
    """Check one NSExceptionDomains entry."""
    insecure_http_keys = (
        'NSExceptionAllowsInsecureHTTPLoads',
        'NSTemporaryExceptionAllowsInsecureHTTPLoads',
        'NSThirdPartyExceptionAllowsInsecureHTTPLoads',
    )
    if (
        domain not in {'localhost', '127.0.0.1'}
        and any(_enabled(config.get(key)) for key in insecure_http_keys)
    ):
        add_finding(
            findings,
            plist_path,
            'ios_ats_insecure_http_loads',
            (domain,),
        )

    minimum_tls = (
        config.get('NSExceptionMinimumTLSVersion')
        or config.get('NSTemporaryExceptionMinimumTLSVersion')
    )
    if minimum_tls in _WEAK_TLS:
        add_finding(
            findings,
            plist_path,
            'ios_ats_weak_tls',
            (minimum_tls, domain),
        )
    elif minimum_tls == _TLS_12:
        add_finding(
            findings,
            plist_path,
            'ios_ats_tls12',
            (domain,),
        )

    forward_secrecy_keys = (
        'NSExceptionRequiresForwardSecrecy',
        'NSTemporaryExceptionRequiresForwardSecrecy',
        'NSThirdPartyExceptionRequiresForwardSecrecy',
    )
    if any(
        key in config and _disabled(config[key])
        for key in forward_secrecy_keys
    ):
        add_finding(
            findings,
            plist_path,
            'ios_ats_forward_secrecy_disabled',
            (domain,),
        )

    if (
        'NSRequiresCertificateTransparency' in config
        and _disabled(config['NSRequiresCertificateTransparency'])
    ):
        add_finding(
            findings,
            plist_path,
            'ios_ats_certificate_transparency_disabled',
            (domain,),
        )
