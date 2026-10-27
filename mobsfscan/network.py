# -*- coding: utf_8 -*-
"""SSRF-safe outbound requests for the App Links assetlinks.json check.

Hosts come from the manifest being scanned, so every destination is
treated as attacker controlled.
"""
import ipaddress
import re
import socket
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter

from mobsfscan.logger import init_logger

logger = init_logger(__name__)

ASSETLINKS_PATH = '/.well-known/assetlinks.json'
ALLOWED_PORTS = (80, 443)
MAX_ASSETLINKS_URLS = 20
MAX_DNS_ADDRESSES = 8
MAX_RESPONSE_SIZE = 1024 * 1024
REQUEST_TIMEOUT = 5
TOTAL_TIMEOUT = 20

_DISALLOWED_IPV4_NETWORKS = tuple(ipaddress.IPv4Network(n) for n in (
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '224.0.0.0/4',
    '240.0.0.0/4',
))
# Python classifies these as global, but they are cloud-internal endpoints.
_DISALLOWED_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    '168.63.129.16',  # Azure WireServer / platform DNS
))
_IPV6_TRANSLATION_NETWORKS = (
    ipaddress.IPv6Network('64:ff9b::/96'),
    ipaddress.IPv6Network('64:ff9b:1::/48'),
)
_INTERNAL_HOST_SUFFIXES = (
    '.home.arpa',
    '.internal',
    '.lan',
    '.local',
    '.localdomain',
    '.localhost',
)
_HOSTNAME_RE = re.compile(r'[a-z0-9-]+(\.[a-z0-9-]+)+')


def is_disallowed_ip(ip_str):
    """Return True if an address must not be contacted."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped:
            return is_disallowed_ip(str(ip_obj.ipv4_mapped))
        # Transition addresses can tunnel a blocked IPv4 destination
        # through an otherwise public-looking IPv6 literal.
        if ip_obj.sixtofour and is_disallowed_ip(str(ip_obj.sixtofour)):
            return True
        if ip_obj.teredo and is_disallowed_ip(str(ip_obj.teredo[1])):
            return True
        for network in _IPV6_TRANSLATION_NETWORKS:
            if ip_obj in network:
                embedded = ipaddress.IPv4Address(ip_obj.packed[-4:])
                if is_disallowed_ip(str(embedded)):
                    return True
    if (not ip_obj.is_global
            or ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified):
        return True
    if ip_obj in _DISALLOWED_ADDRESSES:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in net for net in _DISALLOWED_IPV4_NETWORKS)
    return False


def _normalize_hostname(hostname):
    """Return an ASCII hostname or IP literal, or None if not allowed."""
    hostname = hostname.rstrip('.').lower()
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        hostname = hostname.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    # Numeric-only hosts like 2130706433 fail the regex's dot requirement.
    if (not _HOSTNAME_RE.fullmatch(hostname)
            or hostname.endswith(_INTERNAL_HOST_SUFFIXES)):
        return None
    return hostname


def resolve_public_ips(hostname, port):
    """Resolve hostname and return its addresses, or () if any is non-public.

    Callers must connect to a returned address instead of resolving the
    hostname again, otherwise DNS rebinding is possible.
    """
    try:
        ipaddress.ip_address(hostname)
        return () if is_disallowed_ip(hostname) else (hostname,)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return ()
    addresses = []
    for info in infos:
        address = info[4][0]
        if is_disallowed_ip(address):
            return ()
        if address not in addresses and len(addresses) < MAX_DNS_ADDRESSES:
            addresses.append(address)
    return tuple(addresses)


def assetlinks_url(scheme, host, port=None):
    """Build the assetlinks.json URL for a manifest host, or None if unsafe."""
    netloc = f'{host}:{port}' if port else host
    url = f'{scheme}://{netloc}{ASSETLINKS_PATH}'
    return url if validate_assetlinks_url(url) else None


def validate_assetlinks_url(url):
    """Return (scheme, hostname, port) for a safe assetlinks URL, else None."""
    if not isinstance(url, str) or len(url) > 2083:
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme not in ('http', 'https')
            or not parsed.hostname
            or '@' in parsed.netloc
            or parsed.path != ASSETLINKS_PATH
            or parsed.query
            or parsed.fragment
            or (port is not None and port not in ALLOWED_PORTS)):
        return None
    hostname = _normalize_hostname(parsed.hostname)
    if not hostname:
        return None
    return parsed.scheme, hostname, port


class _RequestDeadline:
    """Shut down a request's sockets once its time limit passes.

    Socket timeouts apply per operation, so a peer sending one byte at a
    time could otherwise hold the TLS handshake, headers or body open
    indefinitely and keep the worker thread blocked.
    """

    def __init__(self, seconds):
        self.expired = False
        self._lock = threading.Lock()
        # Duplicates, so shutdown still reaches the connection after TLS
        # wrapping detaches the original socket object, and so a closed
        # and reused descriptor is never touched.
        self._sockets = []
        self._timer = threading.Timer(max(0, seconds), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def register(self, sock):
        dup = sock.dup()
        with self._lock:
            if not self.expired:
                self._sockets.append(dup)
                return
        self._shutdown(dup)

    def _expire(self):
        with self._lock:
            self.expired = True
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            self._shutdown(sock)

    def cancel(self):
        self._timer.cancel()
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            sock.close()

    @staticmethod
    def _shutdown(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def _deadline_pool(pool_cls, deadline):
    """Return a pool class whose connections register with the deadline."""
    class Connection(pool_cls.ConnectionCls):
        def _new_conn(self):
            sock = super()._new_conn()
            deadline.register(sock)
            return sock

    return type(pool_cls.__name__, (pool_cls,), {'ConnectionCls': Connection})


class _PinnedAdapter(HTTPAdapter):
    """Verify TLS against the hostname while connecting to an IP literal."""

    def __init__(self, hostname, deadline, **kwargs):
        self.hostname = hostname
        self.deadline = deadline
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        kwargs['server_hostname'] = self.hostname
        kwargs['assert_hostname'] = self.hostname
        super().init_poolmanager(connections, maxsize, block=block, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            scheme: _deadline_pool(pool_cls, self.deadline)
            for scheme, pool_cls in
            self.poolmanager.pool_classes_by_scheme.items()}


def _get_pinned(scheme, hostname, port, address, deadline):
    """GET the assetlinks path from one validated address."""
    literal = f'[{address}]' if ':' in address else address
    netloc = f'{literal}:{port}' if port else literal
    host_header = f'{hostname}:{port}' if port else hostname
    url = urlunsplit((scheme, netloc, ASSETLINKS_PATH, '', ''))
    with requests.Session() as session:
        # A proxy would resolve the hostname itself and undo the pinning.
        session.trust_env = False
        session.mount(f'{scheme}://', _PinnedAdapter(hostname, deadline))
        with session.get(url,
                         headers={'Host': host_header},
                         allow_redirects=False,
                         stream=True,
                         timeout=REQUEST_TIMEOUT) as response:
            body = bytearray()
            for chunk in response.iter_content(8192):
                body += chunk
                if len(body) > MAX_RESPONSE_SIZE:
                    raise ValueError('assetlinks.json response too large')
            # A body without Content-Length just ends early on shutdown.
            if deadline.expired:
                raise TimeoutError('assetlinks.json request timed out')
            return response.status_code, bytes(body)


def fetch_assetlinks(url, deadline):
    """Fetch an assetlinks URL.

    Returns (status_code, body), or None if the URL or any address its
    host resolves to is not allowed. Network errors raise.
    """
    validated = validate_assetlinks_url(url)
    if not validated:
        return None
    scheme, hostname, port = validated
    addresses = resolve_public_ips(
        hostname, port or (443 if scheme == 'https' else 80))
    if not addresses:
        return None
    cutoff = _RequestDeadline(deadline - time.monotonic())
    last_error = None
    try:
        for address in addresses:
            if cutoff.expired:
                break
            try:
                return _get_pinned(scheme, hostname, port, address, cutoff)
            except (requests.RequestException, OSError) as exp:
                if cutoff.expired:
                    raise TimeoutError(
                        'assetlinks.json request timed out') from exp
                if not isinstance(exp, requests.ConnectionError):
                    raise
                last_error = exp
    finally:
        cutoff.cancel()
    raise last_error or TimeoutError('assetlinks.json request timed out')


def fetch_all_assetlinks(urls, timeout=TOTAL_TIMEOUT):
    """Fetch assetlinks URLs in parallel within a total time limit.

    Returns {url: result}, where result is (status_code, body), None for a
    disallowed host, or an exception for a failed or unfinished request.
    """
    urls = list(dict.fromkeys(urls))
    if len(urls) > MAX_ASSETLINKS_URLS:
        logger.warning(
            'Checking only the first %d of %d App Link hosts',
            MAX_ASSETLINKS_URLS, len(urls))
        urls = urls[:MAX_ASSETLINKS_URLS]
    deadline = time.monotonic() + timeout
    results = {}

    def worker(url):
        try:
            results[url] = fetch_assetlinks(url, deadline)
        except Exception as exp:
            results[url] = exp

    # Daemon threads so a stalled request can't hold up interpreter exit.
    threads = [
        threading.Thread(target=worker, args=(url,), daemon=True)
        for url in urls]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    return {
        url: results.get(url, TimeoutError('assetlinks.json timed out'))
        for url in urls}
