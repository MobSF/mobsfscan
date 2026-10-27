"""App Links assetlinks.json check must not reach internal hosts."""
import socket
import threading
import time

import pytest

import requests

from xmltodict import parse

from mobsfscan import network
from mobsfscan.manifest import do_checks
from mobsfscan.network import (
    assetlinks_url,
    fetch_all_assetlinks,
    fetch_assetlinks,
    is_disallowed_ip,
)

GITHUB_IP = '192.30.255.113'
CLOUDFLARE_IP = '172.67.1.1'


def addrinfo(*addresses):
    infos = []
    for address in addresses:
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        sockaddr = (address, 443, 0, 0) if ':' in address else (address, 443)
        infos.append((family, socket.SOCK_STREAM, 6, '', sockaddr))
    return infos


class FakeResponse:

    def __init__(self, status_code=200, body=b''):
        self.status_code = status_code
        self.body = body

    def __enter__(self):
        """Enter."""
        return self

    def __exit__(self, *args):
        """Exit."""
        return False

    def iter_content(self, chunk_size):
        """Yield the whole body."""
        yield self.body


@pytest.fixture
def requests_sent(monkeypatch):
    sent = []

    def fake_get(session, url, **kwargs):
        sent.append((url, kwargs))
        return FakeResponse(404)

    monkeypatch.setattr(requests.Session, 'get', fake_get)
    return sent


@pytest.fixture
def dns(monkeypatch):
    records = {}
    calls = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        calls.append(host)
        if host not in records:
            raise socket.gaierror(socket.EAI_NONAME, 'not found')
        answers = records[host]
        if callable(answers):
            answers = answers()
        return addrinfo(*answers)

    monkeypatch.setattr(socket, 'getaddrinfo', fake_getaddrinfo)
    records['calls'] = calls
    return records


@pytest.mark.parametrize('ip', [
    '168.63.129.16',
    '100.64.0.1',
    '100.100.100.200',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '127.0.0.1',
    '169.254.169.254',
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '0.0.0.0',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:168.63.129.16',
    'fe80::1',
    'fc00::1',
    '2002:7f00:1::',
    '2001:0:102:304::80ff:fffe',
    '64:ff9b:1::7f00:1',
    'not-an-ip',
])
def test_disallowed_ips(ip):
    assert is_disallowed_ip(ip)


@pytest.mark.parametrize('ip', [
    '8.8.8.8',
    GITHUB_IP,
    CLOUDFLARE_IP,
    '2606:4700:4700::1111',
])
def test_public_ips_allowed(ip):
    assert not is_disallowed_ip(ip)


@pytest.mark.parametrize('scheme, host, port', [
    ('https', 'evil.com?x=', None),
    ('https', 'evil.com/x', None),
    ('https', 'evil.com#x', None),
    ('https', 'user@evil.com', None),
    ('https', 'user:pass@evil.com', None),
    ('https', 'evil.com', '8080'),
    ('https', 'evil.com', '22'),
    ('https', 'evil.com:8080', None),
    ('https', '2130706433', None),
    ('https', 'localhost', None),
    ('https', 'metadata.google.internal', None),
    ('ftp', 'evil.com', None),
])
def test_unsafe_urls_rejected(scheme, host, port):
    assert assetlinks_url(scheme, host, port) is None


@pytest.mark.parametrize('scheme, host, port', [
    ('https', 'example.com', None),
    ('https', 'example.com', '443'),
    ('http', 'example.com', '80'),
    ('https', '8.8.8.8', None),
])
def test_safe_urls_accepted(scheme, host, port):
    assert assetlinks_url(scheme, host, port)


def test_private_ip_literals_not_requested(requests_sent):
    deadline = time.monotonic() + 5
    for url in (
        'https://168.63.129.16/.well-known/assetlinks.json',
        'https://127.1/.well-known/assetlinks.json',
        'https://[::ffff:127.0.0.1]/.well-known/assetlinks.json',
    ):
        assert fetch_assetlinks(url, deadline) is None
    assert requests_sent == []


def test_hostname_resolving_to_private_ip(dns, requests_sent):
    dns['internal.example.com'] = ['10.0.0.5']
    url = 'https://internal.example.com/.well-known/assetlinks.json'
    assert fetch_assetlinks(url, time.monotonic() + 5) is None
    assert requests_sent == []


def test_hostname_with_loopback_ipv6_record(dns, requests_sent):
    dns['mixed.example.com'] = ['93.184.216.34', '::1']
    url = 'https://mixed.example.com/.well-known/assetlinks.json'
    assert fetch_assetlinks(url, time.monotonic() + 5) is None
    assert requests_sent == []


def test_connects_to_checked_ip(dns, requests_sent):
    answers = iter([['93.184.216.34'], ['127.0.0.1']])
    dns['rebind.example.com'] = lambda: next(answers)
    url = 'https://rebind.example.com/.well-known/assetlinks.json'
    assert fetch_assetlinks(url, time.monotonic() + 5) == (404, b'')
    assert dns['calls'] == ['rebind.example.com']
    sent_url, kwargs = requests_sent[0]
    assert sent_url == 'https://93.184.216.34/.well-known/assetlinks.json'
    assert kwargs['headers'] == {'Host': 'rebind.example.com'}
    assert kwargs['allow_redirects'] is False


def test_total_time_limit(monkeypatch):
    monkeypatch.setattr(
        network, 'fetch_assetlinks', lambda url, deadline: time.sleep(5))
    start = time.monotonic()
    results = fetch_all_assetlinks(
        ['https://slow.example.com/.well-known/assetlinks.json'],
        timeout=0.2)
    assert time.monotonic() - start < 2
    assert isinstance(list(results.values())[0], TimeoutError)


@pytest.fixture
def drip_server(monkeypatch):
    """Local server that sends one byte at a time, never finishing."""
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    mode = {'closed': threading.Event()}

    def handle(conn):
        with conn:
            conn.recv(65536)
            if mode['drip'] == 'body':
                conn.sendall(b'HTTP/1.1 200 OK\r\n'
                             b'Content-Length: 1000000\r\n\r\n')
                payload = iter(lambda: b'x', None)
            elif mode['drip'] == 'body_until_close':
                conn.sendall(b'HTTP/1.0 200 OK\r\n\r\n')
                payload = iter(lambda: b'x', None)
            else:
                conn.sendall(b'HTTP/1.1 200 OK\r\n')
                payload = iter(lambda: b'X-Slow: x\r\n', None)
            for data in payload:
                for byte in data:
                    if stop.wait(0.2):
                        return
                    try:
                        conn.sendall(bytes([byte]))
                    except OSError:
                        mode['closed'].set()
                        return

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    # The server is on loopback, which the real check rightly refuses.
    monkeypatch.setattr(
        network, 'resolve_public_ips', lambda host, port: ('127.0.0.1',))
    monkeypatch.setattr(network, 'ALLOWED_PORTS', (80, 443, port))
    yield mode, f'http://slow.example.com:{port}/.well-known/assetlinks.json'
    stop.set()
    listener.close()


@pytest.mark.parametrize('drip', ['body', 'body_until_close', 'headers'])
def test_slow_drip_server_does_not_hang_scan(drip_server, drip):
    mode, url = drip_server
    mode['drip'] = drip
    start = time.monotonic()
    results = fetch_all_assetlinks([url], timeout=1)
    assert time.monotonic() - start < 3
    assert isinstance(results[url], TimeoutError)
    # The connection is torn down, not left running in the worker thread.
    assert mode['closed'].wait(3)


def test_url_cap(monkeypatch):
    monkeypatch.setattr(
        network, 'fetch_assetlinks', lambda url, deadline: (404, b''))
    urls = [
        f'https://h{i}.example.com/.well-known/assetlinks.json'
        for i in range(network.MAX_ASSETLINKS_URLS + 5)]
    assert len(fetch_all_assetlinks(urls)) == network.MAX_ASSETLINKS_URLS


MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="29"/>
  <application android:allowBackup="false">
    <activity android:name=".Main">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        {}
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def scan(data_tags):
    parsed = parse(MANIFEST.format(data_tags))
    findings = do_checks('AndroidManifest.xml', parsed)
    return [f for f in findings
            if f['id'] == 'android_manifest_well_known_assetlinks']


def test_manifest_internal_hosts_not_requested(dns, requests_sent):
    dns['rebind.example.com'] = ['10.0.0.1']
    findings = scan(
        '<data android:scheme="https" android:host="168.63.129.16"/>'
        '<data android:scheme="https" android:host="100.100.100.200"/>'
        '<data android:scheme="https" android:host="evil.com?x="/>'
        '<data android:scheme="https" android:host="evil.com"'
        ' android:port="8080"/>'
        '<data android:scheme="https" android:host="rebind.example.com"/>')
    assert requests_sent == []
    assert findings == []


def test_manifest_github_and_cloudflare_hosts_checked(dns, requests_sent):
    dns['app.github.example'] = [GITHUB_IP]
    dns['app.cloudflare.example'] = [CLOUDFLARE_IP]
    findings = scan(
        '<data android:scheme="https" android:host="app.github.example"/>'
        '<data android:scheme="https"'
        ' android:host="app.cloudflare.example"/>')
    assert sorted(url for url, _ in requests_sent) == [
        f'https://{CLOUDFLARE_IP}/.well-known/assetlinks.json',
        f'https://{GITHUB_IP}/.well-known/assetlinks.json',
    ]
    assert len(findings) == 2


def test_manifest_valid_assetlinks_no_finding(dns, monkeypatch):
    dns['good.example.com'] = ['93.184.216.34']
    body = b'[{"target": {"sha256_cert_fingerprints": ["AB:CD"]}}]'
    monkeypatch.setattr(
        requests.Session, 'get',
        lambda session, url, **kwargs: FakeResponse(200, body))
    assert scan(
        '<data android:scheme="https" android:host="good.example.com"/>',
    ) == []
