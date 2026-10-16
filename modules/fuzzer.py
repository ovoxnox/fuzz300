#!/usr/bin/env python3
# Native async parameter fuzzer (replaces the blocking wfuzz call).
# Differential analysis vs per-endpoint baseline: 5xx, big body deltas.

import re

from pathlib import Path
from typing import List, Dict, Any

from .utils import load_lines

fp = Path('data') / 'fuzz.txt'
with fp.open(mode="r", encoding="utf-8") as f:
    _d_f = f.readlines()

# ['../../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd',
#    '<svg/onload=alert(document.domain)>', "'\"><svg/onload=alert(1)>",
#    "' OR '1'='1", '" OR "1"="1', '${7*7}', '{{7*7}}']

# param fuzzing

async def fuzz_endpoints(fetcher, endpoints, payload_file, max_payloads=150, cap=300):
    endpoints = [e for e in endpoints[:cap] if 'FUZZ' in e]
    if not endpoints:
        return []
    payloads = load_lines(payload_file) or _d_p
    payloads = payloads[:max_payloads]
    jobs = []
    for ep in endpoints:
        method, url = ep.split(' ', 1)
        base_url = url.replace('FUZZ', 'z9baseline9z')
        jobs.append(('baseline', ep, base_url))
        for pl in payloads:
            jobs.append((pl, ep, url.replace('FUZZ', pl)))
    print(f'[fuzz] {len(jobs)} requests, {len(endpoints)} endpoints, '
          f'{len(payloads)} payloads')
    resps = await fetcher.fetch_many([j[2] for j in jobs], workers=40)
    by_url = {r.url: r for r in resps}
    baselines = {ep: by_url.get(u) for tag, ep, u in jobs if tag == 'baseline'}
    findings = []
    for pl, ep, u in jobs:
        if pl == 'baseline':
            continue
        r, b = by_url.get(u), baselines.get(ep)
        if not r or r.status == 0:
            continue
        if r.status >= 500 and (not b or b.status < 500):
            findings.append({'endpoint': ep, 'payload': pl, 'status': r.status,
                             'note': 'server error - investigate (SQLi/SSRF/template?)'})
        elif b and r.status != b.status and abs(len(r.body) - len(b.body)) > 400:
            findings.append({'endpoint': ep, 'payload': pl,
                             'status': f'{b.status}->{r.status}',
                             'note': 'response changed significantly'})
    # keep the most interesting, dedup by endpoint
    seen, out = set(), []
    for f_ in sorted(findings, key=lambda x: str(x['status'])):
        if f_['endpoint'] not in seen:
            seen.add(f_['endpoint'])
            out.append(f_)
    return out[:50]

# path fuzzing

def load_paths(path_file, cap=5000) -> List:
    # Sanitize a nuclei/afrog-style path wordlist:
    # - strip surrounding quotes / whitespace
    # - only entries that (now) start with '/' survive -> drops SQL fragments,
    #   continuation lines of multi-line entries, regex/junk lines, comments
    # - replace {{template}} vars with a benign value, drop fragments (#...)
    # - dedupe, cap length and count
    out, seen = [], set()
    for line in load_lines(path_file):
        line = line.strip().strip('"').strip("'").strip()
        if not line.startswith('/'):continue
        # nested templates like {{{{r1}}*'{{r2}}'}}: substitute until stable
        for _ in range(4):
            line2 = re.sub(r'\{\{[^{}]*\}\}', '1', line)
            if line2 == line:break
            line = line2
        line = line.split('#', 1)[0].rstrip()
        # entries with raw whitespace are multi-payload afrog junk, not paths
        if not line.startswith('/') or ' ' in line or '\t' in line or len(line) > 300:continue
        if line in seen:continue
        seen.add(line);out.append(line)
        if len(out) >= cap:break
    return out

def _path_signal(resp):
    # classify a non-404 response; returns (sort_key, note)
    loc = resp.headers.get('Location', '')
    body = resp.text.lower()
    if resp.status == 200:
        if 'root:' in body and ':0:0:' in body:
            return 0, 'etc/passwd content?'
        if 'phpinfo()' in body or '<title>phpinfo' in body:
            return 0, 'phpinfo() page?'
        if any(k in body for k in ('swagger', 'openapi', 'graphql')):
            return 1, 'API schema surface'
        return 2, ''
    if resp.status in (401, 403):
        return 3, 'protected endpoint'
    if resp.status in (301, 302, 307, 308):
        return 4, f'redirect -> {loc[:80]}'
    if resp.status >= 500:
        return 5, 'server error'
    return 6, ''

async def fuzz_paths(fetcher, origins, path_file, max_paths=5000, workers=40, cap_results=500):
    # Content discovery: EVERY path in the wordlist is requested against EVERY
    # discovered origin (scheme://host), so findings on subdomains discovered
    # during the crawl are duplicated-checked too.
    paths = load_paths(path_file, max_paths)
    origins = sorted({o.rstrip('/') for o in origins})
    if not paths or not origins:
        return []
    jobs = [o + p for o in origins for p in paths]
    print(f'[pathfuzz] {len(jobs)} requests ({len(paths)} paths x {len(origins)} host(s))')
    resps = await fetcher.fetch_many(jobs, workers=workers)
    findings = []
    for r in resps:
        if r.status == 0 or r.status == 404:continue
        key, note = _path_signal(r)
        findings.append({'url': r.url, 'status': r.status, 'length': len(r.body),
                         'note': note, '_k': key})
    findings.sort(key=lambda f: (f['_k'], f['url']))
    for f in findings:del f['_k']
    return findings[:cap_results]
