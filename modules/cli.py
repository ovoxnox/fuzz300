#!/usr/bin/env python3
# CLI definition.

import os
import argparse
from http.cookies import SimpleCookie

def parse_cookies(raw):
    jar = {}
    if not raw:return jar
    try:
        c = SimpleCookie()
        c.load(raw)
        jar = {k: m.value for k, m in c.items()}
    except Exception:
        for part in raw.replace('Cookie:', '').split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                jar[k.strip()] = v.strip()
    return jar

def build_parser():
    p = argparse.ArgumentParser(
        prog='fuzz300',
        description='fast recon & audit: crawl, forms, JS endpoints, SSRF/smuggling/GAP checks')
    p.add_argument('-u', '--url', help='single target, e.g. https://example.com')
    p.add_argument('-f', '--file', help='file with domains/URLs (one per line) -> multiprocess scan')
    p.add_argument('-c', '--cookies', default='', help="session cookies: 'session=abc; token=xyz'")
    p.add_argument('-o', '--outdir', default='websites')
    p.add_argument('-w', '--workers', type=int,
                   default=min(8, os.cpu_count() or 4), help='parallel domains (processes)')
    p.add_argument('--depth', type=int, default=3)
    p.add_argument('--max-urls', type=int, default=3000)
    p.add_argument('--concurrency', type=int, default=60, help='requests in flight per domain')
    p.add_argument('--timeout', type=float, default=10)
    p.add_argument('--proxy', default=None, help='e.g. http://127.0.0.1:8080 (or set HTTPS_PROXY)')
    p.add_argument('--oob', default=None, help='OOB callback domain for blind SSRF (interactsh)')
    p.add_argument('--payloads', default='data/fuzz.txt', help='payload file for the fuzz module')
    p.add_argument('--modules', default='crawl,scrape,gap',
                   help='comma list: crawl,scrape,fuzz,ssrf,smuggle,gap,redirect')
    p.add_argument('--max-smuggle-paths', type=int, default=10)
    p.add_argument('--paths-file', default='data/vuln_paths.txt',
                   help='path wordlist for the fuzz module (content discovery, fired at every host)')
    p.add_argument('--max-paths', type=int, default=5000, help='wordlist cap for path fuzzing')
    return p
