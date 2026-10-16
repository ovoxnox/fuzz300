#!/usr/bin/env python3
# Shared helpers: URL normalization, dedupe, FUZZ placeholders, output files.

import os
import re
import json
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urljoin

BANNER = r'''
                __
              .'  '.        .-''-.
             | 301  |      ;  ,-> :
              '.__.'       :  |   ;
                ||          '-..-'
                ||
                ||
              \\||///
         ^^^^^^^^^^^^^^^ fuzz300'''

# asset extensions skipped while crawling (note: .json/.xml kept - they may be APIs)
ASSET_EXTS = {
    'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'bmp', 'webp', 'avif',
    'woff', 'woff2', 'ttf', 'otf', 'eot',
    'mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv', 'webm',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'apk', 'exe', 'dmg', 'iso',
}

def normalize_url(url, base=None):
    # Resolve, lowercase host, strip fragment, collapse slashes. None if unusable.
    if not url:return None
    if base:url = urljoin(base, url)
    try:p = urlsplit(url.strip())
    except ValueError:return None
    scheme = p.scheme.lower()
    if scheme not in ('http', 'https'):return None
    netloc = p.netloc.lower()
    if netloc.startswith('www.'):netloc = netloc[4:]
    # drop default ports so http://x:80/ == http://x/ (dedupe)
    if netloc.endswith(':80') and (p.scheme.lower() in ('', 'http')):
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and p.scheme.lower() == 'https':
        netloc = netloc[:-4]
    path = re.sub(r'/+', '/', p.path or '/')
    if path != '/' and path.endswith('/'):
        path = path[:-1]
    return urlunsplit((scheme, netloc, path, p.query, ''))

def host_of(url):
    return urlsplit(url).netloc.lower()

def domain_of(url):
    h = host_of(url).split(':')[0]
    return h[4:] if h.startswith('www.') else h

def same_domain(url, domain):
    h = host_of(url).split(':')[0]
    return h == domain or h.endswith('.' + domain)

def is_js(url):
    return urlsplit(url).path.lower().endswith('.js')

def is_page(url):
    # False for static assets we never want to crawl.
    last = urlsplit(url).path.rsplit('/', 1)[-1]
    if '.' not in last:return True
    return last.rsplit('.', 1)[-1].lower() not in ASSET_EXTS

def fuzzable(url):
    # Replace every query value with FUZZ (param names kept, deduped).
    p = urlsplit(url)
    if not p.query:return None
    seen, pairs = set(), []
    for k, _ in parse_qsl(p.query, keep_blank_values=True):
        if k and k not in seen:
            seen.add(k)
            pairs.append((k, 'FUZZ'))
    if not pairs:return None
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), ''))

def outdir(base, domain):
    path = os.path.join(base, domain.replace(':', '_'))
    os.makedirs(path, exist_ok=True)
    return path

def save_lines(path, lines):
    lines = [l for l in lines if l]
    if not lines:return
    with open(path, 'w', encoding='utf-8', errors='replace') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

def load_lines(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:return []

def save_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)
