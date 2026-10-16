#!/usr/bin/env python3
# Form extraction + JS endpoint mining

import re

from urllib.parse import urlencode, urljoin
from bs4 import BeautifulSoup
from typing import Set

from .utils import same_domain

# strings in JS that look like endpoints: 
#	/api/v1/x, /path/{id}, /x?y=1
JS_EP_RE = re.compile(
    r'''["'](/(?:[A-Za-z0-9_\-\.]+/)+[A-Za-z0-9_\-\.]*(?:\{[A-Za-z0-9_]+\})?(?:\?[A-Za-z0-9_=&\-\.]+)?)["']''')

async def scrape_forms(fetcher, urls, domain, limit=1500):
    pages = sorted(urls, key=len)[:limit]
    forms, endpoints = [], set()
    done = [0]

    def on_each(r):
        done[0] += 1
        print(f'[{domain}] scraping forms {done[0]}/{len(pages)}', end='\r')

    resps = await fetcher.fetch_many(pages, workers=40, on_each=on_each)
    for r in resps:
        if not r.body or r.status >= 400:continue
        try:soup = BeautifulSoup(r.text, 'html.parser')
        except Exception:continue
        for form in soup.find_all('form'):
            method = (form.get('method') or 'GET').upper()
            action = urljoin(r.url, form.get('action') or r.url)
            if not same_domain(action, domain):continue
            params = []
            for tag in form.find_all(('input', 'select', 'textarea', 'button')):
                name = tag.get('name')
                if not name:continue
                if tag.name == 'input' and tag.get('type', '').lower() in ('submit', 'button', 'image'):continue
                val = tag.get('value') or 'FUZZ'
                params.append((name, val))
            if not params:continue
            qs = urlencode(params)
            forms.append(f'{method} {action} :: {qs}')
            endpoints.add(f'{method} {action}?{qs}')
    return forms, endpoints

async def scrape_js(fetcher, js_urls, domain, limit=200) -> Set:
    if not js_urls:return set()
    resps = await fetcher.fetch_many(list(js_urls)[:limit], workers=30)
    out = set()
    for r in resps:
        if not r.body:continue
        for m in JS_EP_RE.finditer(r.text):
            ep = m.group(1)
            if len(ep) > 160 or ' ' in ep:continue
            out.add(urljoin(f'https://{domain}/', ep))
    return out
