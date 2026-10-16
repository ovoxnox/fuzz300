#!/usr/bin/env python3
# Async BFS crawler: worker pool over a queue, depth

import re
import asyncio
from bs4 import BeautifulSoup

from .utils import normalize_url, same_domain, is_page, is_js
from .aopener import Fetcher

TAG_ATTRS = (('a', 'href'), ('link', 'href'), ('script', 'src'), ('img', 'src'),
             ('iframe', 'src'), ('form', 'action'), ('area', 'href'))
HREF_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"'#]+)["']''', re.I)
ABS_URL_RE = re.compile(r'''https?://[^\s"'<>)]+''', re.I)
REL_URL_RE = re.compile(r'''["'](/[^\s"'<>)]*)["']''')

class Crawler:
    def __init__(self, fetcher, start, domain, max_depth=3, max_urls=3000):
        self.f = fetcher
        self.start = start
        self.domain = domain
        self.max_depth = max_depth
        self.max_urls = max_urls

    def extract(self, html, base):
        links, js = set(), set()
        # regex pass first: cheap, survives malformed HTML
        for m in HREF_RE.finditer(html):
            u = normalize_url(m.group(1), base)
            if u:(js if is_js(u) else links).add(u)
        for m in ABS_URL_RE.finditer(html):
            u = normalize_url(m.group(0), base)
            if u:(js if is_js(u) else links).add(u)
        # structured pass
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag, attr in TAG_ATTRS:
                for el in soup.find_all(tag):
                    u = normalize_url(el.get(attr), base)
                    if u:(js if is_js(u) else links).add(u)
        except Exception:pass
        # relative endpoint strings buried in inline JS / JSON blobs
        for m in REL_URL_RE.finditer(html):
            u = normalize_url(m.group(1), base)
            if u:links.add(u)
        return links, js

    async def run(self, workers=30):
        seen = {self.start}
        js_files = set()
        fetched = [0]
        q = asyncio.Queue()
        q.put_nowait((self.start, 0))

        async def worker():
            while True:
                try:url, depth = q.get_nowait()
                except asyncio.QueueEmpty:return
                if fetched[0] >= self.max_urls:return
                resp = await self.f.fetch(url)
                fetched[0] += 1
                if resp.status and resp.body and not resp.error:
                    try:links, js = self.extract(resp.text, url)
                    except Exception:links, js = set(), set()
                    js_files.update(u for u in js if same_domain(u, self.domain))
                    if depth < self.max_depth:
                        for u in links:
                            if (u not in seen and same_domain(u, self.domain)
                                    and is_page(u)):
                                seen.add(u)
                                if fetched[0] + q.qsize() < self.max_urls:
                                    q.put_nowait((u, depth + 1))
                if fetched[0] % 100 == 0:
                    print(f'[{self.domain}] crawled {fetched[0]} ...', end='\r')

        tasks = [asyncio.create_task(worker()) for _ in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f'\n[{self.domain}] crawl done: {len(seen)} urls discovered, '
              f'{fetched[0]} fetched, {len(js_files)} js files')
        return seen, js_files
