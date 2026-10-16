#!/usr/bin/env python3
# Async HTTP layer: one aiohttp session per target process.
# Bounded concurrency, hard timeouts, one retry, redirect capture,

import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import List, Optional

UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0'

@dataclass
class Response:
    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b''
    error: str = ''

    @property
    def text(self):
        return self.body.decode('utf-8', errors='replace')

class Fetcher:
    def __init__(self, cookies=None, timeout=10, concurrency=60, max_tries=2, proxy=None):
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=5, sock_connect=5)
        self.sem = asyncio.Semaphore(concurrency)
        self.max_tries = max_tries
        self.cookies = cookies or {}
        self.proxy = proxy
        self.session = None

    async def __aenter__(self):
        conn = aiohttp.TCPConnector(limit=200, ttl_dns_cache=300, ssl=False,
                                    enable_cleanup_closed=True)
        self.session = aiohttp.ClientSession(
            connector=conn, timeout=self.timeout,
            headers={'User-Agent': UA, 'Accept': '*/*',
                     'Accept-Language': 'en-US,en;q=0.9'},
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            trust_env=True,
        )
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def fetch(self, url, method='GET', data=None, headers=None, last: Optional[str]=''):
        for _ in range(self.max_tries):
            async with self.sem:
                try:
                    async with self.session.request(
                            method, url, data=data, headers=headers,
                            cookies=self.cookies or None, proxy=self.proxy,
                            ssl=False, allow_redirects=False) as r:
                        body = await r.read()
                        return Response(url, r.status, dict(r.headers), body)
                except Exception as e:last = f'{type(e).__name__}: {e}'
        return Response(url, 0, error=last)

    async def fetch_many(self, urls, workers=40, on_each=None) -> List:
        urls = list(dict.fromkeys(urls))
        if not urls: return []
        q = asyncio.Queue()
        for u in urls:
            q.put_nowait(u)
        results = []

        async def worker():
            while True:
                try:u=q.get_nowait()
                except asyncio.QueueEmpty:return
                r = await self.fetch(u)
                results.append(r)
                if on_each:on_each(r)

        tasks = [asyncio.create_task(worker()) for _ in range(min(workers, len(urls)))]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results
