#!/usr/bin/env python3
# fuzz300 v2 - recon & audit orchestrator.
# Multiprocessing: -f domains.txt -w N runs N domains in parallel processes.

import os
import sys
import asyncio
import argparse

from urllib.parse import urlsplit
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.cli import build_parser, parse_cookies
from modules import utils
from modules.aopener import Fetcher
from modules.crawler import Crawler
from modules.scraper import scrape_forms, scrape_js
from modules import audit
from modules.fuzzer import fuzz_endpoints
from modules.fuzzer import fuzz_endpoints, fuzz_paths

ACTIVE = {'ssrf', 'smuggle', 'fuzz', 'redirect'}

async def pipeline(domain, args, modules):
    base = utils.outdir(args.outdir, domain)
    start = f'https://{domain}'
    async with Fetcher(cookies=parse_cookies(args.cookies), timeout=args.timeout,
                       concurrency=args.concurrency, proxy=args.proxy) as f:
        # scheme probe: https first, fall back to http
        r = await f.fetch(start)
        if r.status == 0 and ('ssl' in r.error.lower() or 'certificate' in r.error.lower()):
            start = f'http://{domain}'
            r = await f.fetch(start)

        report = {'domain': domain, 'start': start, 'modules': sorted(modules)}
        urls, js_files, js_eps = set(), set(), set()
        forms, endpoints = [], set()

        if 'crawl' in modules:
            urls, js_files = await Crawler(f, start, domain,
                                           args.depth, args.max_urls).run()
            utils.save_lines(f'{base}/urls.txt', urls)

        if 'scrape' in modules:
            if not urls:
                urls = {start}
            forms, eps = await scrape_forms(f, urls, domain)
            endpoints.update(eps)
            js_eps = await scrape_js(f, js_files, domain)
            utils.save_lines(f'{base}/forms.txt', forms)
            utils.save_lines(f'{base}/js_endpoints.txt', js_eps)

        # any crawled URL with query params becomes a FUZZ entry point
        for u in urls:
            z = utils.fuzzable(u)
            if z:
                endpoints.add('GET ' + z)
        endpoints.update(f'GET {u}' for u in js_eps if '?' in u)
        utils.save_lines(f'{base}/entry_points.txt', sorted(endpoints))

        get_eps = [e for e in endpoints if e.startswith('GET ')]
        post_eps = [e for e in endpoints if e.startswith('POST ')]
        findings = {}

        if 'gap' in modules:
            findings['gap'] = await audit.gap_audit(f, domain, start, urls, js_eps)
        if 'redirect' in modules:
            findings['openredirect'] = await audit.audit_openredirect(f, endpoints)
        if 'ssrf' in modules:
            findings['ssrf'] = await audit.audit_ssrf(f, get_eps[:200], oob=args.oob)
        if 'smuggle' in modules:
            targets = [e.split(' ', 1)[1] for e in post_eps] or [start]
            findings['smuggling'] = await audit.probe_smuggling(
                targets, args.max_smuggle_paths)
        if 'fuzz' in modules:
            findings['fuzz'] = await fuzz_endpoints(f, sorted(endpoints),
                                                    args.payloads)
            origins = {f'{urlsplit(u).scheme}://{urlsplit(u).netloc}'
                       for u in urls} or {start}
            findings['pathfuzz'] = await fuzz_paths(f, sorted(origins),
                                                    args.paths_file, args.max_paths)

        report['stats'] = {'urls': len(urls), 'forms': len(forms),
                           'entry_points': len(endpoints), 'js_files': len(js_files)}
        report['findings'] = findings
        utils.save_json(f'{base}/report.json', report)
        return report

def scan_domain(domain, ns):
    modules = {m.strip() for m in ns.modules.split(',') if m.strip()}
    try:return asyncio.run(pipeline(domain, ns, modules))
    except KeyboardInterrupt:raise
    except Exception as e:return {'domain': domain, 'error': f'\
    					{type(e).__name__}: {e}'}

def read_domains(args) -> List:
    raw = []
    if args.url:raw.append(args.url)
    if args.file:raw += utils.load_lines(args.file)
    out = []
    for item in raw:
        _= utils.normalize_url(item if '://' in item else 'http://' + item)
        try:d = utils.domain_of(_);out.append(d) if d and d not in out else ''
        except:pass
    return out

def summarize(rep):
    print(f'\n=== {rep["domain"]} ===')
    if 'error' in rep:
        print('  ERROR:', rep['error'])
        return
    s = rep.get('stats', {})
    print(f'  crawled {s.get("urls", 0)} urls | forms {s.get("forms", 0)} | '
          f'entry points {s.get("entry_points", 0)} | js files {s.get("js_files", 0)}')
    for mod, f in rep.get('findings', {}).items():
        n = len(f) if isinstance(f, list) else (1 if f else 0)
        print(f'  {mod:<13} {n} finding(s)')

def main():
    args = build_parser().parse_args()
    print(utils.BANNER)
    domains = read_domains(args)
    if not domains:
        print('no targets given (use -u or -f)')
        sys.exit(1)
    print(f'\n{len(domains)} target(s), {args.workers} worker process(es)\n')
    results = []
    try:
        with ProcessPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(scan_domain, d, args): d for d in domains}
            for fut in as_completed(futs):
                d = futs[fut]
                try:rep = fut.result()
                except Exception as e:rep = {'domain': d, 'error': str(e)}
                results.append(rep)
                summarize(rep)
    except KeyboardInterrupt:
        print('\ninterrupted - partial reports are on disk')
    _=sum(1 for r in results if 'error' not in r)
    print(f'\ndone: {_}/{len(domains)} target(s) scanned -> {args.outdir}/')

if __name__ == '__main__':
    main()
