# Napoleon-XSS

**Napoleon-XSS** is a high-octane, asynchronous XSS (Cross-Site Scripting) scanner crafted for ethical pentesters and bug bounty hunters. Built in Python, it wields context-aware payloads to exploit vulnerabilities, bypasses modern WAFs (AWS WAF, Cloudflare), and crawls Web Archive for hidden endpoints. With Burp Suite integration for proxying, Napoleon-XSS is your ultimate weapon for pinpointing XSS flaws with speed and precision. Tested on HackenProof, it’s ready to dominate bug bounties.

⚠️ **Ethical Use Only**: This tool is for authorized security testing. Unauthorized use is illegal and unethical. Get explicit permission before scanning, or you’re fucking yourself over.

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![HackenProof](https://img.shields.io/badge/tested-HackenProof-orange.svg)](https://hackenproof.com/)

## Key Features
- **Context-Aware Payloads**: Targets HTML, JavaScript, SVG, MathML, and more with tailored exploits.
- **WAF Evasion**: Bypasses AWS WAF, Cloudflare, and CSP with advanced encoding and obfuscation.
- **Web Archive Crawling**: Uncovers archived URLs for exhaustive endpoint coverage.
- **Burp Suite Integration**: Routes traffic through proxies for manual analysis and debugging.
- **Asynchronous Scanning**: Blasts through thousands of URLs with minimal latency using `aiohttp`.
- **Fully Customizable**: Tweak workers, jitter, timeouts, and proxies to suit your needs.

## Installation

### Prerequisites
- Python 3.8 or higher
- Burp Suite (optional, for proxy integration)
- Git

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/Galmanus/Napoleon-XSS.git
   cd Napoleon-XSS
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Configure Burp Suite proxy at `http://127.0.0.1:8080` for traffic inspection.

## Usage

Napoleon-XSS supports two modes: direct URL scanning and Web Archive crawling.

### 1. Direct URL Scanning
Scan a list of URLs for XSS vulnerabilities:
```bash
python napoleon-xss.py --urls urls.txt --verbose --output xss_results
```
- `--urls`: File with URLs (one per line) or comma-separated list (e.g., `http://example.com/page?param=test`).
- `--verbose`: Enable detailed logging.
- `--output`: Output file for results (JSON, saved to `results/xss_results.json`).
- `--proxy`: Proxy URL (default: `http://127.0.0.1:8080`).

**Example `urls.txt`**:
```text
http://example.com/page?param=test
http://test.com/search?q=input
```

**Run**:
```bash
python napoleon-xss.py --urls examples/urls.txt --verbose
```

### 2. Web Archive Crawling
Crawl Web Archive for URLs under subdomains, then scan them:
```bash
python napoleon-xss.py --subdomains subdomains.txt --verbose
```
- `--subdomains`: File with subdomains (one per line) or comma-separated list (e.g., `example.com,test.com`).
- Crawled URLs are saved to `results/crawled_urls.txt` and scanned automatically.

**Example `subdomains.txt`**:
```text
example.com
test.com
```

**Run**:
```bash
python napoleon-xss.py --subdomains examples/subdomains.txt --verbose
```

### Output
Results are saved in `results/xss_results.json`:
```json
[
  {
    "url": "http://example.com/page?param=test",
    "payload": "SVG Set",
    "status": 200,
    "length_diff": 150,
    "param": "param",
    "injection_point": "query",
    "context": ["html", "svg"],
    "bypass": "AWS WAF/CSP",
    "target": "CloudFront Cache Poisoning"
  }
]
```

## Configuration
Edit the `CONFIG` dictionary in `napoleon-xss.py`:
- `TIMEOUT`: Request timeout (default: 30s).
- `WORKERS`: Concurrent tasks (default: 70).
- `PROXY`: Proxy URL (default: `http://127.0.0.1:8080`).
- `JITTER_MIN/MAX`: Random delay range (default: 0.01–0.2s).
- `INITIAL_SCAN_LIMIT`: Max URLs per Web Archive query (default: 20,000).

## Payloads
Napoleon-XSS includes payloads for:
- **SVG Exploits**: `set`, `animatemotion` for dynamic injections.
- **Parser Confusion**: `xmp`, `noembed` to exploit browser quirks.
- **MathML and HTML**: Targets niche vectors like `ms` and `marquee`.
Payloads use `https://example.com/test` as a safe placeholder for testing.

## Ethical Use Disclaimer
Napoleon-XSS is a professional security tool. **Use it only with explicit permission from system owners.** Unauthorized scanning violates laws and terms of service. The author is not liable for misuse, so don’t be a dumbass.

## Contributing
Want to make Napoleon-XSS even more badass? Contributions are welcome!
1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/awesome`.
3. Commit changes: `git commit -m "Add awesome feature"`.
4. Push: `git push origin feature/awesome`.
5. Open a Pull Request.

See `CONTRIBUTING.md` (coming soon) for details.

## License
Licensed under the MIT License. See [`LICENSE`](./LICENSE) for details.

## Contact
- **GitHub**: [Galmanus](https://github.com/Galmanus)
- **Email**: m.galmanus@gmail.com
- **X**: @galmanus

Built with blood, sweat, and coffee by a HackenProof-tested bug bounty hunter. Happy (ethical) hacking, you legends! 😎
