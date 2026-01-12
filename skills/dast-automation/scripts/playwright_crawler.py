#!/usr/bin/env python3
"""
Playwright-based Web Crawler
Intelligent crawler for DAST using Playwright MCP for JavaScript-aware crawling.
"""

import argparse
import json
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime

class PlaywrightCrawler:
    """
    Intelligent web crawler using Playwright MCP

    NOTE: This script provides the crawling framework.
    Actual Playwright operations are performed by Claude Code via MCP.
    """

    def __init__(self, start_url, max_depth=3, max_urls=500, scope=None):
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.scope = scope or [urlparse(start_url).netloc]

        # Discovered data
        self.discovered_urls = set([start_url])
        self.crawled_urls = set()
        self.discovered_forms = []
        self.discovered_apis = []
        self.discovered_inputs = []
        self.discovered_files = []

        # Crawl metadata
        self.metadata = {
            'start_time': datetime.now().isoformat(),
            'start_url': start_url,
            'max_depth': max_depth,
            'max_urls': max_urls
        }

    def crawl(self):
        """Execute crawling process"""
        print(f"[*] Starting Playwright crawl: {self.start_url}")
        print(f"[*] Max depth: {self.max_depth}")
        print(f"[*] Max URLs: {self.max_urls}")
        print(f"[*] Scope: {', '.join(self.scope)}\n")

        # Crawl starting from root
        self._crawl_url(self.start_url, depth=0)

        # Finalize metadata
        self.metadata['end_time'] = datetime.now().isoformat()
        self.metadata['urls_discovered'] = len(self.discovered_urls)
        self.metadata['urls_crawled'] = len(self.crawled_urls)
        self.metadata['forms_discovered'] = len(self.discovered_forms)
        self.metadata['apis_discovered'] = len(self.discovered_apis)

        print(f"\n[+] Crawl complete!")
        print(f"[+] URLs discovered: {len(self.discovered_urls)}")
        print(f"[+] URLs crawled: {len(self.crawled_urls)}")
        print(f"[+] Forms discovered: {len(self.discovered_forms)}")
        print(f"[+] APIs discovered: {len(self.discovered_apis)}")

        return self.get_results()

    def _crawl_url(self, url, depth):
        """
        Crawl a single URL

        NOTE: Claude Code performs actual Playwright operations:
        1. Launch browser / reuse context
        2. Navigate to URL
        3. Wait for page load and JavaScript execution
        4. Extract links, forms, inputs
        5. Monitor network requests for APIs
        6. Click interactive elements to discover hidden content
        7. Recursively crawl discovered URLs
        """

        # Check limits
        if depth > self.max_depth:
            return

        if len(self.crawled_urls) >= self.max_urls:
            return

        if url in self.crawled_urls:
            return

        # Check scope
        if not self._in_scope(url):
            return

        print(f"[*] Crawling [{depth}/{self.max_depth}]: {url}")

        # Mark as crawled
        self.crawled_urls.add(url)

        # === Playwright Operations (performed by Claude Code) ===

        # 1. Navigate to URL
        # await page.goto(url, waitUntil='networkidle')

        # 2. Extract all links
        links = self._extract_links_placeholder(url)
        for link in links:
            if link not in self.discovered_urls:
                self.discovered_urls.add(link)
                # Recursively crawl
                self._crawl_url(link, depth + 1)

        # 3. Extract forms
        forms = self._extract_forms_placeholder(url)
        self.discovered_forms.extend(forms)

        # 4. Monitor network for API calls
        apis = self._monitor_apis_placeholder(url)
        self.discovered_apis.extend(apis)

        # 5. Extract input fields
        inputs = self._extract_inputs_placeholder(url)
        self.discovered_inputs.extend(inputs)

        # 6. Extract downloadable files
        files = self._extract_files_placeholder(url)
        self.discovered_files.extend(files)

    def _in_scope(self, url):
        """Check if URL is in scope"""
        parsed = urlparse(url)
        return any(scope_host in parsed.netloc for scope_host in self.scope)

    # === Placeholder methods - Claude Code implements these via Playwright MCP ===

    def _extract_links_placeholder(self, url):
        """
        Extract all links from page using Playwright

        Claude Code will:
        - await page.$$eval('a[href]', links => links.map(a => a.href))
        - Filter and normalize URLs
        - Return list of absolute URLs
        """
        # Example return
        return [
            urljoin(url, '/about'),
            urljoin(url, '/contact'),
            urljoin(url, '/products')
        ]

    def _extract_forms_placeholder(self, url):
        """
        Extract all forms from page

        Claude Code will:
        - const forms = await page.$$('form')
        - For each form:
          - Extract action, method
          - Extract all input fields with names and types
          - Identify CSRF tokens
        """
        # Example return
        return [{
            'url': url,
            'action': urljoin(url, '/api/contact'),
            'method': 'POST',
            'fields': [
                {'name': 'name', 'type': 'text'},
                {'name': 'email', 'type': 'email'},
                {'name': 'message', 'type': 'textarea'}
            ],
            'has_csrf_token': True,
            'csrf_token_name': 'csrf_token'
        }]

    def _monitor_apis_placeholder(self, url):
        """
        Monitor network requests for API endpoints

        Claude Code will:
        - page.on('request', request => ...)
        - Capture all XHR/Fetch requests
        - Extract API endpoints, methods, parameters
        """
        # Example return
        return [{
            'url': urljoin(url, '/api/users'),
            'method': 'GET',
            'content_type': 'application/json',
            'authenticated': True
        }]

    def _extract_inputs_placeholder(self, url):
        """
        Extract all input fields

        Claude Code will:
        - await page.$$('input, textarea, select')
        - Extract name, type, value, placeholder
        """
        # Example return
        return [{
            'url': url,
            'selector': '#search',
            'name': 'q',
            'type': 'text',
            'placeholder': 'Search...'
        }]

    def _extract_files_placeholder(self, url):
        """
        Extract downloadable files

        Claude Code will:
        - await page.$$eval('a[href]', links => ...)
        - Filter for file extensions (.pdf, .doc, .xls, etc.)
        """
        # Example return
        return [{
            'url': urljoin(url, '/downloads/manual.pdf'),
            'type': 'pdf',
            'filename': 'manual.pdf'
        }]

    def get_results(self):
        """Get crawl results"""
        return {
            'metadata': self.metadata,
            'urls': list(self.discovered_urls),
            'forms': self.discovered_forms,
            'apis': self.discovered_apis,
            'inputs': self.discovered_inputs,
            'files': self.discovered_files
        }

    def export_json(self, output_file):
        """Export results to JSON"""
        results = self.get_results()

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"[+] Results exported to: {output_file}")

    def export_urls(self, output_file):
        """Export URLs list for other tools (Nuclei, etc.)"""
        with open(output_file, 'w') as f:
            for url in sorted(self.discovered_urls):
                f.write(f"{url}\n")

        print(f"[+] URLs exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Playwright-based Web Crawler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic crawl
  %(prog)s --url https://example.com --output crawl_results.json

  # Deep crawl with custom limits
  %(prog)s --url https://example.com --depth 5 --max-urls 1000 --output results.json

  # Crawl with scope restriction
  %(prog)s --url https://example.com --scope example.com,api.example.com --output results.json

Note: This script works WITH Claude Code's Playwright MCP integration.
      Claude Code orchestrates actual browser operations.
        """
    )

    parser.add_argument('--url', '-u', required=True, help='Starting URL')
    parser.add_argument('--depth', '-d', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-urls', '-m', type=int, default=500, help='Maximum URLs to crawl (default: 500)')
    parser.add_argument('--scope', '-s', help='Comma-separated list of domains in scope')
    parser.add_argument('--output', '-o', required=True, help='Output JSON file')
    parser.add_argument('--export-urls', help='Export discovered URLs to text file')

    args = parser.parse_args()

    # Parse scope
    scope = None
    if args.scope:
        scope = [s.strip() for s in args.scope.split(',')]

    print(f"\n{'='*60}")
    print("Playwright Web Crawler")
    print(f"{'='*60}\n")

    # Initialize crawler
    crawler = PlaywrightCrawler(
        start_url=args.url,
        max_depth=args.depth,
        max_urls=args.max_urls,
        scope=scope
    )

    # Execute crawl
    results = crawler.crawl()

    # Export results
    crawler.export_json(args.output)

    if args.export_urls:
        crawler.export_urls(args.export_urls)

if __name__ == '__main__':
    main()
