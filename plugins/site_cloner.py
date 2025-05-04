
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
from core.base_plugin import BasePlugin
import logging
import networkx as nx
import json
import os
import mimetypes
import time
import re
import hashlib
import base64
from datetime import datetime
from requests.exceptions import RequestException, Timeout, TooManyRedirects
import random
from PIL import Image
from io import BytesIO

class SiteCloner(BasePlugin):
    @property
    def name(self):
        return "Website Structure Analysis"

    def __init__(self):
        self.visited_urls = set()
        self.site_graph = nx.DiGraph()
        self.downloaded_files = {}
        self.security_issues = []
        self.sitemap = []
        self.screenshots = {}
        self.last_request_time = 0
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]

    def _is_valid_url(self, url, base_domain):
        """Check if URL belongs to the same domain"""
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_domain)

        # Handle URLs with no netloc (relative URLs)
        if not parsed_url.netloc:
            return True

        # Check if the URL is from the same domain or a subdomain
        return parsed_url.netloc == parsed_base.netloc or parsed_url.netloc.endswith('.' + parsed_base.netloc)

    def _is_asset_url(self, url):
        """Check if URL is a static asset (CSS, JS, image, etc.)"""
        extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']
        parsed_url = urlparse(url)
        path = unquote(parsed_url.path.lower())
        return any(path.endswith(ext) for ext in extensions)

    def _extract_resources(self, url, html_content, base_domain):
        """Extract all resources from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        resources = set()

        # Extract links from various HTML elements
        for tag_name, attrs in [
            ('a', ['href']),
            ('link', ['href']),
            ('script', ['src']),
            ('img', ['src', 'data-src']),
            ('source', ['src']),
            ('iframe', ['src']),
            ('form', ['action']),
            ('object', ['data']),
            ('embed', ['src']),
            ('video', ['src', 'poster']),
            ('audio', ['src']),
            ('track', ['src']),
            ('input', ['src']),
            ('button', ['formaction']),
            ('meta', ['content'])  # For refresh redirects
        ]:
            for tag in soup.find_all(tag_name):
                for attr in attrs:
                    if tag.get(attr):
                        # Special case for meta refresh
                        if tag_name == 'meta' and attr == 'content' and tag.get('http-equiv', '').lower() == 'refresh':
                            content = tag.get('content', '')
                            url_match = re.search(r'url=(.+)', content, re.IGNORECASE)
                            if url_match:
                                href = url_match.group(1).strip()
                                full_url = urljoin(url, href)
                                if self._is_valid_url(full_url, base_domain):
                                    resources.add(full_url)
                        else:
                            href = tag.get(attr)
                            if href and not href.startswith('javascript:') and not href.startswith('#'):
                                full_url = urljoin(url, href)
                                if self._is_valid_url(full_url, base_domain):
                                    resources.add(full_url)

        # Extract CSS URLs
        for style_tag in soup.find_all('style'):
            if style_tag.string:
                css_urls = re.findall(r'url\([\'"]?([^\'"]+)[\'"]?\)', style_tag.string)
                for css_url in css_urls:
                    full_url = urljoin(url, css_url)
                    if self._is_valid_url(full_url, base_domain):
                        resources.add(full_url)

        # Extract inline style URLs
        for tag in soup.find_all(style=True):
            css_urls = re.findall(r'url\([\'"]?([^\'"]+)[\'"]?\)', tag['style'])
            for css_url in css_urls:
                full_url = urljoin(url, css_url)
                if self._is_valid_url(full_url, base_domain):
                    resources.add(full_url)

        # Check for security issues
        self._check_security_issues(url, soup)

        return resources

    def _check_security_issues(self, url, soup):
        """Check for common security issues in the HTML"""
        # Check for forms without CSRF protection
        for form in soup.find_all('form', method=lambda x: x and x.lower() == 'post'):
            has_csrf = False
            for input_tag in form.find_all('input', type='hidden'):
                name = input_tag.get('name', '').lower()
                if 'csrf' in name or 'token' in name:
                    has_csrf = True
                    break

            if not has_csrf:
                self.security_issues.append({
                    'url': url,
                    'type': 'CSRF',
                    'severity': 'Medium',
                    'description': 'Form without CSRF protection found',
                    'details': str(form)[:100] + '...' if len(str(form)) > 100 else str(form)
                })

        # Check for password inputs in non-HTTPS forms
        if url.startswith('http://'):
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'password'}):
                    self.security_issues.append({
                        'url': url,
                        'type': 'Insecure Password',
                        'severity': 'High',
                        'description': 'Password input in non-HTTPS form',
                        'details': str(form)[:100] + '...' if len(str(form)) > 100 else str(form)
                    })

        # Check for mixed content
        if url.startswith('https://'):
            for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith('http://'):
                    self.security_issues.append({
                        'url': url,
                        'type': 'Mixed Content',
                        'severity': 'Medium',
                        'description': f'Mixed content: {tag.name} loaded over HTTP',
                        'details': str(tag)
                    })

        # Check for sensitive information in HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        for comment in comments:
            comment_text = comment.strip()
            sensitive_patterns = ['password', 'api', 'key', 'secret', 'token', 'auth', 'todo', 'fix']
            for pattern in sensitive_patterns:
                if pattern in comment_text.lower():
                    self.security_issues.append({
                        'url': url,
                        'type': 'Sensitive Comment',
                        'severity': 'Low',
                        'description': f'Potentially sensitive information in HTML comment',
                        'details': comment_text[:100] + '...' if len(comment_text) > 100 else comment_text
                    })
                    break

    def _download_file(self, url, rate_limit=1.0):
        """Download file from URL with rate limiting"""
        # Implement rate limiting
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < rate_limit:
            time.sleep(rate_limit - time_since_last_request)

        self.last_request_time = time.time()

        # Rotate user agents
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }

        try:
            response = requests.get(url, timeout=10, verify=False, headers=headers, allow_redirects=True)
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').split(';')[0]

                # Add to sitemap
                self.sitemap.append({
                    'url': url,
                    'title': self._extract_title(response.content) if 'text/html' in content_type else None,
                    'status_code': response.status_code,
                    'content_type': content_type,
                    'size': len(response.content)
                })

                # Take screenshot if it's HTML
                if 'text/html' in content_type:
                    self._take_screenshot(url)

                return response.content, content_type
            else:
                logging.warning(f"Failed to download {url}: HTTP {response.status_code}")
                return None, None
        except (RequestException, Timeout, TooManyRedirects) as e:
            logging.error(f"Error downloading {url}: {str(e)}")
            return None, None
        except Exception as e:
            logging.error(f"Unexpected error downloading {url}: {str(e)}")
            return None, None

    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag and title_tag.string:
                return title_tag.string.strip()
        except Exception as e:
            logging.error(f"Error extracting title: {str(e)}")
        return None

    def _take_screenshot(self, url):
        """Placeholder for screenshot functionality"""
        # In a real implementation, this would use a headless browser like Selenium
        # For now, we'll just create a placeholder
        self.screenshots[url] = {
            'timestamp': datetime.now().isoformat(),
            'status': 'Placeholder - Actual screenshots require a headless browser'
        }

    def _clone_site(self, url, base_domain, max_depth=2, current_depth=0, rate_limit=1.0, download_assets=True):
        """Recursively clone site structure and download files"""
        if current_depth > max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        try:
            content, content_type = self._download_file(url, rate_limit)
            if content and content_type:
                self.downloaded_files[url] = {
                    'content': content,
                    'content_type': content_type,
                    'timestamp': datetime.now().isoformat()
                }

                if 'text/html' in content_type:
                    resources = self._extract_resources(url, content.decode('utf-8', errors='ignore'), base_domain)
                    for resource in resources:
                        if resource not in self.visited_urls:
                            self.site_graph.add_edge(url, resource)

                            # For assets, don't increment depth
                            if download_assets and self._is_asset_url(resource):
                                self._clone_site(resource, base_domain, max_depth, current_depth, rate_limit, download_assets)
                            else:
                                self._clone_site(resource, base_domain, max_depth, current_depth + 1, rate_limit, download_assets)

        except Exception as e:
            logging.error(f"Error cloning {url}: {str(e)}")

    def generate_sitemap_xml(self):
        """Generate sitemap in XML format"""
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

        for page in self.sitemap:
            if page.get('content_type') and 'text/html' in page.get('content_type'):
                xml += '  <url>\n'
                xml += f'    <loc>{page["url"]}</loc>\n'
                xml += f'    <lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod>\n'
                xml += '  </url>\n'

        xml += '</urlset>'
        return xml

    def generate_html_report(self, target):
        """Generate HTML report of the cloned site"""
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Website Clone Report - {target}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                .header {{
                    background-color: #3498db;
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .section {{
                    background-color: #f9f9f9;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                    border-left: 5px solid #3498db;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                th, td {{
                    padding: 12px 15px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #3498db;
                    color: white;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .security-high {{
                    background-color: #ffdddd;
                }}
                .security-medium {{
                    background-color: #ffffdd;
                }}
                .security-low {{
                    background-color: #ddffdd;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    color: #7f8c8d;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Website Clone Report</h1>
                    <p>Target: {target}</p>
                    <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>

                <div class="section">
                    <h2>Summary</h2>
                    <table>
                        <tr>
                            <th>Metric</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Total Pages</td>
                            <td>{len([p for p in self.sitemap if p.get('content_type') and 'text/html' in p.get('content_type')])}</td>
                        </tr>
                        <tr>
                            <td>Total Files</td>
                            <td>{len(self.downloaded_files)}</td>
                        </tr>
                        <tr>
                            <td>Total Links</td>
                            <td>{len(self.site_graph.edges())}</td>
                        </tr>
                        <tr>
                            <td>Security Issues</td>
                            <td>{len(self.security_issues)}</td>
                        </tr>
                    </table>
                </div>

                <div class="section">
                    <h2>Pages</h2>
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Title</th>
                            <th>Content Type</th>
                            <th>Size</th>
                        </tr>
        """

        # Add pages to the report
        for page in sorted(self.sitemap, key=lambda x: x['url']):
            if page.get('content_type') and 'text/html' in page.get('content_type'):
                size_kb = page.get('size', 0) / 1024
                html += f"""
                        <tr>
                            <td><a href="{page['url']}" target="_blank">{page['url']}</a></td>
                            <td>{page.get('title', 'No title')}</td>
                            <td>{page.get('content_type', 'Unknown')}</td>
                            <td>{size_kb:.1f} KB</td>
                        </tr>
                """

        html += """
                    </table>
                </div>

                <div class="section">
                    <h2>Assets</h2>
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Content Type</th>
                            <th>Size</th>
                        </tr>
        """

        # Add assets to the report
        for url, info in sorted(self.downloaded_files.items()):
            content_type = info.get('content_type', 'Unknown')
            if 'text/html' not in content_type:
                size_kb = len(info.get('content', b'')) / 1024
                html += f"""
                        <tr>
                            <td><a href="{url}" target="_blank">{url}</a></td>
                            <td>{content_type}</td>
                            <td>{size_kb:.1f} KB</td>
                        </tr>
                """

        html += """
                    </table>
                </div>
        """

        # Add security issues section if there are any
        if self.security_issues:
            html += """
                <div class="section">
                    <h2>Security Issues</h2>
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
            """

            for issue in sorted(self.security_issues, key=lambda x: x['severity']):
                severity_class = f"security-{issue['severity'].lower()}"
                html += f"""
                        <tr class="{severity_class}">
                            <td><a href="{issue['url']}" target="_blank">{issue['url']}</a></td>
                            <td>{issue['type']}</td>
                            <td>{issue['severity']}</td>
                            <td>{issue['description']}</td>
                        </tr>
                """

            html += """
                    </table>
                </div>
            """

        html += """
                <div class="footer">
                    <p>Generated by CyberWolfScanner Website Cloner</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html

    def run(self, target: str, ports: str = None, options: dict = None) -> dict:
        """Clone website with advanced options"""
        logging.info(f"Starting website structure analysis for {target}")

        # Set default options
        if not options:
            options = {}

        max_depth = options.get('max_depth', 2)
        rate_limit = options.get('rate_limit', 1.0)
        download_assets = options.get('download_assets', True)
        protocol = options.get('protocol', 'https')

        base_url = f"{protocol}://{target}"

        self.visited_urls.clear()
        self.site_graph.clear()
        self.downloaded_files.clear()
        self.security_issues.clear()
        self.sitemap.clear()
        self.screenshots.clear()

        self._clone_site(base_url, base_url, max_depth, 0, rate_limit, download_assets)

        nodes = list(self.site_graph.nodes())
        edges = list(self.site_graph.edges())

        # Generate sitemap XML
        sitemap_xml = self.generate_sitemap_xml()

        # Generate HTML report
        html_report = self.generate_html_report(target)

        site_structure = {
            'nodes': nodes,
            'edges': [{'source': s, 'target': t} for s, t in edges],
            'total_pages': len([p for p in self.sitemap if p.get('content_type') and 'text/html' in p.get('content_type')]),
            'total_files': len(self.downloaded_files),
            'total_links': len(edges),
            'security_issues': self.security_issues,
            'sitemap': self.sitemap,
            'screenshots': self.screenshots,
            'downloaded_files': {
                url: {
                    'content_type': info['content_type'],
                    'size': len(info['content']),
                    'timestamp': info.get('timestamp', datetime.now().isoformat())
                } for url, info in self.downloaded_files.items()
            },
            'reports': {
                'sitemap_xml': sitemap_xml,
                'html_report': html_report
            }
        }

        return site_structure
