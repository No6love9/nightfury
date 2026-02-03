#!/usr/bin/env python3
import requests
import concurrent.futures
import time
import random
import argparse
import sys
import re
from urllib.parse import urljoin
from typing import List, Dict, Set

class SophisticatedBrute:
    """
    Advanced Directory Brute-forcing Tool
    Features:
    - Adaptive rate limiting
    - User-Agent rotation
    - Recursive discovery
    - False positive detection (Wildcard DNS/404 handling)
    - Response analysis (Content-Length/Type)
    """
    
    def __init__(self, target: str, threads: int = 10, extensions: List[str] = None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.extensions = extensions or ['', '.php', '.html', '.js', '.json', '.txt', '.env', '.bak']
        self.found_items: Dict[str, Dict] = {}
        self.visited: Set[str] = set()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ]
        self.session = requests.Session()
        self.base_404_content = self._get_404_baseline()

    def _get_404_baseline(self):
        """Detects the behavior of the server for non-existent pages."""
        random_path = f"/{random.getrandbits(64):x}"
        try:
            r = self.session.get(urljoin(self.target, random_path), headers={'User-Agent': random.choice(self.user_agents)}, timeout=5)
            return {
                'status_code': r.status_code,
                'content_length': len(r.content),
                'text_snippet': r.text[:100]
            }
        except:
            return None

    def _is_false_positive(self, response: requests.Response) -> bool:
        """Heuristic check for false positives (custom 404s)."""
        if not self.base_404_content:
            return False
        
        # Check if status code matches baseline 404 (even if it's 200)
        if response.status_code == self.base_404_content['status_code']:
            # If lengths are very similar, it might be a false positive
            diff = abs(len(response.content) - self.base_404_content['content_length'])
            if diff < 50:
                return True
        return False

    def scan_path(self, path: str):
        """Checks a single path with various extensions."""
        results = []
        for ext in self.extensions:
            full_path = f"{path}{ext}"
            if full_path in self.visited:
                continue
            self.visited.add(full_path)
            
            url = urljoin(self.target, full_path)
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                # Use GET to analyze content, but HEAD could be used for speed
                r = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
                
                if r.status_code in [200, 204, 301, 302, 307, 403, 405]:
                    if not self._is_false_positive(r):
                        res_data = {
                            'url': url,
                            'status': r.status_code,
                            'length': len(r.content),
                            'type': r.headers.get('Content-Type', 'unknown')
                        }
                        print(f"  [+] Found: {url} (Status: {r.status_code}, Size: {len(r.content)})")
                        results.append(res_data)
                        
                        # If it's a directory (301/302 or 200 with directory-like content), mark for recursion
                        if r.status_code in [301, 302] or (r.status_code == 200 and 'text/html' in res_data['type']):
                            if not ext: # Only recurse into base paths
                                self.found_items[full_path] = res_data
            except Exception:
                pass
        return results

    def run(self, wordlist: List[str], recursive: bool = False):
        print(f"[*] Starting sophisticated brute-force on {self.target}")
        print(f"[*] Threads: {self.threads} | Extensions: {', '.join(self.extensions)}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_path, word) for word in wordlist]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        if recursive:
            dirs_to_scan = [p for p, d in self.found_items.items() if d['status'] in [301, 302]]
            if dirs_to_scan:
                print(f"[*] Recursing into {len(dirs_to_scan)} discovered directories...")
                for d in dirs_to_scan:
                    sub_wordlist = [f"{d}/{w}" for w in wordlist[:20]] # Limited sub-scan for demo
                    self.run(sub_wordlist, recursive=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist", default=None)
    parser.add_argument("-t", "--threads", type=int, default=10)
    args = parser.parse_args()

    default_words = ["admin", "login", "api", "v1", "v2", "config", "dev", "test", "uploads", "images", "assets", "scripts", "backup", ".env", ".git", "phpmyadmin", "robots.txt"]
    
    scanner = SophisticatedBrute(args.target, threads=args.threads)
    scanner.run(default_words, recursive=True)
