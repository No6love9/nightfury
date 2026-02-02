import requests
import concurrent.futures
import os
from core.base_module import BaseModule

class DirBrute(BaseModule):
    """
    Automated Directory Brute-forcing for Reconnaissance.
    Optimized for testing RuneHall infrastructure.
    """
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "dir_brute"
        self.description = "Automated directory brute-forcing module."
        self.wordlist = ["admin", "login", "config", "db", "api", "v1", "backup", "dev", "test", "staging", "uploads", "images", "css", "js", "robots.txt", "sitemap.xml", ".env", ".git"]
        self.options = {
            "target": "https://runehall.com",
            "threads": 5,
            "wordlist_path": ""
        }

    def load_wordlist(self, path):
        """Load custom wordlist if provided"""
        if path and os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                self.log(f"Loaded {len(self.wordlist)} words from {path}")
            except Exception as e:
                self.log(f"Error loading wordlist: {e}", "error")

    def brute_force(self):
        """Runs the brute-force operation using a thread pool."""
        target_url = self.options["target"].rstrip('/')
        threads = int(self.options["threads"])
        wordlist_path = self.options["wordlist_path"]
        
        if wordlist_path:
            self.load_wordlist(wordlist_path)
            
        self.log(f"Starting directory brute-force on: {target_url} with {threads} threads")
        found = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(self._check_url, target_url, path): path for path in self.wordlist}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    found.append(res)
        return found

    def _check_url(self, base_url, path):
        url = f"{base_url}/{path}"
        try:
            # Using a head request for speed and less noise
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code in [200, 301, 302, 403]:
                print(f"  [+] Found: {url} (Status: {response.status_code})")
                return (url, response.status_code)
        except Exception:
            pass
        return None

    def run(self, args):
        if args:
            self.options["target"] = args[0]
        
        results = self.brute_force()
        print(f"\n[*] Brute-force complete. Found {len(results)} directories.")
        if results:
            for url, status in results:
                print(f"  - {url} ({status})")
