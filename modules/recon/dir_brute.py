import requests
import concurrent.futures

class DirBrute:
    """
    Automated Directory Brute-forcing for Reconnaissance.
    Optimized for testing RuneHall infrastructure.
    """
    def __init__(self, target_url, wordlist_path=None):
        self.target_url = target_url.rstrip('/')
        self.wordlist = ["admin", "login", "config", "db", "api", "v1", "backup", "dev", "test", "staging", "uploads", "images", "css", "js"]
        if wordlist_path:
            # Load custom wordlist if provided
            pass

    def brute_force(self, threads=5):
        """Runs the brute-force operation using a thread pool."""
        print(f"[*] Starting directory brute-force on: {self.target_url}")
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(self._check_url, path): path for path in self.wordlist}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    found.append(res)
        return found

    def _check_url(self, path):
        url = f"{self.target_url}/{path}"
        try:
            # Using a head request for speed and less noise
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code in [200, 301, 302, 403]:
                print(f"[+] Found: {url} (Status: {response.status_code})")
                return (url, response.status_code)
        except Exception:
            pass
        return None

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://runehall.com"
    brute = DirBrute(target)
    results = brute.brute_force()
    print(f"[*] Brute-force complete. Found {len(results)} directories.")
