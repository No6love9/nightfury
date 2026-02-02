from core.base_module import BaseModule
import requests
import random

class ProxyOrchestrator(BaseModule):
    """
    Custom Proxy Orchestration for Clandestine Operations.
    Manages proxy rotation and ensures maximum anonymity.
    """
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "proxy_orchestrator"
        self.description = "Fetch and manage real-time proxy lists for stealth operations."
        self.proxy_list = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]

    def fetch_proxies(self):
        """Fetches a list of free proxies from public sources."""
        self.log("Fetching fresh proxies from public APIs...")
        sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"
        ]
        
        all_proxies = []
        for source in sources:
            try:
                resp = requests.get(source, timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    all_proxies.extend(lines)
            except Exception as e:
                self.log(f"Error fetching from {source}: {str(e)}", "error")
        
        self.proxy_list = list(set(all_proxies))
        self.log(f"Successfully loaded {len(self.proxy_list)} unique proxies.")
        return self.proxy_list

    def get_random_proxy(self):
        """Returns a random proxy from the list."""
        if not self.proxy_list:
            self.fetch_proxies()
        
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        return None

    def get_stealth_session(self):
        """Creates a requests session with rotated headers and proxies."""
        session = requests.Session()
        session.headers.update({"User-Agent": random.choice(self.user_agents)})
        proxy = self.get_random_proxy()
        if proxy:
            session.proxies = proxy
        return session

    def rotate_identity(self):
        """Rotates operational identity."""
        self.log("Rotating operational identity...")
        return self.get_stealth_session()

    def run(self, args):
        if "fetch" in args or not self.proxy_list:
            self.fetch_proxies()
        
        print(f"[*] Currently managing {len(self.proxy_list)} proxies.")
        if self.proxy_list:
            print(f"[*] Example proxy: {random.choice(self.proxy_list)}")
        print("[*] Use 'rotate_identity()' in other modules to enable stealth.")
