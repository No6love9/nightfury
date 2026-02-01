import socket
import requests
import json
import os
from core.error_handler import handle_exception

class DNSBypass:
    """
    Advanced DNS Deep-dive and Cloudflare Bypass Module.
    Focuses on finding origin IPs and bypassing WAFs.
    """
    def __init__(self):
        self.common_subdomains = ['dev', 'test', 'stage', 'origin', 'direct', 'mail', 'ftp', 'api', 'vpn', 'backend']
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def get_origin_ip(self, domain):
        """
        Attempts to find the origin IP by checking common 'direct' subdomains
        and utilizing historical DNS data if available.
        """
        print(f"[*] Investigating origin IP for: {domain}")
        found_ips = set()
        
        # 1. Check common direct-access subdomains
        for sub in self.common_subdomains:
            target = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                if ip:
                    print(f"[+] Potential Origin Found: {target} -> {ip}")
                    found_ips.add(ip)
            except socket.gaierror:
                continue

        # 2. Check for common Cloudflare bypass techniques (e.g., crimeflare style)
        # Note: In a real scenario, this would involve querying specialized APIs
        
        return list(found_ips)

    def cloudflare_check(self, domain):
        """
        Checks if a domain is behind Cloudflare.
        """
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(f"http://{domain}", headers=headers, timeout=5)
            server = response.headers.get('Server', '')
            if 'cloudflare' in server.lower():
                return True
        except Exception as e:
            handle_exception(e, {"module": "dns_bypass", "action": "cloudflare_check"})
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        db = DNSBypass()
        domain = sys.argv[1]
        if db.cloudflare_check(domain):
            print(f"[!] {domain} is behind Cloudflare. Attempting bypass...")
            ips = db.get_origin_ip(domain)
            if not ips:
                print("[-] No direct origin IPs found via standard subdomains.")
        else:
            print(f"[+] {domain} does not appear to be using Cloudflare.")
