from core.base_module import BaseModule
import subprocess
import socket
import os

class AdvancedScan(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "advanced_scan"
        self.description = "Advanced multi-vector scan utilizing system tools."

    def run(self, args):
        if not args:
            print("Usage: use advanced_scan <target>")
            return
        
        target = args[0]
        self.log(f"Starting advanced multi-vector scan on {target}...")
        
        # 1. DNS Enumeration
        print(f"\n[1] DNS Enumeration for {target}:")
        try:
            # Try to get MX and TXT records
            for qtype in ['MX', 'TXT', 'A']:
                print(f"  Checking {qtype} records...")
                # We'll use host command if available
                cmd = f"host -t {qtype} {target}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode == 0:
                    print(result.stdout.strip())
        except Exception as e:
            print(f"  DNS check failed: {e}")

        # 2. HTTP Header Analysis
        print(f"\n[2] HTTP Header Analysis:")
        try:
            import requests
            url = f"https://{target}" if not target.startswith('http') else target
            resp = requests.get(url, timeout=5, verify=False)
            print(f"  Status: {resp.status_code}")
            for header, value in resp.headers.items():
                print(f"  {header}: {value}")
                if header.lower() in ['server', 'x-powered-by']:
                    print(f"  [!] Tech stack hint found: {value}")
        except Exception as e:
            print(f"  HTTP check failed: {e}")

        # 3. Cloudflare/WAF Detection
        print(f"\n[3] WAF/CDN Detection:")
        try:
            ip = socket.gethostbyname(target)
            # Cloudflare IPs often start with 104., 172., etc.
            if ip.startswith('104.') or ip.startswith('172.'):
                print(f"  [+] Target {target} ({ip}) appears to be behind Cloudflare.")
            else:
                print(f"  [-] No obvious Cloudflare signature in IP: {ip}")
        except:
            pass

        # 4. Directory Brute (Simulated small list)
        print(f"\n[4] Common Directory Check:")
        common_paths = ['/admin', '/login', '/api', '/v1', '/.env', '/config.php', '/wp-admin']
        for path in common_paths:
            try:
                url = f"https://{target}{path}"
                resp = requests.get(url, timeout=2, verify=False)
                if resp.status_code != 404:
                    print(f"  [+] Potential path found: {url} (Status: {resp.status_code})")
            except:
                continue

        print("\nScan completed. Max vectors evaluated.")
