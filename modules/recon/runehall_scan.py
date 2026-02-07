from core.base_module import BaseModule
from utils.polymorphic_wrapper import PolymorphicWrapper
import requests
import json
import time
import socket
from .runehall_osint import RunehallOSINT
from .dir_brute import DirBrute

@PolymorphicWrapper.wrap_module
@PolymorphicWrapper.wrap_module
class RunehallScan(BaseModule):
    """
    Advanced Runehall Infrastructure Scanner.
    Combines Subdomain Discovery, OSINT, and Directory Brute-forcing.
    """
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "runehall_scan"
        self.description = "Unified scanner for Runehall targets (Subdomains + OSINT + Infra)."
        self.options = {
            "domain": "runehall.com",
            "username": "",
            "threads": 10,
            "depth": "standard"
        }

    def run(self, args):
        domain = self.options["domain"]
        username = self.options["username"]
        
        if args:
            if "." in args[0]:
                domain = args[0]
            else:
                username = args[0]

        self.log(f"Starting unified scan on {domain}...")
        
        # 1. Subdomain Discovery
        print(f"\n[*] Phase 1: Subdomain Discovery ({domain})")
        subdomains = ["api", "play", "secure", "dev", "staging", "cdn", "ws", "admin", "db", "mail", "vpn", "portal", "test"]
        found_subs = []
        for sub in subdomains:
            target = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                print(f"  [+] Found: {target:20} -> {ip}")
                found_subs.append({"domain": target, "ip": ip})
            except socket.gaierror:
                continue
        
        # 2. Infrastructure Recon (on main domain)
        print(f"\n[*] Phase 2: Directory Brute-force (https://{domain})")
        brute = DirBrute(self.framework)
        brute.options["target"] = f"https://{domain}"
        brute.options["threads"] = self.options["threads"]
        infra_results = brute.brute_force()
        
        # 3. User Recon (if username provided)
        user_results = None
        if username:
            print(f"\n[*] Phase 3: User Intelligence ({username})")
            osint = RunehallOSINT(self.framework)
            user_results = osint.search_username(username)
        
        # 4. Report Generation
        self.generate_unified_report(domain, username, found_subs, infra_results, user_results)

    def generate_unified_report(self, domain, username, subs, infra, user):
        print("\n" + "="*60)
        print(f"RUNEHALL UNIFIED SCAN REPORT - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        print(f"\n[+] Target Domain: {domain}")
        print(f"    - Subdomains identified: {len(subs)}")
        for sub in subs[:5]:
            print(f"      > {sub['domain']} ({sub['ip']})")
        
        print(f"\n[+] Infrastructure Analysis:")
        if infra:
            print(f"    - Found {len(infra)} accessible directories/files")
            for url, status in infra[:5]:
                print(f"      > {url} ({status})")
        else:
            print("    - No significant directories found.")
            
        if username:
            print(f"\n[+] User Intelligence: {username}")
            if user:
                print(f"    - User ID: {user.get('user_id', 'Unknown')}")
                print(f"    - Profile: {user.get('profile_url', 'N/A')}")
                for k, v in user.items():
                    if k not in ['user_id', 'profile_url', 'raw_state', 'user_data', 'timestamp', 'username']:
                        print(f"    - {k.replace('_', ' ').title()}: {v}")
            else:
                print("    - User not found or profile is private.")
        
        print("\n" + "="*60)
        
        # Save unified report
        report = {
            "domain": domain,
            "username": username,
            "timestamp": time.time(),
            "subdomains": subs,
            "infrastructure": infra,
            "user_data": user
        }
        
        filename = f"unified_scan_{domain}_{int(time.time())}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[*] Unified report saved to {filename}")
