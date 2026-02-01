from core.base_module import BaseModule
import requests
import json

class OSINT(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "osint"
        self.description = "Perform OSINT searches on usernames or domains."

    def run(self, args):
        if not args:
            print("Usage: use osint <username|domain>")
            return
        
        target = args[0]
        self.log(f"Starting OSINT search on {target}...")
        
        # Simulated OSINT check for common platforms
        platforms = {
            "GitHub": f"https://github.com/{target}",
            "Twitter": f"https://twitter.com/{target}",
            "Instagram": f"https://instagram.com/{target}",
            "Reddit": f"https://reddit.com/user/{target}"
        }
        
        print(f"Checking availability for: {target}")
        for name, url in platforms.items():
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    print(f"  [+] Found on {name}: {url}")
                else:
                    print(f"  [-] Not found on {name}")
            except:
                print(f"  [!] Error checking {name}")
