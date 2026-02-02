from core.base_module import BaseModule
import requests
import json
import concurrent.futures

class OSINT(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "osint"
        self.description = "Advanced OSINT module for username and domain discovery."
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def check_platform(self, name, url_template, target):
        url = url_template.format(target)
        try:
            resp = requests.get(url, headers=self.headers, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                # Some sites return 200 even if user not found, need better check
                if name == "Reddit" and "user not found" in resp.text.lower():
                    return None
                if name == "Twitter" and "this account doesn't exist" in resp.text.lower():
                    return None
                return url
        except:
            pass
        return None

    def run(self, args):
        if not args:
            print("Usage: use osint <username>")
            return
        
        target = args[0]
        self.log(f"Starting comprehensive OSINT search on: {target}")
        
        platforms = {
            "GitHub": "https://github.com/{}",
            "Twitter": "https://twitter.com/{}",
            "Instagram": "https://instagram.com/{}",
            "Reddit": "https://reddit.com/user/{}",
            "Steam": "https://steamcommunity.com/id/{}",
            "YouTube": "https://youtube.com/@{}",
            "Pinterest": "https://pinterest.com/{}",
            "SoundCloud": "https://soundcloud.com/{}",
            "Twitch": "https://twitch.tv/{}",
            "Telegram": "https://t.me/{}",
            "Medium": "https://medium.com/@{}",
            "Behance": "https://www.behance.net/{}",
            "Dribbble": "https://dribbble.com/{}",
            "About.me": "https://about.me/{}"
        }
        
        results = {}
        print(f"[*] Scanning {len(platforms)} platforms for '{target}'...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_platform = {executor.submit(self.check_platform, name, url, target): name for name, url in platforms.items()}
            for future in concurrent.futures.as_completed(future_to_platform):
                name = future_to_platform[future]
                try:
                    url = future.result()
                    if url:
                        print(f"  [+] \033[92mFOUND\033[0m on {name}: {url}")
                        results[name] = url
                    else:
                        # Optional: print not found for verbosity
                        pass
                except Exception as e:
                    self.log(f"Error checking {name}: {str(e)}", "error")

        if not results:
            print("[-] No profiles found across common platforms.")
        else:
            print(f"\n[+] Search complete. Found {len(results)} profiles.")
            # Save results
            with open(f"osint_{target}.json", "w") as f:
                json.dump(results, f, indent=4)
            print(f"[*] Detailed results saved to osint_{target}.json")
