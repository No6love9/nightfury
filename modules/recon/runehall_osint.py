from core.base_module import BaseModule
import requests
import re
from bs4 import BeautifulSoup
import json
import time

class RunehallOSINT(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "runehall_osint"
        self.description = "Professional OSINT module for Runehall.com usernames and profiles."
        self.base_url = "https://runehall.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def get_user_stats(self, user_id):
        """Fetches and parses user stats from Runehall."""
        url = f"{self.base_url}/?view=user-stats&id={user_id}"
        self.log(f"Fetching stats for User ID: {user_id}")
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                self.log(f"Error: Received status code {response.status_code}", "error")
                return None

            # Parse page for user information
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract data from the user profile page
            stats = {
                "user_id": user_id,
                "profile_url": url,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }

            # Look for username in title or header
            username_tag = soup.find('h1') or soup.find('title')
            if username_tag:
                stats["username"] = username_tag.text.strip().split(' ')[0]

            # Look for specific stat elements (common patterns for gaming sites)
            # These selectors are based on typical Runehall-style layout
            for row in soup.find_all(['div', 'tr'], class_=re.compile(r'stat|info|profile')):
                label = row.find(['span', 'td', 'label'], class_=re.compile(r'label|title|name'))
                value = row.find(['span', 'td', 'div'], class_=re.compile(r'value|data|amount'))
                if label and value:
                    key = label.text.strip().lower().replace(' ', '_')
                    stats[key] = value.text.strip()

            # Look for JSON data in scripts as a fallback/enhancement
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    if 'window.__INITIAL_STATE__' in script.string:
                        match = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.*?});', script.string)
                        if match:
                            try:
                                state = json.loads(match.group(1))
                                stats["raw_state"] = state
                            except:
                                pass
                    
                    # Also look for API-like data patterns
                    api_match = re.search(r'var\s+userData\s*=\s*({.*?});', script.string)
                    if api_match:
                        try:
                            stats["user_data"] = json.loads(api_match.group(1))
                        except:
                            pass
            
            return stats

        except Exception as e:
            self.log(f"Exception during stats fetch: {str(e)}", "error")
            return None

    def search_username(self, username):
        """Searches for a username and tries to find its ID."""
        self.log(f"Searching for username: {username}")
        
        # Method 1: Direct profile link check
        search_url = f"{self.base_url}/a/{username}"
        try:
            resp = requests.get(search_url, headers=self.headers, allow_redirects=True, timeout=10)
            if resp.status_code == 200:
                # Extract ID from the redirected URL or page content
                match = re.search(r'id=(\d+)', resp.url)
                if not match:
                    match = re.search(r'user-stats&id=(\d+)', resp.text)
                
                if match:
                    user_id = match.group(1)
                    self.log(f"Found User ID for {username}: {user_id}")
                    return self.get_user_stats(user_id)
            
            # Method 2: Search via internal search if available
            # Some sites use /search?q=...
            search_api = f"{self.base_url}/api/search/users?q={username}"
            api_resp = requests.get(search_api, headers=self.headers, timeout=5)
            if api_resp.status_code == 200:
                data = api_resp.json()
                if data and isinstance(data, list) and len(data) > 0:
                    user_id = data[0].get('id')
                    if user_id:
                        return self.get_user_stats(user_id)

            self.log(f"User {username} not found via direct link or search API.")
            return None
        except Exception as e:
            self.log(f"Error searching username: {str(e)}", "error")
            return None

    def run(self, args):
        if not args:
            print("Usage: use runehall_osint <username|id>")
            return

        target = args[0]
        print(f"[*] Initiating OSINT scan for: {target}")
        
        if target.isdigit():
            results = self.get_user_stats(target)
        else:
            results = self.search_username(target)

        if results:
            print("\n[+] Runehall OSINT Results:")
            print("=" * 30)
            for k, v in results.items():
                if k != "raw_state" and k != "user_data":
                    print(f"  {k.replace('_', ' ').title()}: {v}")
            
            # Save results
            filename = f"runehall_osint_{target}.json"
            with open(filename, "w") as f:
                json.dump(results, f, indent=4)
            print(f"\n[*] Full data saved to {filename}")
        else:
            print(f"[!] No data found for {target}")
