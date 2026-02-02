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

            # Since the site is dynamic, we might need to parse the initial state or use a better approach.
            # However, often these sites include initial data in a <script> tag.
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for JSON data in scripts
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and 'window.__INITIAL_STATE__' in script.string:
                    # Extract JSON
                    match = re.search(r'window\.__INITIAL_STATE__\s*=\s*({.*?});', script.string)
                    if match:
                        return json.loads(match.group(1))
            
            # If not found in initial state, it might be purely client-side.
            # In a real "professional" tool, we'd use the internal API.
            # Based on my research, the stats are likely available via an API endpoint.
            
            return {"status": "manual_check_required", "url": url}

        except Exception as e:
            self.log(f"Exception during stats fetch: {str(e)}", "error")
            return None

    def search_username(self, username):
        """Searches for a username and tries to find its ID."""
        self.log(f"Searching for username: {username}")
        # In Runehall, usernames are often mapped to IDs.
        # We can try to find the user by scraping the Hall of Fame or other public lists.
        # For a dedicated tool, we can also check if the username is currently in chat.
        
        # Placeholder for real search logic - let's make it effective.
        # We can use the 'a' endpoint if we find how it works.
        search_url = f"{self.base_url}/a/{username}"
        try:
            resp = requests.get(search_url, headers=self.headers, allow_redirects=True, timeout=10)
            if resp.status_code == 200:
                # Extract ID from the redirected URL or page content
                # e.g., https://runehall.com/a/Username?view=user-stats&id=12345
                match = re.search(r'id=(\d+)', resp.url)
                if match:
                    user_id = match.group(1)
                    self.log(f"Found User ID for {username}: {user_id}")
                    return self.get_user_stats(user_id)
            
            self.log(f"User {username} not found via direct link.")
            return None
        except Exception as e:
            self.log(f"Error searching username: {str(e)}", "error")
            return None

    def run(self, args):
        if not args:
            print("Usage: use runehall_osint <username|id>")
            return

        target = args[0]
        if target.isdigit():
            results = self.get_user_stats(target)
        else:
            results = self.search_username(target)

        if results:
            print(json.dumps(results, indent=4))
        else:
            print(f"[!] No data found for {target}")
