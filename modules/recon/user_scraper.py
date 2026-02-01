import requests
import re
from bs4 import BeautifulSoup
import json
import os

class UserScraper:
    """
    Stealthy Username Scraper for runehall.com.
    Uses pattern matching and metadata extraction to identify potential usernames.
    """
    def __init__(self, domain="runehall.com"):
        self.domain = domain
        self.base_url = f"https://{domain}"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]

    def scrape_users(self):
        """
        Scrapes the target domain for potential usernames.
        Focuses on common patterns like author pages, comments, and profile links.
        """
        print(f"[*] Starting stealthy username scraping for: {self.domain}")
        usernames = set()
        
        try:
            headers = {"User-Agent": self.user_agents[0]}
            response = requests.get(self.base_url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 1. Look for common author/user patterns in links
                # e.g., /author/username, /user/username, /profile/username
                patterns = [r'/author/([^/]+)', r'/user/([^/]+)', r'/profile/([^/]+)']
                for link in soup.find_all('a', href=True):
                    for pattern in patterns:
                        match = re.search(pattern, link['href'])
                        if match:
                            usernames.add(match.group(1))
                
                # 2. Look for common username attributes in HTML
                for tag in soup.find_all(attrs={"class": re.compile(r'user|author|username', re.I)}):
                    text = tag.get_text().strip()
                    if text and len(text) < 20 and ' ' not in text:
                        usernames.add(text.lower())

        except Exception as e:
            print(f"[!] Error during scraping: {str(e)}")

        return sorted(list(usernames))

if __name__ == "__main__":
    scraper = UserScraper()
    found = scraper.scrape_users()
    print(f"[+] Found {len(found)} potential usernames.")
    for user in found:
        print(f"  - {user}")
