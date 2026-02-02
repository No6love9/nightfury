import os
import sys
import time
import json
import random
import urllib.parse
import requests
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path
from core.base_module import BaseModule

class GoogleDorkEngine(BaseModule):
    """Advanced Google Dorking with OPSEC-aware queries and execution capabilities"""
    
    # Comprehensive dork templates organized by category
    DORK_TEMPLATES = {
        'sensitive_files': [
            'site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx',
            'site:{domain} ext:sql | ext:db | ext:mdb',
            'site:{domain} ext:log | ext:txt | ext:conf | ext:config',
            'site:{domain} ext:bak | ext:backup | ext:old | ext:save',
            'site:{domain} ext:env | ext:ini | ext:cfg',
            'site:{domain} filetype:xml inurl:sitemap',
            'site:{domain} filetype:json',
            'site:{domain} ext:csv | ext:dat',
            'site:{domain} intext:"private key" | intext:"BEGIN RSA PRIVATE KEY"',
            'site:{domain} intext:"client_secret" | intext:"oauth_token"'
        ],
        
        'credentials': [
            'site:{domain} intext:"password" | intext:"passwd" | intext:"pwd"',
            'site:{domain} intext:"username" | intext:"user" | intext:"login"',
            'site:{domain} intext:"api key" | intext:"api_key" | intext:"apikey"',
            'site:{domain} intext:"secret" | intext:"token" | intext:"auth"',
            'site:{domain} inurl:admin | inurl:login | inurl:signin',
            'site:{domain} intext:"DB_PASSWORD" | intext:"DB_USERNAME"',
            'site:{domain} filetype:env "DB_PASSWORD"',
            'site:{domain} ext:sql intext:INSERT INTO',
            'site:{domain} intext:"jira_password" | intext:"confluence_password"'
        ],
        
        'vulnerabilities': [
            'site:{domain} inurl:php?id= | inurl:asp?id= | inurl:jsp?id=',
            'site:{domain} inurl:".php?cat=" | inurl:".php?page="',
            'site:{domain} intext:"sql syntax near" | intext:"mysql_fetch"',
            'site:{domain} intext:"Warning: mysql" | intext:"MySQL Error"',
            'site:{domain} intext:"error in your SQL syntax"',
            'site:{domain} inurl:upload | inurl:file | inurl:download',
            'site:{domain} inurl:admin/upload | inurl:admin/file',
            'site:{domain} intitle:"index of" "parent directory"',
            'site:{domain} intext:"powered by WordPress" | intext:"Joomla!" | intext:"Drupal"',
            'site:{domain} intext:"version" | intext:"build" filetype:txt'
        ],
        
        'subdomains': [
            'site:*.{domain}',
            'site:*.*.{domain}',
            'inurl:{domain} -www',
            'site:{domain} -www',
            'inurl:app.{domain} | inurl:dev.{domain} | inurl:test.{domain}'
        ],
        
        'emails': [
            'site:{domain} intext:"@{domain}"',
            'site:{domain} "email" | "e-mail" | "contact"',
            'site:{domain} intext:"@" -inurl:mailto',
            'site:{domain} intext:"email address" | intext:"contact us"'
        ],
        
        'technologies': [
            'site:{domain} "powered by" | "built with" | "running"',
            'site:{domain} inurl:wp-content | inurl:wp-includes',
            'site:{domain} inurl:joomla | inurl:drupal',
            'site:{domain} intext:"Apache" | intext:"nginx" | intext:"IIS"',
            'site:{domain} inurl:.git | inurl:.svn | inurl:.env',
            'site:{domain} intext:"React" | intext:"Angular" | intext:"Vue.js"'
        ],
        
        'directories': [
            'site:{domain} intitle:"index of" "parent directory"',
            'site:{domain} intitle:"index of" backup',
            'site:{domain} intitle:"index of" config',
            'site:{domain} intitle:"index of" admin',
            'site:{domain} intitle:"index of" password',
            'site:{domain} intitle:"index of" logs'
        ],
        
        'social_media': [
            'site:linkedin.com "{domain}"',
            'site:twitter.com "{domain}"',
            'site:facebook.com "{domain}"',
            'site:github.com "{domain}"',
            'site:pastebin.com "{domain}"',
            'site:reddit.com "{domain}"'
        ],
        
        'cloud_storage': [
            'site:s3.amazonaws.com "{domain}"',
            'site:blob.core.windows.net "{domain}"',
            'site:storage.googleapis.com "{domain}"',
            'site:digitaloceanspaces.com "{domain}"',
            'site:drive.google.com intext:"{domain}"'
        ],
        
        'employee_info': [
            'site:linkedin.com intitle:"{domain}" "current" | "former"',
            'site:{domain} intext:"employee" | intext:"staff" | intext:"team"',
            'site:{domain} inurl:about | inurl:team | inurl:contact',
            'site:{domain} intext:"@gmail.com" | intext:"@yahoo.com"'
        ],
    }
    
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "google_dorking"
        self.description = "Advanced Google Dorking module for automated recon."
        self.output_dir = Path("/home/ubuntu/nightfury/data/exports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
        ]
    
    def generate_dorks(self, domain: str, categories: Optional[List[str]] = None) -> List[Dict[str, str]]:
        if categories is None:
            categories = list(self.DORK_TEMPLATES.keys())
        
        dorks = []
        for category in categories:
            if category not in self.DORK_TEMPLATES:
                continue
            
            templates = self.DORK_TEMPLATES[category]
            for template in templates:
                dork_query = template.format(domain=domain)
                dorks.append({
                    'category': category,
                    'query': dork_query,
                    'url': f"https://www.google.com/search?q={urllib.parse.quote_plus(dork_query)}"
                })
        return dorks
    
    def execute_dorks(self, domain: str, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        all_dorks = self.generate_dorks(domain, categories)
        executed_results = []

        self.log(f"Executing {len(all_dorks)} Google dorks for {domain}...")

        for dork_info in all_dorks:
            query = dork_info['query']
            self.log(f"Running dork: {query}")
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                search_url = dork_info['url']
                
                # Perform a real request
                resp = requests.get(search_url, headers=headers, timeout=10)
                
                # Extract potential results from the HTML (simplified)
                found_links = re.findall(r'href="/url\?q=(https?://[^&]+)', resp.text)
                
                executed_results.append({
                    'dork_query': query,
                    'category': dork_info['category'],
                    'status_code': resp.status_code,
                    'links': found_links[:5] # Top 5 links
                })
                # Random delay to avoid CAPTCHA
                time.sleep(random.uniform(2, 5))
            except Exception as e:
                self.log(f"Error executing dork '{query}': {e}", "error")
                executed_results.append({
                    'dork_query': query,
                    'category': dork_info['category'],
                    'error': str(e),
                    'links': []
                })
        
        self.results.extend(executed_results)
        return executed_results

    def run(self, args):
        if not args:
            print("Usage: use google_dorking <domain> [category]")
            return
        
        domain = args[0]
        category = [args[1]] if len(args) > 1 else None
        
        print(f"[*] Starting Google Dorking for: {domain}")
        results = self.execute_dorks(domain, category)
        
        print(f"\n[+] Dorking complete. Found results for {len([r for r in results if r['links']])} queries.")
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"dorks_{domain}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[*] Results saved to {filename}")

import re # Needed for re.findall
