import os
import sys
import time
import json
import random
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path

# Assuming a search tool is available for execution
# from tools import search # Placeholder for actual search tool integration

class GoogleDorkEngine:
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
            'site:{domain} intext:"@gmail.com" | intext:"@yahoo.com"' # Looking for personal emails on corporate sites
        ],

        'development_artifacts': [
            'site:{domain} inurl:.git/config | inurl:.svn/entries',
            'site:{domain} inurl:wp-config.php.bak | inurl:web.config.bak',
            'site:{domain} intext:"dump.sql" | intext:"database.sql" filetype:sql'
        ],

        'exposed_apis': [
            'site:{domain} inurl:api | inurl:rest | inurl:graphql',
            'site:{domain} intext:"swagger ui" | intext:"openapi"',
            'site:{domain} intext:"api_key" | intext:"token" filetype:json | filetype:txt'
        ]
    }
    
    def __init__(self, output_dir: str = "/home/ubuntu/nightfury/data/exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
        ]
    
    def generate_dorks(
        self,
        domain: str,
        categories: Optional[List[str]] = None
    ) -> List[Dict[str, str]]:
        """
        Generate Google dork queries for a domain
        
        Args:
            domain: Target domain
            categories: Specific categories to generate (None = all)
            
        Returns:
            List of dork queries with metadata
        """
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
                    'url': self._build_google_url(dork_query),
                    'encoded_url': self._build_google_url(dork_query, encode=True)
                })
        
        return dorks
    
    def _build_google_url(self, query: str, encode: bool = False) -> str:
        """Build Google search URL"""
        if encode:
            query = urllib.parse.quote_plus(query)
        return f"https://www.google.com/search?q={query}"
    
    def execute_dorks(self, domain: str, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Executes generated Google dorks and collects results using the search tool.
        
        Args:
            domain: Target domain.
            categories: Specific categories of dorks to execute (None = all).
            
        Returns:
            A list of dictionaries, each containing dork query and search results.
        """
        all_dorks = self.generate_dorks(domain, categories)
        executed_results = []

        print(f"[*] Executing {len(all_dorks)} Google dorks for {domain}...")

        for dork_info in all_dorks:
            query = dork_info['query']
            print(f"    - Running dork: {query}")
            try:
                # Integration with search engine (simulated via requests for this module)
                # In a real operational environment, this would use the framework's search tool
                headers = {'User-Agent': random.choice(self.user_agents)}
                search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
                
                # We perform a real request to check for connectivity and basic results
                # Note: In a real red-team scenario, we'd use proxies to avoid CAPTCHAs
                resp = requests.get(search_url, headers=headers, timeout=10)
                
                executed_results.append({
                    'dork_query': query,
                    'category': dork_info['category'],
                    'status_code': resp.status_code,
                    'results': [f"Found {len(resp.text)} bytes of data"] if resp.status_code == 200 else []
                })
                time.sleep(random.uniform(1, 3)) # Simulate delay for opsec
            except Exception as e:
                print(f"[!] Error executing dork '{query}': {e}")
                executed_results.append({
                    'dork_query': query,
                    'category': dork_info['category'],
                    'error': str(e),
                    'results': []
                })
        
        self.results.extend(executed_results)
        return executed_results

    def export_dorks(
        self,
        domain: str,
        categories: Optional[List[str]] = None,
        format: str = 'txt'
    ) -> str:
        """
        Export dork queries to file
        
        Args:
            domain: Target domain
            categories: Categories to include
            format: Output format (txt, json, csv)
            
        Returns:
            Path to exported file
        """
        dorks = self.generate_dorks(domain, categories)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"dorks_{domain}_{timestamp}.{format}"
        output_path = self.output_dir / filename
        
        if format == 'txt':
            self._export_txt(dorks, output_path)
        elif format == 'json':
            self._export_json(dorks, output_path)
        elif format == 'csv':
            self._export_csv(dorks, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return str(output_path)
    
    def _export_txt(self, dorks: List[Dict], output_path: Path) -> None:
        """Export dorks to text file"""
        with open(output_path, 'w') as f:
            f.write(f"# Google Dorks Generated: {datetime.now()}\n")
            f.write(f"# Total Queries: {len(dorks)}\n\n")
            
            current_category = None
            for dork in dorks:
                if dork['category'] != current_category:
                    current_category = dork['category']
                    f.write(f"\n## {current_category.upper().replace('_', ' ')}\n\n")
                
                f.write(f"{dork['query']}\n")
                f.write(f"URL: {dork['url']}\n\n")
    
    def _export_json(self, dorks: List[Dict], output_path: Path) -> None:
        """Export dorks to JSON file"""
        data = {
            'generated_at': datetime.now().isoformat(),
            'total_queries': len(dorks),
            'dorks': dorks
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _export_csv(self, dorks: List[Dict], output_path: Path) -> None:
        """Export dorks to CSV file"""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['category', 'query', 'url'])
            writer.writeheader()
            writer.writerows(dorks)
    
    def get_dork_statistics(self, domain: str) -> Dict[str, Any]:
        """
        Get statistics about generated dorks
        """
        dorks = self.generate_dorks(domain)
        
        category_counts = {}
        for dork in dorks:
            cat = dork['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return {
            'total_dorks': len(dorks),
            'categories': len(category_counts),
            'dorks_per_category': category_counts,
            'domain': domain
        }

if __name__ == "__main__":
    engine = GoogleDorkEngine()
    test_domain = "example.com"
    print(f"[*] Generating dorks for {test_domain}...")
    generated_dorks = engine.generate_dorks(test_domain)
    print(f"[+] Generated {len(generated_dorks)} dorks.")
    # for dork in generated_dorks:
    #     print(f"  - {dork['category']}: {dork['query']}")

    print(f"\n[*] Executing dorks for {test_domain}...")
    executed_results = engine.execute_dorks(test_domain)
    print(f"[+] Executed {len(executed_results)} dorks.")
    # for result in executed_results:
    #     print(f"  - Dork: {result['dork_query']}")
    #     print(f"    Results: {len(result['results'])} items")

    # Export results
    export_path_json = engine.export_dorks(test_domain, format='json')
    print(f"[+] Dorks exported to: {export_path_json}")
    export_path_txt = engine.export_dorks(test_domain, format='txt')
    print(f"[+] Dorks exported to: {export_path_txt}")
