#!/usr/bin/env python3
"""
NightFury Google Dorking Module
Advanced Google Dork queries for OSINT reconnaissance
"""

import os
import sys
import time
import json
import random
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path


class GoogleDorkEngine:
    """Advanced Google Dorking with OPSEC-aware queries"""
    
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
        ],
        
        'subdomains': [
            'site:*.{domain}',
            'site:*.*.{domain}',
            'inurl:{domain} -www',
            'site:{domain} -www',
        ],
        
        'emails': [
            'site:{domain} intext:"@{domain}"',
            'site:{domain} "email" | "e-mail" | "contact"',
            'site:{domain} intext:"@" -inurl:mailto',
        ],
        
        'technologies': [
            'site:{domain} "powered by" | "built with" | "running"',
            'site:{domain} inurl:wp-content | inurl:wp-includes',
            'site:{domain} inurl:joomla | inurl:drupal',
            'site:{domain} intext:"Apache" | intext:"nginx" | intext:"IIS"',
            'site:{domain} inurl:.git | inurl:.svn | inurl:.env',
        ],
        
        'directories': [
            'site:{domain} intitle:"index of" "parent directory"',
            'site:{domain} intitle:"index of" backup',
            'site:{domain} intitle:"index of" config',
            'site:{domain} intitle:"index of" admin',
            'site:{domain} intitle:"index of" password',
        ],
        
        'social_media': [
            'site:linkedin.com "{domain}"',
            'site:twitter.com "{domain}"',
            'site:facebook.com "{domain}"',
            'site:github.com "{domain}"',
            'site:pastebin.com "{domain}"',
        ],
        
        'cloud_storage': [
            'site:s3.amazonaws.com "{domain}"',
            'site:blob.core.windows.net "{domain}"',
            'site:storage.googleapis.com "{domain}"',
            'site:digitaloceanspaces.com "{domain}"',
        ],
        
        'employee_info': [
            'site:linkedin.com intitle:"{domain}" "current" | "former"',
            'site:{domain} intext:"employee" | intext:"staff" | intext:"team"',
            'site:{domain} inurl:about | inurl:team | inurl:contact',
        ],
        
        'documents': [
            'site:{domain} filetype:pdf "confidential" | "internal"',
            'site:{domain} filetype:doc "confidential" | "internal"',
            'site:{domain} filetype:xls "confidential" | "internal"',
            'site:{domain} filetype:ppt "confidential" | "internal"',
        ],
    }
    
    def __init__(self, output_dir: str = "/home/ubuntu/nightfury/data/exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[Dict[str, Any]] = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
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
    
    def generate_custom_dork(
        self,
        domain: str,
        keywords: List[str],
        operators: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate custom dork query
        
        Args:
            domain: Target domain
            keywords: Keywords to search for
            operators: Additional operators (inurl, intext, filetype, etc.)
            
        Returns:
            Custom dork query string
        """
        parts = [f'site:{domain}']
        
        # Add keywords
        if keywords:
            keyword_str = ' | '.join(f'"{kw}"' for kw in keywords)
            parts.append(f'({keyword_str})')
        
        # Add operators
        if operators:
            for op, value in operators.items():
                if op == 'filetype' or op == 'ext':
                    parts.append(f'{op}:{value}')
                elif op in ['inurl', 'intext', 'intitle']:
                    parts.append(f'{op}:"{value}"')
                else:
                    parts.append(f'{op}:{value}')
        
        return ' '.join(parts)
    
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
        """Get statistics about generated dorks"""
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
    
    def generate_report(self, domain: str, categories: Optional[List[str]] = None) -> str:
        """Generate comprehensive dork report"""
        dorks = self.generate_dorks(domain, categories)
        stats = self.get_dork_statistics(domain)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / f"dork_report_{domain}_{timestamp}.md"
        
        with open(report_path, 'w') as f:
            f.write(f"# Google Dork Report: {domain}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Statistics\n\n")
            f.write(f"- **Total Queries:** {stats['total_dorks']}\n")
            f.write(f"- **Categories:** {stats['categories']}\n\n")
            
            f.write("### Queries per Category\n\n")
            for cat, count in stats['dorks_per_category'].items():
                f.write(f"- **{cat.replace('_', ' ').title()}:** {count}\n")
            
            f.write("\n## Dork Queries\n\n")
            
            current_category = None
            for dork in dorks:
                if dork['category'] != current_category:
                    current_category = dork['category']
                    f.write(f"\n### {current_category.replace('_', ' ').title()}\n\n")
                
                f.write(f"**Query:**\n```\n{dork['query']}\n```\n\n")
                f.write(f"**Search URL:** [Click to search]({dork['url']})\n\n")
                f.write("---\n\n")
            
            f.write("\n## Usage Instructions\n\n")
            f.write("1. Copy the dork query\n")
            f.write("2. Paste into Google search\n")
            f.write("3. Review results manually\n")
            f.write("4. Document findings\n\n")
            
            f.write("## OPSEC Considerations\n\n")
            f.write("- Use VPN or proxy for searches\n")
            f.write("- Randomize user agent\n")
            f.write("- Add delays between queries\n")
            f.write("- Consider using Google Dorking tools\n")
            f.write("- Be aware of rate limiting\n\n")
            
            f.write("---\n")
            f.write("*Generated by NightFury OSINT Engine*\n")
        
        return str(report_path)


class AdvancedDorkBuilder:
    """Build complex dork queries with advanced operators"""
    
    def __init__(self):
        self.query_parts = []
    
    def site(self, domain: str) -> 'AdvancedDorkBuilder':
        """Add site operator"""
        self.query_parts.append(f'site:{domain}')
        return self
    
    def inurl(self, text: str) -> 'AdvancedDorkBuilder':
        """Add inurl operator"""
        self.query_parts.append(f'inurl:"{text}"')
        return self
    
    def intext(self, text: str) -> 'AdvancedDorkBuilder':
        """Add intext operator"""
        self.query_parts.append(f'intext:"{text}"')
        return self
    
    def intitle(self, text: str) -> 'AdvancedDorkBuilder':
        """Add intitle operator"""
        self.query_parts.append(f'intitle:"{text}"')
        return self
    
    def filetype(self, ext: str) -> 'AdvancedDorkBuilder':
        """Add filetype operator"""
        self.query_parts.append(f'filetype:{ext}')
        return self
    
    def ext(self, extensions: List[str]) -> 'AdvancedDorkBuilder':
        """Add multiple extensions with OR"""
        ext_str = ' | '.join(f'ext:{e}' for e in extensions)
        self.query_parts.append(f'({ext_str})')
        return self
    
    def exclude(self, term: str) -> 'AdvancedDorkBuilder':
        """Exclude term"""
        self.query_parts.append(f'-{term}')
        return self
    
    def or_terms(self, terms: List[str]) -> 'AdvancedDorkBuilder':
        """Add OR terms"""
        or_str = ' | '.join(f'"{t}"' for t in terms)
        self.query_parts.append(f'({or_str})')
        return self
    
    def and_terms(self, terms: List[str]) -> 'AdvancedDorkBuilder':
        """Add AND terms"""
        for term in terms:
            self.query_parts.append(f'"{term}"')
        return self
    
    def build(self) -> str:
        """Build final query"""
        return ' '.join(self.query_parts)
    
    def reset(self) -> 'AdvancedDorkBuilder':
        """Reset builder"""
        self.query_parts = []
        return self


def main():
    """CLI interface for Google Dorking"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='NightFury Google Dorking Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('domain', help='Target domain')
    parser.add_argument(
        '-c', '--categories',
        nargs='+',
        choices=list(GoogleDorkEngine.DORK_TEMPLATES.keys()),
        help='Specific categories to generate'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'json', 'csv'],
        default='txt',
        help='Output format'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output directory',
        default='/home/ubuntu/nightfury/data/exports'
    )
    parser.add_argument(
        '-r', '--report',
        action='store_true',
        help='Generate comprehensive report'
    )
    parser.add_argument(
        '-s', '--stats',
        action='store_true',
        help='Show statistics only'
    )
    
    args = parser.parse_args()
    
    engine = GoogleDorkEngine(output_dir=args.output)
    
    if args.stats:
        stats = engine.get_dork_statistics(args.domain)
        print(json.dumps(stats, indent=2))
        return
    
    if args.report:
        report_path = engine.generate_report(args.domain, args.categories)
        print(f"[+] Report generated: {report_path}")
    else:
        output_path = engine.export_dorks(args.domain, args.categories, args.format)
        print(f"[+] Dorks exported: {output_path}")
    
    # Show summary
    stats = engine.get_dork_statistics(args.domain)
    print(f"\n[+] Generated {stats['total_dorks']} dork queries")
    print(f"[+] Categories: {stats['categories']}")


if __name__ == '__main__':
    main()
