#!/usr/bin/env python3
"""
NightFury Reporting & Analysis Engine
Automated data collection, analysis, and report generation
Version: 2.0 - Advanced analytics and insights
"""

import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
import statistics

class ReportingEngine:
    """Advanced reporting and analysis engine"""
    
    def __init__(self, data_dir: str = "./nightfury_reports"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.operations = []
        self.findings_db = []
        self.load_operations()
    
    def load_operations(self) -> None:
        """Load all operations from disk"""
        for file in self.data_dir.glob("operation_*.json"):
            try:
                with open(file, 'r') as f:
                    operation = json.load(f)
                    self.operations.append(operation)
                    self.findings_db.extend(operation.get("findings", []))
            except Exception as e:
                print(f"[!] Error loading {file}: {e}")
    
    def analyze_findings(self) -> Dict:
        """Analyze all findings"""
        if not self.findings_db:
            return {}
        
        analysis = {
            "total_findings": len(self.findings_db),
            "by_severity": self._analyze_by_severity(),
            "by_type": self._analyze_by_type(),
            "temporal_analysis": self._analyze_temporal(),
            "risk_score": self._calculate_risk_score(),
            "trends": self._analyze_trends(),
            "statistics": self._calculate_statistics()
        }
        
        return analysis
    
    def _analyze_by_severity(self) -> Dict:
        """Analyze findings by severity"""
        severity_counts = Counter(f["severity"] for f in self.findings_db)
        
        return {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
            "percentage": {
                "critical": (severity_counts.get("critical", 0) / len(self.findings_db)) * 100,
                "high": (severity_counts.get("high", 0) / len(self.findings_db)) * 100,
                "medium": (severity_counts.get("medium", 0) / len(self.findings_db)) * 100,
                "low": (severity_counts.get("low", 0) / len(self.findings_db)) * 100,
                "info": (severity_counts.get("info", 0) / len(self.findings_db)) * 100
            }
        }
    
    def _analyze_by_type(self) -> Dict:
        """Analyze findings by type/category"""
        type_counts = Counter()
        
        for finding in self.findings_db:
            title = finding.get("title", "Unknown")
            category = self._categorize_finding(title)
            type_counts[category] += 1
        
        return dict(type_counts.most_common(10))
    
    def _categorize_finding(self, title: str) -> str:
        """Categorize a finding based on title"""
        title_lower = title.lower()
        
        categories = {
            "Authentication": ["auth", "login", "session", "token", "password"],
            "Injection": ["sql", "injection", "xss", "command", "ldap"],
            "Encryption": ["encryption", "ssl", "tls", "https", "crypto"],
            "Access Control": ["access", "permission", "privilege", "authorization"],
            "Information Disclosure": ["information", "disclosure", "leak", "exposed"],
            "Configuration": ["configuration", "misconfiguration", "config", "settings"],
            "Validation": ["validation", "input", "sanitization", "filter"],
            "Rate Limiting": ["rate", "limit", "throttle", "brute"],
            "Headers": ["header", "security", "x-frame", "csp"],
            "Other": []
        }
        
        for category, keywords in categories.items():
            if any(keyword in title_lower for keyword in keywords):
                return category
        
        return "Other"
    
    def _analyze_temporal(self) -> Dict:
        """Analyze findings over time"""
        temporal_data = defaultdict(int)
        
        for finding in self.findings_db:
            timestamp = finding.get("timestamp", "")
            if timestamp:
                date = timestamp.split("T")[0]
                temporal_data[date] += 1
        
        return dict(sorted(temporal_data.items()))
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        if not self.findings_db:
            return 0.0
        
        severity_scores = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1
        }
        
        total_score = sum(severity_scores.get(f["severity"], 0) for f in self.findings_db)
        max_score = 25 * len(self.findings_db)
        
        risk_score = min((total_score / max_score) * 100, 100)
        return round(risk_score, 2)
    
    def _analyze_trends(self) -> Dict:
        """Analyze trends in findings"""
        if len(self.operations) < 2:
            return {}
        
        trends = {
            "operations_count": len(self.operations),
            "avg_findings_per_operation": len(self.findings_db) / len(self.operations),
            "finding_growth": self._calculate_growth(),
            "most_common_issues": self._get_most_common_issues()
        }
        
        return trends
    
    def _calculate_growth(self) -> float:
        """Calculate finding growth rate"""
        if len(self.operations) < 2:
            return 0.0
        
        first_op_findings = len(self.operations[0].get("findings", []))
        last_op_findings = len(self.operations[-1].get("findings", []))
        
        if first_op_findings == 0:
            return 0.0
        
        growth = ((last_op_findings - first_op_findings) / first_op_findings) * 100
        return round(growth, 2)
    
    def _get_most_common_issues(self) -> List[str]:
        """Get most common issues"""
        titles = [f.get("title", "") for f in self.findings_db]
        title_counts = Counter(titles)
        return [title for title, _ in title_counts.most_common(5)]
    
    def _calculate_statistics(self) -> Dict:
        """Calculate statistical metrics"""
        if not self.findings_db:
            return {}
        
        severity_values = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        
        severity_nums = [severity_values.get(f["severity"], 0) for f in self.findings_db]
        
        return {
            "mean_severity": round(statistics.mean(severity_nums), 2),
            "median_severity": statistics.median(severity_nums),
            "std_dev": round(statistics.stdev(severity_nums), 2) if len(severity_nums) > 1 else 0,
            "unique_issues": len(set(f.get("title", "") for f in self.findings_db))
        }
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        analysis = self.analyze_findings()
        
        if not analysis:
            return "No findings to analyze"
        
        severity = analysis.get("by_severity", {})
        risk_score = analysis.get("risk_score", 0)
        
        summary = f"""
EXECUTIVE SUMMARY
=================

Risk Score: {risk_score}/100

Finding Breakdown:
  - Critical: {severity.get('critical', 0)} ({severity.get('percentage', {}).get('critical', 0):.1f}%)
  - High: {severity.get('high', 0)} ({severity.get('percentage', {}).get('high', 0):.1f}%)
  - Medium: {severity.get('medium', 0)} ({severity.get('percentage', {}).get('medium', 0):.1f}%)
  - Low: {severity.get('low', 0)} ({severity.get('percentage', {}).get('low', 0):.1f}%)
  - Info: {severity.get('info', 0)} ({severity.get('percentage', {}).get('info', 0):.1f}%)

Total Findings: {analysis.get('total_findings', 0)}

Top Issues:
"""
        
        for i, issue in enumerate(analysis.get("trends", {}).get("most_common_issues", []), 1):
            summary += f"  {i}. {issue}\n"
        
        return summary
    
    def generate_detailed_report(self) -> str:
        """Generate detailed analysis report"""
        analysis = self.analyze_findings()
        
        report = f"""
NIGHTFURY DETAILED ANALYSIS REPORT
===================================

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

1. OVERVIEW
-----------
Total Operations: {len(self.operations)}
Total Findings: {analysis.get('total_findings', 0)}
Overall Risk Score: {analysis.get('risk_score', 0)}/100

2. SEVERITY DISTRIBUTION
------------------------
"""
        
        severity = analysis.get("by_severity", {})
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity.get(sev, 0)
            pct = severity.get("percentage", {}).get(sev, 0)
            report += f"{sev.upper():<10}: {count:>3} ({pct:>5.1f}%)\n"
        
        report += "\n3. FINDINGS BY CATEGORY\n"
        report += "-" * 24 + "\n"
        
        by_type = analysis.get("by_type", {})
        for category, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            report += f"{category:<25}: {count:>3}\n"
        
        report += "\n4. STATISTICS\n"
        report += "-" * 24 + "\n"
        
        stats = analysis.get("statistics", {})
        report += f"Mean Severity: {stats.get('mean_severity', 0)}\n"
        report += f"Median Severity: {stats.get('median_severity', 0)}\n"
        report += f"Std Deviation: {stats.get('std_dev', 0)}\n"
        report += f"Unique Issues: {stats.get('unique_issues', 0)}\n"
        
        report += "\n5. TRENDS\n"
        report += "-" * 24 + "\n"
        
        trends = analysis.get("trends", {})
        report += f"Avg Findings/Operation: {trends.get('avg_findings_per_operation', 0):.1f}\n"
        report += f"Finding Growth Rate: {trends.get('finding_growth', 0):.1f}%\n"
        
        return report
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        analysis = self.analyze_findings()
        
        severity = analysis.get("by_severity", {})
        by_type = analysis.get("by_type", {})
        stats = analysis.get("statistics", {})
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NightFury Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 32px;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric {{
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .metric-label {{
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h2 {{
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            color: #333;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f0f0f0;
            font-weight: bold;
            color: #333;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        .info {{ color: #1976d2; font-weight: bold; }}
        .chart {{
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .footer {{
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NightFury Analysis Report</h1>
            <p>Comprehensive Penetration Testing Analysis</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{analysis.get('total_findings', 0)}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value">{analysis.get('risk_score', 0)}</div>
                <div class="metric-label">Risk Score (0-100)</div>
            </div>
            <div class="metric">
                <div class="metric-value">{severity.get('critical', 0)}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="metric">
                <div class="metric-value">{len(self.operations)}</div>
                <div class="metric-label">Operations</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Severity Distribution</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                <tr>
                    <td><span class="critical">CRITICAL</span></td>
                    <td>{severity.get('critical', 0)}</td>
                    <td>{severity.get('percentage', {}).get('critical', 0):.1f}%</td>
                </tr>
                <tr>
                    <td><span class="high">HIGH</span></td>
                    <td>{severity.get('high', 0)}</td>
                    <td>{severity.get('percentage', {}).get('high', 0):.1f}%</td>
                </tr>
                <tr>
                    <td><span class="medium">MEDIUM</span></td>
                    <td>{severity.get('medium', 0)}</td>
                    <td>{severity.get('percentage', {}).get('medium', 0):.1f}%</td>
                </tr>
                <tr>
                    <td><span class="low">LOW</span></td>
                    <td>{severity.get('low', 0)}</td>
                    <td>{severity.get('percentage', {}).get('low', 0):.1f}%</td>
                </tr>
                <tr>
                    <td><span class="info">INFO</span></td>
                    <td>{severity.get('info', 0)}</td>
                    <td>{severity.get('percentage', {}).get('info', 0):.1f}%</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Findings by Category</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                </tr>
"""
        
        for category, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            html += f"                <tr><td>{category}</td><td>{count}</td></tr>\n"
        
        html += f"""
            </table>
        </div>
        
        <div class="section">
            <h2>Statistical Analysis</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Mean Severity</td>
                    <td>{stats.get('mean_severity', 0)}</td>
                </tr>
                <tr>
                    <td>Median Severity</td>
                    <td>{stats.get('median_severity', 0)}</td>
                </tr>
                <tr>
                    <td>Standard Deviation</td>
                    <td>{stats.get('std_dev', 0)}</td>
                </tr>
                <tr>
                    <td>Unique Issues</td>
                    <td>{stats.get('unique_issues', 0)}</td>
                </tr>
            </table>
        </div>
        
        <div class="footer">
            <p>NightFury Framework v2.0 | Professional Penetration Testing Platform</p>
            <p>This report is confidential and for authorized testing only.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def save_report(self, report_type: str = "html") -> str:
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report_type == "html":
            filename = f"analysis_report_{timestamp}.html"
            content = self.generate_html_report()
        elif report_type == "text":
            filename = f"analysis_report_{timestamp}.txt"
            content = self.generate_detailed_report()
        else:
            filename = f"analysis_report_{timestamp}.json"
            content = json.dumps(self.analyze_findings(), indent=2)
        
        filepath = self.data_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        return str(filepath)
    
    def export_findings(self, format: str = "json") -> str:
        """Export findings to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"findings_export_{timestamp}.{format}"
        filepath = self.data_dir / filename
        
        if format == "json":
            with open(filepath, 'w') as f:
                json.dump(self.findings_db, f, indent=2)
        elif format == "csv":
            import csv
            with open(filepath, 'w', newline='') as f:
                if self.findings_db:
                    writer = csv.DictWriter(f, fieldnames=self.findings_db[0].keys())
                    writer.writeheader()
                    writer.writerows(self.findings_db)
        
        return str(filepath)

def main():
    """Main entry point"""
    engine = ReportingEngine()
    
    print("\n" + "="*80)
    print("NIGHTFURY REPORTING & ANALYSIS ENGINE")
    print("="*80 + "\n")
    
    # Generate and display executive summary
    print(engine.generate_executive_summary())
    
    # Generate and save reports
    print("\n[*] Generating reports...")
    
    html_report = engine.save_report("html")
    print(f"[+] HTML report saved: {html_report}")
    
    text_report = engine.save_report("text")
    print(f"[+] Text report saved: {text_report}")
    
    json_report = engine.save_report("json")
    print(f"[+] JSON report saved: {json_report}")
    
    # Export findings
    print("\n[*] Exporting findings...")
    
    json_export = engine.export_findings("json")
    print(f"[+] JSON export saved: {json_export}")
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()
