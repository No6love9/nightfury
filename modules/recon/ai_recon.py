import requests
import json
import os
import socket
from core.base_module import BaseModule
from utils.polymorphic_wrapper import PolymorphicWrapper

@PolymorphicWrapper.wrap_module
@PolymorphicWrapper.wrap_module
class AIRecon(BaseModule):
    """
    AI-Driven Reconnaissance Module.
    Uses LLM-based analysis to prioritize targets and identify vulnerabilities.
    """
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "ai_recon"
        self.description = "AI-powered target analysis and vulnerability prioritization."
        self.api_key = os.getenv("OPENAI_API_KEY")

    def run(self, args):
        if not args:
            print("Usage: use ai_recon <target_domain>")
            return
        
        target = args[0]
        self.log(f"Starting AI-driven recon on {target}...")
        
        # 1. Gather basic data
        basic_data = self._gather_basic_data(target)
        
        # 2. Analyze with AI
        analysis = self._analyze_with_ai(basic_data)
        
        # 3. Report findings
        self._report_findings(target, analysis)

    def _gather_basic_data(self, target):
        """Gathers initial data for AI analysis."""
        data = {
            "domain": target,
            "subdomains": [],
            "technologies": [],
            "open_ports": []
        }
        
        try:
            data["ip"] = socket.gethostbyname(target)
            # Add common subdomains to check
            common = ['www', 'api', 'dev', 'staging', 'vpn', 'mail']
            for sub in common:
                try:
                    socket.gethostbyname(f"{sub}.{target}")
                    data["subdomains"].append(f"{sub}.{target}")
                except:
                    pass
        except:
            pass
            
        return data

    def _analyze_with_ai(self, data):
        """Sends gathered data to an LLM for strategic analysis."""
        if not self.api_key:
            self.log("OpenAI API key not found. Using local heuristic analysis.", "warning")
            return self._heuristic_analysis(data)

        prompt = f"""
        Analyze the following reconnaissance data for security vulnerabilities and prioritize attack vectors.
        Provide a structured report with:
        1. Potential Vulnerabilities
        2. Priority Level (High/Medium/Low)
        3. Recommended Attack Vectors
        4. Next Steps for Reconnaissance
        
        Data: {json.dumps(data)}
        """
        
        try:
            from openai import OpenAI
            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": "You are an expert red team security analyst."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            self.log(f"AI analysis failed: {e}", "error")
            return self._heuristic_analysis(data)

    def _heuristic_analysis(self, data):
        """Fallback heuristic analysis."""
        priority = "HIGH" if any(sub in str(data['subdomains']) for sub in ['dev', 'staging', 'api']) else "MEDIUM"
        analysis = f"Heuristic Analysis for {data['domain']}:\n"
        analysis += f"- Priority: {priority}\n"
        analysis += f"- Identified IP: {data.get('ip', 'Unknown')}\n"
        analysis += f"- Subdomains Found: {', '.join(data['subdomains']) if data['subdomains'] else 'None'}\n"
        analysis += "- Recommendations: Focus on discovered subdomains and check for common web vulnerabilities (XSS, SQLi)."
        return analysis

    def _report_findings(self, target, analysis):
        print(f"\n--- AI Reconnaissance Report: {target} ---")
        print(analysis)
        print("-" * 40)
        
        # Save report
        filename = f"ai_report_{target}.txt"
        with open(filename, "w") as f:
            f.write(analysis)
        print(f"[*] AI Report saved to {filename}")
