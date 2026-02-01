import requests
import json
import os
from core.base_module import BaseModule

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
        
        # 1. Gather basic data (simulated for this implementation)
        basic_data = self._gather_basic_data(target)
        
        # 2. Analyze with AI
        analysis = self._analyze_with_ai(basic_data)
        
        # 3. Report findings
        self._report_findings(target, analysis)

    def _gather_basic_data(self, target):
        """Simulates gathering initial data for AI analysis."""
        return {
            "domain": target,
            "subdomains": [f"api.{target}", f"dev.{target}", f"vpn.{target}"],
            "technologies": ["Nginx", "React", "Cloudflare", "PHP 8.1"],
            "open_ports": [80, 443, 8080]
        }

    def _analyze_with_ai(self, data):
        """Sends gathered data to an LLM for strategic analysis."""
        if not self.api_key:
            self.log("OpenAI API key not found. Using local heuristic analysis.", "warning")
            return self._heuristic_analysis(data)

        prompt = f"Analyze the following reconnaissance data for security vulnerabilities and prioritize attack vectors: {json.dumps(data)}"
        
        try:
            from openai import OpenAI
            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            self.log(f"AI analysis failed: {e}", "error")
            return self._heuristic_analysis(data)

    def _heuristic_analysis(self, data):
        """Fallback heuristic analysis."""
        priority = "HIGH" if "dev" in str(data['subdomains']) else "MEDIUM"
        return f"Heuristic Analysis: Priority {priority}. Focus on outdated PHP versions and exposed dev subdomains."

    def _report_findings(self, target, analysis):
        print(f"\n--- AI Reconnaissance Report: {target} ---")
        print(analysis)
        print("-" * 40)
