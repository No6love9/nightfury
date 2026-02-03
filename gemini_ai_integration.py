#!/usr/bin/env python3
"""
NightFury Gemini AI Integration
Google Gemini AI for advanced reconnaissance, analysis, and reporting
Version: 2.0 - Free AI-powered features
"""

import os
import json
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("[!] google-generativeai not installed. Install with: pip install google-generativeai")


class GeminiAIIntegration:
    """Integrates Google Gemini AI with NightFury framework"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Gemini AI integration
        
        Args:
            api_key: Google Gemini API key (or set GEMINI_API_KEY environment variable)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = "gemini-pro"
        self.client = None
        self.model = None
        self.conversation_history = []
        
        if not self.api_key:
            raise ValueError(
                "Gemini API key not provided. Set GEMINI_API_KEY environment variable "
                "or pass api_key parameter. Get free key at: https://aistudio.google.com/app/apikeys"
            )
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Gemini client"""
        if not GEMINI_AVAILABLE:
            raise ImportError("google-generativeai package required. Install with: pip install google-generativeai")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)
        self.client = genai.GenerativeModel(self.model_name)
    
    def analyze_findings(self, findings: List[Dict]) -> str:
        """
        Use Gemini to analyze security findings
        
        Args:
            findings: List of security findings
            
        Returns:
            Analysis from Gemini
        """
        if not findings:
            return "No findings to analyze"
        
        findings_summary = json.dumps(findings, indent=2)
        
        prompt = f"""
You are a professional cybersecurity analyst. Analyze the following security findings 
and provide a comprehensive assessment:

FINDINGS:
{findings_summary}

Please provide:
1. Summary of critical issues
2. Risk assessment
3. Recommended remediation steps
4. Priority ranking
5. Potential impact analysis
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error analyzing findings: {str(e)}"
    
    def generate_executive_summary(self, operation_data: Dict) -> str:
        """
        Generate executive summary using Gemini
        
        Args:
            operation_data: Operation data including findings
            
        Returns:
            Executive summary
        """
        prompt = f"""
You are a professional penetration testing report writer. Generate a concise executive 
summary for the following penetration test:

Operation: {operation_data.get('name', 'Unknown')}
Target: {operation_data.get('target', 'Unknown')}
Type: {operation_data.get('type', 'Unknown')}
Total Findings: {len(operation_data.get('findings', []))}

Findings Summary:
{json.dumps(operation_data.get('findings', [])[:5], indent=2)}

Generate a professional executive summary suitable for C-level management including:
1. Overview of assessment
2. Key findings
3. Risk rating
4. Recommended actions
5. Timeline for remediation
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating summary: {str(e)}"
    
    def generate_remediation_steps(self, finding: Dict) -> str:
        """
        Generate detailed remediation steps for a finding
        
        Args:
            finding: Security finding
            
        Returns:
            Remediation steps
        """
        prompt = f"""
You are a cybersecurity remediation expert. Provide detailed, step-by-step remediation 
guidance for the following security vulnerability:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Description: {finding.get('description', 'Unknown')}

Provide:
1. Immediate mitigation steps
2. Long-term remediation plan
3. Testing procedures to verify fix
4. Prevention measures
5. Tools and resources needed
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating remediation: {str(e)}"
    
    def analyze_attack_surface(self, target_info: Dict) -> str:
        """
        Analyze attack surface using Gemini
        
        Args:
            target_info: Information about target
            
        Returns:
            Attack surface analysis
        """
        prompt = f"""
You are a penetration testing expert. Analyze the attack surface for the following target:

Target: {target_info.get('target', 'Unknown')}
Services: {json.dumps(target_info.get('services', []))}
Infrastructure: {target_info.get('infrastructure', 'Unknown')}

Provide:
1. Identified attack vectors
2. High-risk areas
3. Recommended testing approach
4. Potential vulnerabilities to look for
5. Testing priority
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error analyzing attack surface: {str(e)}"
    
    def generate_exploit_suggestions(self, vulnerability: Dict) -> str:
        """
        Generate exploitation suggestions (for authorized testing only)
        
        Args:
            vulnerability: Vulnerability information
            
        Returns:
            Exploitation suggestions
        """
        prompt = f"""
You are a penetration testing expert providing guidance for authorized security testing.

Vulnerability: {vulnerability.get('title', 'Unknown')}
Type: {vulnerability.get('type', 'Unknown')}
Description: {vulnerability.get('description', 'Unknown')}

For authorized testing purposes, suggest:
1. Exploitation techniques
2. Tools that could be used
3. Expected outcomes
4. Detection evasion considerations
5. Post-exploitation steps

IMPORTANT: This guidance is for authorized security testing only.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating suggestions: {str(e)}"
    
    def chat(self, message: str) -> str:
        """
        Chat with Gemini about security topics
        
        Args:
            message: User message
            
        Returns:
            Gemini response
        """
        self.conversation_history.append({
            "role": "user",
            "content": message
        })
        
        try:
            response = self.model.generate_content(message)
            assistant_message = response.text
            
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })
            
            return assistant_message
        except Exception as e:
            return f"Error: {str(e)}"
    
    def analyze_log_file(self, log_content: str) -> str:
        """
        Analyze log files for security events
        
        Args:
            log_content: Log file content
            
        Returns:
            Log analysis
        """
        prompt = f"""
You are a security log analyst. Analyze the following logs for security events:

LOGS:
{log_content[:2000]}  # Limit to first 2000 chars

Identify:
1. Suspicious activities
2. Failed authentication attempts
3. Unusual patterns
4. Potential attacks
5. Recommended actions
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error analyzing logs: {str(e)}"
    
    def generate_compliance_report(self, findings: List[Dict], 
                                  compliance_standard: str = "OWASP") -> str:
        """
        Generate compliance-focused report
        
        Args:
            findings: Security findings
            compliance_standard: Compliance standard (OWASP, CIS, PCI-DSS, etc.)
            
        Returns:
            Compliance report
        """
        prompt = f"""
You are a compliance expert. Generate a {compliance_standard} compliance report 
based on the following findings:

Findings:
{json.dumps(findings[:10], indent=2)}

For {compliance_standard} compliance, provide:
1. Compliance gaps identified
2. Severity of non-compliance
3. Required remediation
4. Timeline for compliance
5. Verification procedures
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating compliance report: {str(e)}"
    
    def generate_threat_model(self, target_info: Dict) -> str:
        """
        Generate threat model for target
        
        Args:
            target_info: Target information
            
        Returns:
            Threat model
        """
        prompt = f"""
You are a threat modeling expert. Create a threat model for:

Target: {target_info.get('target', 'Unknown')}
Type: {target_info.get('type', 'Unknown')}
Architecture: {target_info.get('architecture', 'Unknown')}

Provide:
1. Threat actors
2. Attack vectors
3. Assets at risk
4. Potential impacts
5. Mitigation strategies
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating threat model: {str(e)}"
    
    def save_analysis(self, analysis_type: str, content: str, 
                     output_dir: str = "./nightfury_reports") -> str:
        """
        Save AI analysis to file
        
        Args:
            analysis_type: Type of analysis
            content: Analysis content
            output_dir: Output directory
            
        Returns:
            File path
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gemini_{analysis_type}_{timestamp}.txt"
        filepath = output_path / filename
        
        with open(filepath, 'w') as f:
            f.write(f"Gemini AI Analysis - {analysis_type}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(content)
        
        return str(filepath)


class GeminiAIReportGenerator:
    """Generates reports using Gemini AI"""
    
    def __init__(self, gemini: GeminiAIIntegration):
        self.gemini = gemini
    
    def generate_full_report(self, operation_data: Dict) -> str:
        """Generate full report using Gemini"""
        
        report = f"""
NIGHTFURY PENETRATION TEST REPORT
Generated with Google Gemini AI
{'='*80}

OPERATION DETAILS
{'-'*80}
Name: {operation_data.get('name', 'Unknown')}
Target: {operation_data.get('target', 'Unknown')}
Type: {operation_data.get('type', 'Unknown')}
Start Time: {operation_data.get('start_time', 'Unknown')}
End Time: {operation_data.get('end_time', 'Unknown')}
Status: {operation_data.get('status', 'Unknown')}

EXECUTIVE SUMMARY
{'-'*80}
"""
        
        # Add Gemini-generated executive summary
        exec_summary = self.gemini.generate_executive_summary(operation_data)
        report += exec_summary + "\n\n"
        
        # Add findings analysis
        findings = operation_data.get('findings', [])
        if findings:
            report += "FINDINGS ANALYSIS\n"
            report += "-" * 80 + "\n"
            analysis = self.gemini.analyze_findings(findings)
            report += analysis + "\n\n"
        
        # Add remediation steps for critical findings
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        if critical_findings:
            report += "CRITICAL REMEDIATION STEPS\n"
            report += "-" * 80 + "\n"
            for finding in critical_findings[:3]:  # Top 3 critical
                report += f"\n{finding.get('title', 'Unknown')}\n"
                remediation = self.gemini.generate_remediation_steps(finding)
                report += remediation + "\n"
        
        return report


def main():
    """Main entry point"""
    
    # Check if API key is set
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("\n" + "="*80)
        print("GEMINI AI INTEGRATION SETUP")
        print("="*80 + "\n")
        print("[!] GEMINI_API_KEY environment variable not set\n")
        print("To use Gemini AI with NightFury:\n")
        print("1. Get free API key at: https://aistudio.google.com/app/apikeys")
        print("2. Set environment variable:")
        print("   export GEMINI_API_KEY='your-api-key-here'\n")
        print("3. Or pass as parameter:")
        print("   gemini = GeminiAIIntegration(api_key='your-api-key')\n")
        print("="*80 + "\n")
        return
    
    try:
        # Initialize Gemini
        print("[*] Initializing Gemini AI integration...")
        gemini = GeminiAIIntegration(api_key)
        print("[+] Gemini AI initialized successfully\n")
        
        # Test chat
        print("[*] Testing Gemini AI chat...")
        response = gemini.chat("What are the top 5 OWASP vulnerabilities I should test for?")
        print("[+] Gemini Response:")
        print(response)
        
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
