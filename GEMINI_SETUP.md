# NightFury Framework - Google Gemini AI Setup Guide

## Overview

This guide provides complete instructions for setting up and using Google Gemini AI with the NightFury Framework v2.0. Gemini AI provides free access to advanced AI capabilities for analysis, reporting, and threat modeling.

---

## Why Gemini AI?

Google Gemini AI offers several advantages for penetration testing:

- **Free Access**: No credit card required, generous free tier
- **Powerful Analysis**: Advanced natural language processing for security analysis
- **Real-time Insights**: Instant analysis of findings and vulnerabilities
- **Professional Reports**: AI-generated executive summaries and remediation steps
- **Threat Modeling**: Automated threat model generation
- **Compliance Reports**: OWASP, CIS, PCI-DSS compliance analysis

---

## Getting Started

### Step 1: Get Your Free Gemini API Key

1. Visit **Google AI Studio**: https://aistudio.google.com/app/apikeys
2. Click **"Create API Key"**
3. Select **"Create API key in new project"**
4. Copy your API key (keep it secure)

**Important**: Your API key is sensitive. Never commit it to version control.

### Step 2: Set Environment Variable

**On Linux/macOS:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export GEMINI_API_KEY='your-api-key-here'

# Reload shell
source ~/.bashrc
```

**On Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY='your-api-key-here'

# To make permanent, use:
[Environment]::SetEnvironmentVariable("GEMINI_API_KEY", "your-api-key-here", "User")
```

**On Windows (Command Prompt):**
```cmd
setx GEMINI_API_KEY "your-api-key-here"
```

### Step 3: Install Gemini Package

```bash
# Install google-generativeai
pip install google-generativeai

# Or update requirements.txt
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Test Gemini integration
python3 gemini_ai_integration.py

# Should output Gemini response to a test query
```

---

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Your Gemini API key | `AIzaSy...` |
| `GEMINI_MODEL` | Model to use (optional) | `gemini-pro` |
| `GEMINI_TIMEOUT` | Request timeout in seconds | `30` |

### Configuration File

Create `gemini_config.json`:

```json
{
  "api": {
    "key": "${GEMINI_API_KEY}",
    "model": "gemini-pro",
    "timeout": 30,
    "max_retries": 3
  },
  "analysis": {
    "auto_analyze": true,
    "generate_summary": true,
    "generate_remediation": true,
    "generate_threat_model": true
  },
  "reporting": {
    "format": "html",
    "include_ai_analysis": true,
    "save_conversations": true
  },
  "security": {
    "encrypt_api_key": false,
    "log_requests": false
  }
}
```

---

## Using Gemini AI with NightFury

### Method 1: GUI Dashboard

Start the Gemini-enabled GUI:

```bash
python3 nightfury_gui_gemini.py
```

**Features:**
- Automatic Gemini AI analysis on operation completion
- AI Analysis tab for viewing Gemini insights
- Menu options for various AI functions
- Real-time chat with Gemini

### Method 2: Command Line

Use Gemini directly in scripts:

```python
from gemini_ai_integration import GeminiAIIntegration

# Initialize
gemini = GeminiAIIntegration()

# Analyze findings
findings = [...]
analysis = gemini.analyze_findings(findings)
print(analysis)

# Generate executive summary
summary = gemini.generate_executive_summary(operation_data)
print(summary)

# Generate remediation steps
remediation = gemini.generate_remediation_steps(finding)
print(remediation)
```

### Method 3: Integration with Quick Commands

```bash
# Run operation with Gemini analysis
python3 runehall_quick_commands.py recon-full runehall.com --ai-analysis

# Generate AI-powered report
python3 nightfury_reporting_engine.py --use-gemini
```

---

## Gemini AI Capabilities

### 1. Finding Analysis

Gemini analyzes security findings to provide:
- Vulnerability assessment
- Risk prioritization
- Attack vector analysis
- Potential impact evaluation

```python
analysis = gemini.analyze_findings(findings_list)
```

### 2. Executive Summaries

Generate professional executive summaries:
- Overview of assessment
- Key findings summary
- Risk rating
- Recommended actions

```python
summary = gemini.generate_executive_summary(operation_data)
```

### 3. Remediation Steps

Detailed remediation guidance:
- Immediate mitigation
- Long-term fixes
- Verification procedures
- Prevention measures

```python
remediation = gemini.generate_remediation_steps(finding)
```

### 4. Attack Surface Analysis

Analyze target attack surface:
- Identified attack vectors
- High-risk areas
- Testing approach
- Vulnerability likelihood

```python
analysis = gemini.analyze_attack_surface(target_info)
```

### 5. Threat Modeling

Generate threat models:
- Threat actors
- Attack vectors
- Assets at risk
- Mitigation strategies

```python
threat_model = gemini.generate_threat_model(target_info)
```

### 6. Compliance Reports

Generate compliance-focused reports:
- OWASP compliance
- CIS benchmarks
- PCI-DSS requirements
- HIPAA considerations

```python
report = gemini.generate_compliance_report(findings, "OWASP")
```

### 7. Log Analysis

Analyze security logs:
- Suspicious activities
- Failed authentication attempts
- Unusual patterns
- Potential attacks

```python
analysis = gemini.analyze_log_file(log_content)
```

### 8. Interactive Chat

Chat with Gemini about security topics:

```python
response = gemini.chat("What are the top OWASP vulnerabilities?")
```

---

## Practical Examples

### Example 1: Analyze Operation Findings

```python
from gemini_ai_integration import GeminiAIIntegration

# Initialize Gemini
gemini = GeminiAIIntegration()

# Your findings
findings = [
    {
        "severity": "high",
        "title": "SQL Injection",
        "description": "Vulnerable to SQL injection in login form",
        "evidence": "payload: ' OR '1'='1"
    },
    {
        "severity": "medium",
        "title": "Weak Encryption",
        "description": "Sensitive data transmitted over HTTP",
        "evidence": "Payment information exposed"
    }
]

# Get analysis
analysis = gemini.analyze_findings(findings)
print(analysis)

# Save analysis
filepath = gemini.save_analysis("findings", analysis)
print(f"Analysis saved to: {filepath}")
```

### Example 2: Generate Full Report

```python
from gemini_ai_integration import GeminiAIIntegration, GeminiAIReportGenerator

# Initialize
gemini = GeminiAIIntegration()
reporter = GeminiAIReportGenerator(gemini)

# Your operation data
operation_data = {
    "name": "Runehall Penetration Test",
    "target": "runehall.com",
    "type": "Full Penetration Test",
    "findings": findings  # from previous example
}

# Generate report
report = reporter.generate_full_report(operation_data)
print(report)

# Save report
with open("penetration_test_report.txt", "w") as f:
    f.write(report)
```

### Example 3: Interactive Security Chat

```python
from gemini_ai_integration import GeminiAIIntegration

gemini = GeminiAIIntegration()

# Ask security questions
questions = [
    "What are the OWASP Top 10 vulnerabilities?",
    "How do I test for SQL injection?",
    "What is the best way to secure an API?"
]

for question in questions:
    response = gemini.chat(question)
    print(f"Q: {question}")
    print(f"A: {response}\n")
```

---

## GUI Features

### Gemini AI Tab

The GUI includes a dedicated "AI Analysis" tab showing:
- Real-time Gemini analysis
- Executive summaries
- Remediation guidance
- Threat models
- Compliance reports

### AI Menu Options

| Option | Function |
|--------|----------|
| Analyze Findings | Comprehensive finding analysis |
| Generate Summary | Executive summary generation |
| Remediation Steps | Step-by-step remediation guide |
| Threat Model | Threat model generation |
| Chat with AI | Interactive security chat |

### Automatic Analysis

When "Enable Gemini AI Analysis" is checked:
- Findings are automatically analyzed
- Executive summary is generated
- Results appear in AI Analysis tab
- Analysis is saved with operation data

---

## API Rate Limits

Google Gemini API has the following free tier limits:

- **Requests per minute**: 60
- **Requests per day**: 1,500
- **Characters per request**: 30,000

For higher limits, upgrade to a paid plan at https://cloud.google.com/generative-ai/pricing

---

## Troubleshooting

### Issue: "GEMINI_API_KEY not set"

**Solution:**
```bash
# Verify environment variable is set
echo $GEMINI_API_KEY

# If empty, set it
export GEMINI_API_KEY='your-api-key'

# Or pass directly to code
gemini = GeminiAIIntegration(api_key='your-api-key')
```

### Issue: "google-generativeai not installed"

**Solution:**
```bash
pip install google-generativeai
```

### Issue: "API Key invalid"

**Solution:**
1. Verify API key at https://aistudio.google.com/app/apikeys
2. Ensure no extra spaces or quotes
3. Regenerate key if needed

### Issue: "Rate limit exceeded"

**Solution:**
- Wait before making more requests
- Upgrade to paid plan for higher limits
- Batch requests efficiently

### Issue: "Timeout error"

**Solution:**
```python
# Increase timeout
gemini = GeminiAIIntegration(api_key=key, timeout=60)
```

---

## Security Best Practices

### Protect Your API Key

1. **Never commit to version control**:
   ```bash
   # Add to .gitignore
   echo "GEMINI_API_KEY" >> .gitignore
   ```

2. **Use environment variables**:
   ```bash
   export GEMINI_API_KEY='your-key'
   ```

3. **Rotate keys regularly**:
   - Generate new key monthly
   - Delete old keys

4. **Restrict API key usage**:
   - Set HTTP referrer restrictions
   - Limit to specific APIs

### Secure Conversations

- Don't include sensitive data in chat
- Don't share API keys in prompts
- Review saved conversations
- Delete sensitive logs

---

## Advanced Configuration

### Custom Model Parameters

```python
gemini = GeminiAIIntegration()
gemini.model_name = "gemini-pro-vision"  # For image analysis
```

### Batch Processing

```python
# Process multiple operations
for operation in operations:
    analysis = gemini.analyze_findings(operation['findings'])
    gemini.save_analysis("batch_analysis", analysis)
```

### Custom Prompts

```python
# Create custom analysis prompt
custom_prompt = """
You are a specialized security analyst for financial systems.
Analyze these findings with focus on payment security...
"""

response = gemini.model.generate_content(custom_prompt)
```

---

## Integration with Other Tools

### Burp Suite Integration

```python
# Analyze Burp Suite findings
burp_findings = parse_burp_export("burp_export.json")
analysis = gemini.analyze_findings(burp_findings)
```

### OWASP ZAP Integration

```python
# Analyze ZAP scan results
zap_findings = parse_zap_report("zap_report.json")
analysis = gemini.analyze_findings(zap_findings)
```

### Nessus Integration

```python
# Analyze Nessus vulnerabilities
nessus_findings = parse_nessus_report("nessus_report.nessus")
analysis = gemini.analyze_findings(nessus_findings)
```

---

## Performance Tips

1. **Batch Requests**: Send multiple findings at once
2. **Cache Results**: Store analysis for repeated queries
3. **Optimize Prompts**: Use concise, specific prompts
4. **Parallel Processing**: Use threading for multiple analyses

---

## Monitoring & Logging

### Enable Request Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)

gemini = GeminiAIIntegration()
# Requests will be logged
```

### Track API Usage

```python
# Monitor API calls
request_count = 0
for finding in findings:
    analysis = gemini.analyze_findings([finding])
    request_count += 1
    print(f"Requests used: {request_count}/1500 daily limit")
```

---

## Upgrading to Paid Plan

For production use with higher limits:

1. Visit https://cloud.google.com/generative-ai/pricing
2. Set up billing
3. Increase quotas in Google Cloud Console
4. Update API key configuration

---

## Support & Resources

- **Google AI Studio**: https://aistudio.google.com
- **API Documentation**: https://ai.google.dev/
- **Pricing**: https://cloud.google.com/generative-ai/pricing
- **Community**: https://github.com/google/generative-ai-python

---

## Next Steps

1. **Get API Key**: https://aistudio.google.com/app/apikeys
2. **Set Environment Variable**: `export GEMINI_API_KEY='...'`
3. **Install Package**: `pip install google-generativeai`
4. **Start GUI**: `python3 nightfury_gui_gemini.py`
5. **Run Operations**: Use quick commands with AI analysis

---

**Version**: 2.0
**Last Updated**: 2026-02-03
**Status**: Production Ready

For issues or questions, refer to the troubleshooting section or consult Google's official documentation.
