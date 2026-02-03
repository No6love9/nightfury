# NightFury Framework v2.0 - User Manual

**Version**: 2.0  
**Last Updated**: February 2026  
**Author**: Manus AI  
**Repository**: https://github.com/No6love9/nightfury

---

## Table of Contents

1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation Guide](#installation-guide)
4. [Quick Start](#quick-start)
5. [GUI Dashboard](#gui-dashboard)
6. [Core Functionalities](#core-functionalities)
7. [Quick Commands Reference](#quick-commands-reference)
8. [Exploitation Chains](#exploitation-chains)
9. [Gemini AI Integration](#gemini-ai-integration)
10. [Reporting and Analysis](#reporting-and-analysis)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)

---

## Introduction

NightFury Framework v2.0 is a professional-grade penetration testing platform designed for comprehensive security assessments and vulnerability exploitation. The framework integrates advanced reconnaissance capabilities, automated exploitation chains, and AI-powered analysis through Google Gemini AI. It provides both command-line interfaces and a graphical user interface for maximum flexibility and ease of use.

The framework is specifically optimized for Runehall platform testing, featuring specialized modules for authentication bypass, game logic analysis, payment system vulnerabilities, and RNG manipulation detection. All operations are logged, analyzed, and reported automatically for professional documentation and compliance purposes.

---

## System Requirements

### Minimum Requirements

The NightFury Framework requires the following minimum specifications to operate effectively:

**Hardware:**
- Processor: Intel Core i5 or equivalent (2.0 GHz or higher)
- RAM: 4 GB minimum (8 GB recommended for large-scale operations)
- Storage: 2 GB free disk space for installation and data
- Network: Stable internet connection

**Software:**
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment support (venv)
- Git (for repository cloning)

### Supported Operating Systems

The framework has been tested and verified on the following platforms:

| Operating System | Version | Status |
|------------------|---------|--------|
| Ubuntu | 20.04 LTS, 22.04 LTS | ✅ Fully Supported |
| Debian | 10, 11, 12 | ✅ Fully Supported |
| CentOS/RHEL | 7, 8, 9 | ✅ Fully Supported |
| macOS | 11.0+, 12.0+, 13.0+ | ✅ Fully Supported |
| Windows | 10, 11 | ✅ Fully Supported |

### Python Dependencies

The framework requires 60+ Python packages organized into the following categories:

**Core Frameworks**: requests, aiohttp, flask, fastapi, uvicorn  
**Security**: cryptography, bcrypt, PyNaCl, pycryptodome  
**Data Processing**: pandas, numpy, scipy, scikit-learn  
**GUI**: PyQt5, dash, streamlit  
**Reporting**: reportlab, fpdf2, python-docx, openpyxl  
**AI**: google-generativeai  
**Utilities**: click, colorama, rich, loguru

All dependencies are automatically installed through the setup scripts.

---

## Installation Guide

### Method 1: Linux/macOS (Bash Script)

The bash setup script provides the most automated installation experience for Unix-like systems. It automatically detects your operating system and installs all necessary system dependencies.

**Step 1: Clone the Repository**

```bash
git clone https://github.com/No6love9/nightfury.git
cd nightfury
```

**Step 2: Run the Setup Script**

```bash
bash setup-unix.sh
```

The script will automatically:
- Detect your operating system (Ubuntu, Debian, CentOS, or macOS)
- Install system-level dependencies (build tools, Python development headers, etc.)
- Create a Python virtual environment
- Upgrade pip, setuptools, and wheel
- Install all Python dependencies from requirements.txt
- Create necessary directories (reports, logs, data)
- Generate configuration files
- Optionally configure Google Gemini API
- Verify the installation

**Step 3: Activate Virtual Environment**

After the setup completes, activate the virtual environment:

```bash
source nightfury_env/bin/activate
```

### Method 2: Windows (Batch Script)

The Windows batch script provides an automated setup experience specifically optimized for Windows systems.

**Step 1: Clone the Repository**

```cmd
git clone https://github.com/No6love9/nightfury.git
cd nightfury
```

**Step 2: Run the Setup Script**

```cmd
setup-windows.bat
```

The script will:
- Check for Python installation
- Detect Visual C++ Build Tools
- Create a virtual environment
- Upgrade pip and install dependencies
- Create necessary directories
- Generate configuration files
- Setup Gemini API (optional)
- Verify the installation

**Step 3: Activate Virtual Environment**

```cmd
nightfury_env\Scripts\activate.bat
```

### Method 3: Universal Python Setup

The universal Python setup script works on all platforms and provides command-line customization options.

**Step 1: Clone the Repository**

```bash
git clone https://github.com/No6love9/nightfury.git
cd nightfury
```

**Step 2: Run the Setup Script**

```bash
python3 setup.py
```

Or with custom virtual environment name:

```bash
python3 setup.py --venv my_custom_env
```

**Step 3: Activate Virtual Environment**

For Linux/macOS:
```bash
source nightfury_env/bin/activate
```

For Windows:
```cmd
nightfury_env\Scripts\activate.bat
```

### Troubleshooting Installation

If you encounter issues during installation, refer to the [Troubleshooting](#troubleshooting) section below.

---

## Quick Start

### Starting the GUI Dashboard

The graphical user interface provides the most user-friendly way to interact with the framework. It includes real-time monitoring, operation management, and automated reporting.

**Linux/macOS:**
```bash
source nightfury_env/bin/activate
python3 nightfury_gui_gemini.py
```

**Windows:**
```cmd
nightfury_env\Scripts\activate.bat
python nightfury_gui_gemini.py
```

Or use the startup script created during installation:

**Linux/macOS:**
```bash
./start_nightfury.sh
```

**Windows:**
```cmd
start_nightfury.bat
```

### Your First Reconnaissance Operation

Once the GUI dashboard is running, follow these steps to perform your first reconnaissance operation:

1. **Select Operation Type**: Click on the "Operations" tab in the left sidebar
2. **Choose Reconnaissance**: Select "Reconnaissance" from the operation type dropdown
3. **Select Module**: Choose "runehall_scan" for a quick Runehall infrastructure scan
4. **Configure Target**: Enter the target domain (e.g., `runehall.com`)
5. **Enable AI Analysis**: Check the "Enable Gemini AI Analysis" checkbox for automated findings analysis
6. **Execute**: Click the "Execute" button to start the operation
7. **Monitor Progress**: Watch the real-time progress in the "Activity Log" tab
8. **Review Results**: Check the "Results" tab for findings and recommendations

### Using Quick Commands

For command-line users, quick commands provide a fast way to execute common operations:

```bash
# List all available quick commands
python3 runehall_quick_commands.py list

# Run full reconnaissance
python3 runehall_quick_commands.py recon-full runehall.com

# Run quick reconnaissance
python3 runehall_quick_commands.py recon-quick runehall.com

# Run authentication bypass exploitation
python3 runehall_quick_commands.py exploit-auth runehall.com

# Run all exploitation vectors
python3 runehall_quick_commands.py exploit-all runehall.com
```

---

## GUI Dashboard

### Dashboard Overview

The NightFury GUI Dashboard is built with PyQt5 and provides a comprehensive interface for managing penetration testing operations. The dashboard is organized into several main sections:

**Main Tabs:**
- **Operations**: Create and manage penetration testing operations
- **Results**: View and analyze operation results
- **Reports**: Generate and export professional reports
- **AI Analysis**: View Gemini AI-powered findings analysis
- **Settings**: Configure framework parameters and preferences
- **Activity Log**: Monitor real-time operation progress

### Operations Tab

The Operations tab allows you to create and execute penetration testing operations with full customization.

**Creating an Operation:**

1. Click the "New Operation" button
2. Select the operation type (Reconnaissance, Exploitation, Post-Exploitation)
3. Choose the specific module (runehall_scan, runehall_chat, runehall_nexus, etc.)
4. Configure module parameters:
   - **Target**: The target domain or IP address
   - **Vector**: For exploitation, select the attack vector (auth_bypass, bet_manipulation, payment_leak, game_logic)
   - **Threads**: Number of concurrent threads (1-32)
   - **Timeout**: Operation timeout in seconds
   - **Proxy**: Enable proxy rotation for anonymity
5. Enable optional features:
   - **AI Analysis**: Automatically analyze findings with Gemini AI
   - **Screenshot**: Capture screenshots of results
   - **Deep Scan**: Perform more thorough scanning
6. Click "Execute" to start the operation

### Results Tab

The Results tab displays findings from completed operations with filtering and sorting capabilities.

**Viewing Results:**

- **Filter by Operation**: Select a specific operation to view its results
- **Filter by Severity**: Show only critical, high, medium, or low severity findings
- **Sort Results**: Click column headers to sort by different criteria
- **Export Results**: Export findings to JSON, CSV, or HTML format
- **View Details**: Click on any finding to see detailed information and recommendations

### Reports Tab

The Reports tab provides automated report generation with multiple output formats.

**Generating Reports:**

1. Click "Generate Report"
2. Select report type:
   - **Executive Summary**: High-level overview for management
   - **Technical Report**: Detailed technical findings and remediation
   - **Compliance Report**: OWASP, CIS, PCI-DSS compliance analysis
   - **Full Report**: Comprehensive report with all findings
3. Select output format (HTML, PDF, DOCX, JSON)
4. Configure report options:
   - Include screenshots
   - Include remediation steps
   - Include risk ratings
5. Click "Generate" to create the report
6. Reports are automatically saved to `nightfury_reports/` directory

### AI Analysis Tab

The AI Analysis tab displays Gemini AI-powered analysis of findings.

**Viewing AI Analysis:**

- **Automatic Analysis**: Findings are automatically analyzed when AI is enabled
- **Manual Analysis**: Click "Analyze with AI" on any finding for on-demand analysis
- **Analysis Results**: View AI-generated:
  - Vulnerability assessment
  - Risk prioritization
  - Attack vector analysis
  - Remediation recommendations
  - Compliance implications

### Settings Tab

The Settings tab provides framework configuration options.

**Available Settings:**

- **Framework Mode**: Ultra Performance, Balanced, Stealth, Precision
- **Thread Count**: Number of concurrent threads (1-32)
- **Timeout**: Default operation timeout
- **Proxy Settings**: Enable/disable proxy rotation
- **Evasion**: Enable/disable advanced evasion techniques
- **Cache**: Enable/disable result caching
- **Logging Level**: DEBUG, INFO, WARNING, ERROR
- **Theme**: Dark or Light UI theme
- **Gemini API Key**: Configure or update Gemini API key

---

## Core Functionalities

### Reconnaissance Modules

Reconnaissance modules gather information about the target infrastructure and identify potential vulnerabilities.

**runehall_scan**: Performs automated infrastructure scanning including subdomain enumeration, port scanning, and service identification.

```bash
python3 runehall_quick_commands.py recon-full runehall.com
```

**runehall_osint**: Conducts open-source intelligence gathering including user profiling, social engineering reconnaissance, and public data collection.

```bash
python3 runehall_quick_commands.py recon-osint runehall.com
```

**runehall_chat**: Analyzes Runehall chat functionality for information leakage and user enumeration.

```bash
python3 runehall_quick_commands.py recon-chat runehall.com
```

**user_scraper**: Extracts and catalogs user information from accessible endpoints.

```bash
python3 runehall_quick_commands.py recon-users runehall.com
```

### Exploitation Modules

Exploitation modules attempt to identify and exploit specific vulnerabilities.

**runehall_nexus**: The primary exploitation module supporting multiple attack vectors:

- **auth_bypass**: Tests for authentication bypass vulnerabilities including SQL injection, session manipulation, and JWT flaws
- **bet_manipulation**: Tests for game logic vulnerabilities including negative bets, integer overflows, and race conditions
- **payment_leak**: Tests for payment system vulnerabilities including IDOR, information disclosure, and transaction manipulation
- **game_logic**: Analyzes RNG implementation for predictability and fairness issues

```bash
python3 runehall_quick_commands.py exploit-auth runehall.com
python3 runehall_quick_commands.py exploit-bet runehall.com
python3 runehall_quick_commands.py exploit-payment runehall.com
python3 runehall_quick_commands.py exploit-rng runehall.com
```

### Post-Exploitation Modules

Post-exploitation modules maintain access and gather sensitive data after initial compromise.

**lateral_movement**: Identifies and exploits paths for lateral movement within the target infrastructure.

**privilege_escalation**: Attempts to escalate privileges from compromised accounts.

**data_exfiltration**: Safely extracts sensitive data from compromised systems.

### Automation and Chaining

The framework supports advanced exploitation chains that automatically execute multiple modules in sequence.

**ELITE_NEXUS Chain**: Complete compromise workflow executing reconnaissance, vulnerability analysis, exploitation, and post-exploitation in sequence.

```bash
python3 runehall_exploitation_chains.py ELITE_NEXUS runehall.com
```

**RAPID_STRIKE Chain**: Fast exploitation targeting high-probability vulnerabilities.

```bash
python3 runehall_exploitation_chains.py RAPID_STRIKE runehall.com
```

**STEALTH_OPERATION Chain**: Low-detection exploitation with maximum operational security.

```bash
python3 runehall_exploitation_chains.py STEALTH_OPERATION runehall.com
```

---

## Quick Commands Reference

Quick commands provide simplified interfaces to complex operations. This section documents all available quick commands and their usage.

### Reconnaissance Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `recon-full` | Complete reconnaissance suite | `python3 runehall_quick_commands.py recon-full <target>` |
| `recon-quick` | Fast reconnaissance scan | `python3 runehall_quick_commands.py recon-quick <target>` |
| `recon-users` | User enumeration and scraping | `python3 runehall_quick_commands.py recon-users <target>` |
| `recon-chat` | Analyze chat functionality | `python3 runehall_quick_commands.py recon-chat <target>` |
| `recon-dns` | DNS enumeration and analysis | `python3 runehall_quick_commands.py recon-dns <target>` |

### Exploitation Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `exploit-auth` | Authentication bypass testing | `python3 runehall_quick_commands.py exploit-auth <target>` |
| `exploit-bet` | Betting logic exploitation | `python3 runehall_quick_commands.py exploit-bet <target>` |
| `exploit-payment` | Payment system exploitation | `python3 runehall_quick_commands.py exploit-payment <target>` |
| `exploit-rng` | RNG analysis and manipulation | `python3 runehall_quick_commands.py exploit-rng <target>` |
| `exploit-all` | Execute all exploitation vectors | `python3 runehall_quick_commands.py exploit-all <target>` |
| `exploit-web` | General web exploitation | `python3 runehall_quick_commands.py exploit-web <target>` |

### Automation Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `batch-users` | Batch user enumeration | `python3 runehall_quick_commands.py batch-users <target_list>` |
| `batch-vectors` | Batch exploitation testing | `python3 runehall_quick_commands.py batch-vectors <target_list>` |
| `continuous-monitor` | Continuous monitoring mode | `python3 runehall_quick_commands.py continuous-monitor <target>` |

### Operational Security Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `opsec-proxy` | Configure proxy rotation | `python3 runehall_quick_commands.py opsec-proxy <proxy_list>` |
| `opsec-clean` | Clean logs and cache | `python3 runehall_quick_commands.py opsec-clean` |

---

## Exploitation Chains

Exploitation chains automate complex multi-stage attacks by combining multiple modules in a coordinated workflow.

### ELITE_NEXUS Chain

The ELITE_NEXUS chain represents the most comprehensive exploitation workflow, executing all phases of a penetration test in sequence.

**Execution:**
```bash
python3 runehall_exploitation_chains.py ELITE_NEXUS runehall.com
```

**Phases:**
1. **Reconnaissance**: Gather comprehensive target information
2. **Vulnerability Analysis**: Identify potential vulnerabilities
3. **Exploitation**: Attempt to exploit identified vulnerabilities
4. **Post-Exploitation**: Maintain access and gather sensitive data
5. **Reporting**: Generate comprehensive findings report

### RAPID_STRIKE Chain

The RAPID_STRIKE chain focuses on speed and efficiency, targeting the most likely high-probability vulnerabilities.

**Execution:**
```bash
python3 runehall_exploitation_chains.py RAPID_STRIKE runehall.com
```

**Phases:**
1. **Quick Reconnaissance**: Fast information gathering
2. **High-Probability Exploitation**: Focus on auth bypass and payment leaks
3. **Quick Reporting**: Generate findings summary

### STEALTH_OPERATION Chain

The STEALTH_OPERATION chain prioritizes operational security and low detection rates.

**Execution:**
```bash
python3 runehall_exploitation_chains.py STEALTH_OPERATION runehall.com
```

**Features:**
- Slow operation to avoid detection
- Proxy rotation enabled
- Randomized request timing
- Minimal logging
- Low thread count

---

## Gemini AI Integration

The framework integrates Google Gemini AI for automated analysis and intelligent decision-making.

### Setting Up Gemini AI

**Step 1: Get API Key**

1. Visit https://aistudio.google.com/app/apikeys
2. Click "Create API Key"
3. Copy your API key

**Step 2: Configure API Key**

**Option A: Environment Variable**
```bash
export GEMINI_API_KEY='your-api-key-here'
```

**Option B: During Setup**
The setup scripts will prompt you to enter your Gemini API key.

**Option C: GUI Settings**
1. Open the GUI dashboard
2. Go to Settings tab
3. Paste your API key in the "Gemini API Key" field
4. Click "Save"

### Using Gemini AI Features

**Automatic Analysis**

When enabled, Gemini AI automatically analyzes all findings:

```bash
python3 runehall_quick_commands.py recon-full runehall.com --ai-enabled
```

**Finding Analysis**

Gemini AI analyzes security findings and provides:
- Vulnerability assessment
- Risk prioritization
- Attack vector analysis
- Remediation recommendations
- Compliance implications

**Executive Summaries**

Generate professional C-level summaries:
```python
from gemini_ai_integration import GeminiAI

ai = GeminiAI(api_key="your-key")
summary = ai.generate_executive_summary(findings)
print(summary)
```

**Threat Modeling**

Generate threat models for identified vulnerabilities:
```python
threat_model = ai.generate_threat_model(findings)
print(threat_model)
```

**Compliance Reports**

Generate compliance-focused reports:
```python
compliance = ai.generate_compliance_report(findings, standard="OWASP")
print(compliance)
```

---

## Reporting and Analysis

### Automated Reporting

The framework automatically generates comprehensive reports from operation results.

**Report Types:**

- **Executive Summary**: High-level overview for non-technical stakeholders
- **Technical Report**: Detailed technical findings with remediation steps
- **Compliance Report**: OWASP, CIS, PCI-DSS compliance analysis
- **Full Report**: Comprehensive report with all findings and recommendations

**Generating Reports:**

```bash
python3 nightfury_reporting_engine.py --operation-id <id> --format html
```

**Output Formats:**

- **HTML**: Interactive web-based report
- **PDF**: Portable document format
- **DOCX**: Microsoft Word document
- **JSON**: Structured data format
- **CSV**: Spreadsheet format

### Data Organization

All data is automatically organized in the following directory structure:

```
nightfury_reports/          # Operation reports
├── html/                   # HTML reports
├── pdf/                    # PDF reports
├── json/                   # JSON data exports
└── csv/                    # CSV exports

nightfury_logs/             # Operation logs
├── operations.log          # Operation execution logs
├── errors.log              # Error logs
└── debug.log               # Debug logs

nightfury_data/             # Cached data and analysis
├── findings.json           # Cached findings
├── targets.json            # Target information
└── cache/                  # Operation cache
```

---

## Troubleshooting

### Common Installation Issues

**Issue: Python 3 not found**

**Solution**: Install Python 3.8 or higher:
- Ubuntu/Debian: `sudo apt-get install python3 python3-pip python3-venv`
- CentOS/RHEL: `sudo yum install python3 python3-pip`
- macOS: `brew install python3`
- Windows: Download from https://www.python.org/downloads/

**Issue: Permission denied when running setup script**

**Solution**: Make the script executable:
```bash
chmod +x setup-unix.sh
bash setup-unix.sh
```

**Issue: Virtual environment activation fails**

**Solution**: Ensure you're in the correct directory and the venv exists:
```bash
ls -la nightfury_env/
source nightfury_env/bin/activate
```

**Issue: Dependency installation fails**

**Solution**: Upgrade pip and try again:
```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

### Common Runtime Issues

**Issue: GUI fails to start**

**Solution**: Check if PyQt5 is installed:
```bash
python3 -c "import PyQt5; print('PyQt5 installed')"
```

If not installed, reinstall dependencies:
```bash
pip install -r requirements.txt
```

**Issue: Gemini API key not working**

**Solution**: Verify the API key:
1. Check that the key is correctly set: `echo $GEMINI_API_KEY`
2. Verify the key is valid at https://aistudio.google.com/app/apikeys
3. Ensure the key has not been revoked

**Issue: Operations timeout**

**Solution**: Increase the timeout value in settings or use the Precision mode:
```bash
python3 setup.py --mode precision
```

**Issue: Out of memory errors**

**Solution**: Reduce thread count and increase timeout:
1. Go to Settings tab in GUI
2. Reduce "Thread Count" to 2-4
3. Increase "Timeout" to 600+ seconds

---

## FAQ

**Q: Is NightFury Framework legal to use?**

A: NightFury is a penetration testing framework designed for authorized security testing only. Always ensure you have explicit written permission from the target organization before conducting any security assessments. Unauthorized access to computer systems is illegal in most jurisdictions.

**Q: Can I use NightFury on systems I don't own?**

A: No. Only use NightFury on systems you own or have explicit written permission to test. Unauthorized access is illegal.

**Q: What is the difference between the GUI and command-line interfaces?**

A: The GUI provides a user-friendly interface with real-time monitoring and automated reporting. The command-line interface offers more control and is suitable for automation and scripting. Both provide the same core functionality.

**Q: How do I update the framework?**

A: Pull the latest changes from the repository:
```bash
cd nightfury
git pull origin master
pip install -r requirements.txt --upgrade
```

**Q: Can I use NightFury without Gemini AI?**

A: Yes. Gemini AI is optional. The framework works fully without it, but you won't have AI-powered analysis features.

**Q: How do I get a free Gemini API key?**

A: Visit https://aistudio.google.com/app/apikeys and click "Create API Key". Google provides free tier access with generous rate limits.

**Q: What should I do if I find a vulnerability in NightFury?**

A: Please report security vulnerabilities responsibly by opening an issue on GitHub or contacting the maintainers directly.

**Q: Can I modify the framework for my needs?**

A: Yes. The framework is open-source and can be modified. Ensure you comply with the license terms.

**Q: How do I contribute to the project?**

A: Fork the repository, make your changes, and submit a pull request. Contributions are welcome!

**Q: Where can I get help?**

A: Refer to the documentation files, check the GitHub issues, or consult the troubleshooting section above.

---

## Additional Resources

- **GitHub Repository**: https://github.com/No6love9/nightfury
- **Gemini AI Documentation**: https://ai.google.dev/
- **Python Documentation**: https://docs.python.org/3/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Penetration Testing Frameworks**: https://www.owasp.org/index.php/Penetration_testing

---

**End of User Manual**

For the latest updates and additional documentation, visit the GitHub repository at https://github.com/No6love9/nightfury
