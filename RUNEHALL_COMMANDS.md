# NightFury Framework - Runehall Specialized Commands Reference

**Complete Command List for Runehall OSINT, Reconnaissance, and Exploitation**

Version: 2.0  
Last Updated: February 2026  
Repository: https://github.com/No6love9/nightfury

---

## Table of Contents

1. [Quick Command Index](#quick-command-index)
2. [OSINT Commands](#osint-commands)
3. [Reconnaissance Commands](#reconnaissance-commands)
4. [Exploitation Commands](#exploitation-commands)
5. [Post-Exploitation Commands](#post-exploitation-commands)
6. [Advanced Chains](#advanced-chains)
7. [Batch Operations](#batch-operations)
8. [Operational Security](#operational-security)

---

## Quick Command Index

### Essential Commands (Copy & Paste Ready)

```bash
# Full Runehall assessment
python3 runehall_quick_commands.py runehall-full-assessment

# Quick vulnerability check
python3 runehall_quick_commands.py runehall-quick-check

# Complete OSINT
python3 runehall_quick_commands.py runehall-osint-complete

# Advanced reconnaissance
python3 runehall_quick_commands.py runehall-recon-advanced

# Exploitation suite
python3 runehall_quick_commands.py runehall-exploit-suite

# Post-exploitation
python3 runehall_quick_commands.py runehall-post-exploit
```

---

## OSINT Commands

Open-source intelligence gathering provides the foundation for all subsequent operations. These commands systematically collect publicly available information about Runehall.

### Basic OSINT Operations

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-osint-basic` | Basic OSINT gathering | `python3 runehall_quick_commands.py runehall-osint-basic` |
| `runehall-osint-complete` | Comprehensive OSINT suite | `python3 runehall_quick_commands.py runehall-osint-complete` |
| `runehall-osint-social` | Social media reconnaissance | `python3 runehall_quick_commands.py runehall-osint-social` |
| `runehall-osint-financial` | Financial information gathering | `python3 runehall_quick_commands.py runehall-osint-financial` |
| `runehall-osint-technical` | Technical infrastructure OSINT | `python3 runehall_quick_commands.py runehall-osint-technical` |

### Advanced OSINT Operations

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-osint-darkweb` | Dark web intelligence | `python3 runehall_quick_commands.py runehall-osint-darkweb` |
| `runehall-osint-breaches` | Breach database search | `python3 runehall_quick_commands.py runehall-osint-breaches` |
| `runehall-osint-leaks` | Data leak investigation | `python3 runehall_quick_commands.py runehall-osint-leaks` |
| `runehall-osint-employees` | Employee enumeration | `python3 runehall_quick_commands.py runehall-osint-employees` |
| `runehall-osint-infrastructure` | Infrastructure mapping | `python3 runehall_quick_commands.py runehall-osint-infrastructure` |

### OSINT Command Examples

**Complete OSINT with AI Analysis:**
```bash
python3 runehall_quick_commands.py runehall-osint-complete --ai-enabled --output json
```

**Social Media Reconnaissance:**
```bash
python3 runehall_quick_commands.py runehall-osint-social --deep-scan --include-archives
```

**Employee Enumeration:**
```bash
python3 runehall_quick_commands.py runehall-osint-employees --linkedin --github --twitter
```

---

## Reconnaissance Commands

Reconnaissance commands actively probe the target infrastructure while maintaining operational security.

### Infrastructure Reconnaissance

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-recon-dns` | DNS enumeration | `python3 runehall_quick_commands.py runehall-recon-dns` |
| `runehall-recon-subdomains` | Subdomain discovery | `python3 runehall_quick_commands.py runehall-recon-subdomains` |
| `runehall-recon-ports` | Port scanning | `python3 runehall_quick_commands.py runehall-recon-ports` |
| `runehall-recon-services` | Service identification | `python3 runehall_quick_commands.py runehall-recon-services` |
| `runehall-recon-certificates` | SSL/TLS certificate analysis | `python3 runehall_quick_commands.py runehall-recon-certificates` |

### Application Reconnaissance

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-recon-web` | Web application scanning | `python3 runehall_quick_commands.py runehall-recon-web` |
| `runehall-recon-api` | API endpoint discovery | `python3 runehall_quick_commands.py runehall-recon-api` |
| `runehall-recon-forms` | Form and input discovery | `python3 runehall_quick_commands.py runehall-recon-forms` |
| `runehall-recon-parameters` | Parameter enumeration | `python3 runehall_quick_commands.py runehall-recon-parameters` |
| `runehall-recon-technologies` | Technology stack identification | `python3 runehall_quick_commands.py runehall-recon-technologies` |

### User and Account Reconnaissance

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-recon-users` | User enumeration | `python3 runehall_quick_commands.py runehall-recon-users` |
| `runehall-recon-accounts` | Account discovery | `python3 runehall_quick_commands.py runehall-recon-accounts` |
| `runehall-recon-profiles` | User profile analysis | `python3 runehall_quick_commands.py runehall-recon-profiles` |
| `runehall-recon-permissions` | Permission mapping | `python3 runehall_quick_commands.py runehall-recon-permissions` |
| `runehall-recon-roles` | Role identification | `python3 runehall_quick_commands.py runehall-recon-roles` |

### Advanced Reconnaissance

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-recon-advanced` | Full advanced reconnaissance | `python3 runehall_quick_commands.py runehall-recon-advanced` |
| `runehall-recon-behavioral` | Behavioral pattern analysis | `python3 runehall_quick_commands.py runehall-recon-behavioral` |
| `runehall-recon-traffic` | Traffic analysis | `python3 runehall_quick_commands.py runehall-recon-traffic` |
| `runehall-recon-timing` | Timing analysis | `python3 runehall_quick_commands.py runehall-recon-timing` |

### Reconnaissance Command Examples

**Full Infrastructure Reconnaissance:**
```bash
python3 runehall_quick_commands.py runehall-recon-advanced --threads 8 --timeout 600
```

**API Endpoint Discovery:**
```bash
python3 runehall_quick_commands.py runehall-recon-api --deep-scan --include-deprecated
```

**User Enumeration with Validation:**
```bash
python3 runehall_quick_commands.py runehall-recon-users --validate --export csv
```

---

## Exploitation Commands

Exploitation commands attempt to identify and exploit specific vulnerabilities.

### Authentication Exploitation

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-exploit-auth-bypass` | Authentication bypass | `python3 runehall_quick_commands.py runehall-exploit-auth-bypass` |
| `runehall-exploit-sqli-auth` | SQL injection in authentication | `python3 runehall_quick_commands.py runehall-exploit-sqli-auth` |
| `runehall-exploit-jwt` | JWT vulnerabilities | `python3 runehall_quick_commands.py runehall-exploit-jwt` |
| `runehall-exploit-session` | Session manipulation | `python3 runehall_quick_commands.py runehall-exploit-session` |
| `runehall-exploit-mfa-bypass` | MFA bypass attempts | `python3 runehall_quick_commands.py runehall-exploit-mfa-bypass` |

### Game Logic Exploitation

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-exploit-bet-manipulation` | Betting logic exploitation | `python3 runehall_quick_commands.py runehall-exploit-bet-manipulation` |
| `runehall-exploit-rng` | RNG manipulation | `python3 runehall_quick_commands.py runehall-exploit-rng` |
| `runehall-exploit-race-condition` | Race condition exploitation | `python3 runehall_quick_commands.py runehall-exploit-race-condition` |
| `runehall-exploit-integer-overflow` | Integer overflow exploitation | `python3 runehall_quick_commands.py runehall-exploit-integer-overflow` |
| `runehall-exploit-logic-bypass` | Game logic bypass | `python3 runehall_quick_commands.py runehall-exploit-logic-bypass` |

### Payment System Exploitation

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-exploit-payment-idor` | Payment IDOR exploitation | `python3 runehall_quick_commands.py runehall-exploit-payment-idor` |
| `runehall-exploit-payment-sqli` | SQL injection in payments | `python3 runehall_quick_commands.py runehall-exploit-payment-sqli` |
| `runehall-exploit-payment-manipulation` | Payment amount manipulation | `python3 runehall_quick_commands.py runehall-exploit-payment-manipulation` |
| `runehall-exploit-transaction-replay` | Transaction replay attacks | `python3 runehall_quick_commands.py runehall-exploit-transaction-replay` |
| `runehall-exploit-currency-conversion` | Currency conversion exploitation | `python3 runehall_quick_commands.py runehall-exploit-currency-conversion` |

### Web Exploitation

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-exploit-xss` | Cross-site scripting | `python3 runehall_quick_commands.py runehall-exploit-xss` |
| `runehall-exploit-csrf` | Cross-site request forgery | `python3 runehall_quick_commands.py runehall-exploit-csrf` |
| `runehall-exploit-lfi` | Local file inclusion | `python3 runehall_quick_commands.py runehall-exploit-lfi` |
| `runehall-exploit-rfi` | Remote file inclusion | `python3 runehall_quick_commands.py runehall-exploit-rfi` |
| `runehall-exploit-xxe` | XML external entity | `python3 runehall_quick_commands.py runehall-exploit-xxe` |

### Exploitation Command Examples

**Authentication Bypass with Multiple Vectors:**
```bash
python3 runehall_quick_commands.py runehall-exploit-auth-bypass --vectors all --ai-analysis
```

**Betting Logic Exploitation:**
```bash
python3 runehall_quick_commands.py runehall-exploit-bet-manipulation --deep-analysis --race-conditions
```

**Payment System IDOR:**
```bash
python3 runehall_quick_commands.py runehall-exploit-payment-idor --enumerate-ids --validate
```

---

## Post-Exploitation Commands

Post-exploitation commands maintain access and gather sensitive data after initial compromise.

### Data Exfiltration

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-post-data-extract` | Extract sensitive data | `python3 runehall_quick_commands.py runehall-post-data-extract` |
| `runehall-post-user-data` | Extract user data | `python3 runehall_quick_commands.py runehall-post-user-data` |
| `runehall-post-financial-data` | Extract financial data | `python3 runehall_quick_commands.py runehall-post-financial-data` |
| `runehall-post-transaction-history` | Extract transaction history | `python3 runehall_quick_commands.py runehall-post-transaction-history` |
| `runehall-post-account-data` | Extract account information | `python3 runehall_quick_commands.py runehall-post-account-data` |

### Persistence

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-post-persistence-account` | Create persistent account | `python3 runehall_quick_commands.py runehall-post-persistence-account` |
| `runehall-post-persistence-backdoor` | Install backdoor | `python3 runehall_quick_commands.py runehall-post-persistence-backdoor` |
| `runehall-post-persistence-token` | Create persistent token | `python3 runehall_quick_commands.py runehall-post-persistence-token` |
| `runehall-post-persistence-webhook` | Setup webhook persistence | `python3 runehall_quick_commands.py runehall-post-persistence-webhook` |

### Lateral Movement

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-post-lateral-movement` | Lateral movement detection | `python3 runehall_quick_commands.py runehall-post-lateral-movement` |
| `runehall-post-privilege-escalation` | Privilege escalation attempts | `python3 runehall_quick_commands.py runehall-post-privilege-escalation` |
| `runehall-post-account-takeover` | Account takeover | `python3 runehall_quick_commands.py runehall-post-account-takeover` |
| `runehall-post-admin-access` | Gain admin access | `python3 runehall_quick_commands.py runehall-post-admin-access` |

### Covering Tracks

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-post-log-cleanup` | Clean logs | `python3 runehall_quick_commands.py runehall-post-log-cleanup` |
| `runehall-post-evidence-removal` | Remove evidence | `python3 runehall_quick_commands.py runehall-post-evidence-removal` |
| `runehall-post-cache-clear` | Clear caches | `python3 runehall_quick_commands.py runehall-post-cache-clear` |
| `runehall-post-history-wipe` | Wipe history | `python3 runehall_quick_commands.py runehall-post-history-wipe` |

### Post-Exploitation Command Examples

**Extract All User Data:**
```bash
python3 runehall_quick_commands.py runehall-post-data-extract --all-data --export json --compress
```

**Create Persistent Access:**
```bash
python3 runehall_quick_commands.py runehall-post-persistence-account --hidden --backup-account
```

**Cover Tracks:**
```bash
python3 runehall_quick_commands.py runehall-post-log-cleanup --wipe-evidence --remove-artifacts
```

---

## Advanced Chains

Pre-configured exploitation chains that combine multiple operations in sequence.

### Complete Assessment Chains

| Chain | Description | Phases |
|-------|-------------|--------|
| `RUNEHALL_ELITE` | Complete compromise | OSINT → Recon → Exploit → Post-Exploit |
| `RUNEHALL_RAPID` | Fast exploitation | Quick Recon → High-Prob Exploit |
| `RUNEHALL_STEALTH` | Low-detection | Slow Recon → Careful Exploit → Cover Tracks |
| `RUNEHALL_DEEP` | Thorough analysis | Full OSINT → Deep Recon → All Vectors |

### Chain Execution

```bash
# Complete assessment
python3 runehall_exploitation_chains.py RUNEHALL_ELITE runehall.com

# Fast exploitation
python3 runehall_exploitation_chains.py RUNEHALL_RAPID runehall.com

# Stealthy operation
python3 runehall_exploitation_chains.py RUNEHALL_STEALTH runehall.com

# Deep analysis
python3 runehall_exploitation_chains.py RUNEHALL_DEEP runehall.com
```

---

## Batch Operations

Process multiple targets or operations efficiently.

### Batch Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-batch-osint` | Batch OSINT | `python3 runehall_quick_commands.py runehall-batch-osint targets.txt` |
| `runehall-batch-recon` | Batch reconnaissance | `python3 runehall_quick_commands.py runehall-batch-recon targets.txt` |
| `runehall-batch-exploit` | Batch exploitation | `python3 runehall_quick_commands.py runehall-batch-exploit targets.txt` |
| `runehall-batch-assessment` | Batch full assessment | `python3 runehall_quick_commands.py runehall-batch-assessment targets.txt` |

### Batch Operation Examples

**Batch OSINT on Multiple Targets:**
```bash
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "target3.com" >> targets.txt
python3 runehall_quick_commands.py runehall-batch-osint targets.txt --threads 4
```

**Batch Full Assessment:**
```bash
python3 runehall_quick_commands.py runehall-batch-assessment targets.txt --parallel --ai-analysis
```

---

## Operational Security

Commands for maintaining operational security during operations.

### OpSec Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `runehall-opsec-proxy-setup` | Setup proxy rotation | `python3 runehall_quick_commands.py runehall-opsec-proxy-setup proxies.txt` |
| `runehall-opsec-vpn-check` | Verify VPN connection | `python3 runehall_quick_commands.py runehall-opsec-vpn-check` |
| `runehall-opsec-fingerprint-minimize` | Minimize fingerprint | `python3 runehall_quick_commands.py runehall-opsec-fingerprint-minimize` |
| `runehall-opsec-timing-randomize` | Randomize request timing | `python3 runehall_quick_commands.py runehall-opsec-timing-randomize` |
| `runehall-opsec-user-agent-rotate` | Rotate user agents | `python3 runehall_quick_commands.py runehall-opsec-user-agent-rotate` |
| `runehall-opsec-logs-cleanup` | Clean local logs | `python3 runehall_quick_commands.py runehall-opsec-logs-cleanup` |
| `runehall-opsec-cache-clear` | Clear cache | `python3 runehall_quick_commands.py runehall-opsec-cache-clear` |

### OpSec Command Examples

**Setup Proxy Rotation:**
```bash
python3 runehall_quick_commands.py runehall-opsec-proxy-setup proxies.txt --rotation-interval 60
```

**Minimize Fingerprint:**
```bash
python3 runehall_quick_commands.py runehall-opsec-fingerprint-minimize --randomize-headers --spoof-browser
```

---

## Command Syntax and Options

### Common Options

All Runehall commands support these common options:

```bash
--threads N              # Number of concurrent threads (1-32)
--timeout N             # Operation timeout in seconds
--proxy URL             # Use specific proxy
--ai-enabled            # Enable Gemini AI analysis
--output FORMAT         # Output format (json, csv, html)
--export PATH           # Export results to file
--verbose               # Verbose output
--quiet                 # Minimal output
--deep-scan             # Perform deep scanning
--validate              # Validate findings
--compress              # Compress output
```

### Example Usage

**Full command with options:**
```bash
python3 runehall_quick_commands.py runehall-recon-advanced \
  --threads 8 \
  --timeout 600 \
  --ai-enabled \
  --output json \
  --export results.json \
  --deep-scan \
  --validate \
  --verbose
```

---

## Performance Recommendations

### For Speed (RAPID Mode)
```bash
python3 runehall_quick_commands.py runehall-full-assessment \
  --threads 16 \
  --timeout 120 \
  --quick-scan
```

### For Stealth (STEALTH Mode)
```bash
python3 runehall_quick_commands.py runehall-full-assessment \
  --threads 2 \
  --timeout 600 \
  --randomize-timing \
  --proxy-rotation \
  --minimize-fingerprint
```

### For Accuracy (PRECISION Mode)
```bash
python3 runehall_quick_commands.py runehall-full-assessment \
  --threads 4 \
  --timeout 900 \
  --validate \
  --deep-scan \
  --ai-analysis
```

---

## Integration with GUI

All commands can be executed through the GUI Dashboard:

1. Open GUI: `python3 nightfury_gui_gemini.py`
2. Select "Operations" tab
3. Choose "Runehall Specialized" from module dropdown
4. Select command from the list
5. Configure options
6. Click "Execute"

---

## Quick Reference Table

| Category | Command Count | Key Commands |
|----------|---------------|--------------|
| OSINT | 10 | runehall-osint-complete, runehall-osint-employees |
| Reconnaissance | 15 | runehall-recon-advanced, runehall-recon-api |
| Exploitation | 20 | runehall-exploit-auth-bypass, runehall-exploit-payment-idor |
| Post-Exploitation | 12 | runehall-post-data-extract, runehall-post-persistence |
| Chains | 4 | RUNEHALL_ELITE, RUNEHALL_RAPID |
| OpSec | 7 | runehall-opsec-proxy-setup, runehall-opsec-logs-cleanup |
| **Total** | **68** | **Comprehensive Runehall Coverage** |

---

## Getting Help

For detailed information on any command:

```bash
python3 runehall_quick_commands.py <command> --help
```

For framework documentation:
- USER_MANUAL.md - Complete user manual
- QUICK_START_GUIDE.md - Quick start guide
- TROUBLESHOOTING_ADVANCED.md - Advanced troubleshooting

---

**Ready to start? Pick a command and execute!**
