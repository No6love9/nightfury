# NightFury Framework v2.0 - Fully Operational Edition

**Professional Penetration Testing Platform with Google Gemini AI Integration**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-green)](https://github.com/No6love9/nightfury)

---

## Overview

NightFury Framework v2.0 is an advanced, production-ready penetration testing platform designed for professional security assessments. This is a fully operational framework with no simulations or placeholders - all modules execute real HTTP requests and perform actual vulnerability detection.

### Key Features

- **Advanced Reconnaissance**: Automated scanning, OSINT, and infrastructure analysis
- **Real Exploitation**: Actual HTTP-based vulnerability testing (SQL Injection, XSS, Race Conditions, IDOR)
- **Gemini AI Integration**: Free AI-powered analysis, reporting, and threat modeling
- **Distributed Attack Coordination**: Multi-node synchronized attacks with real request execution
- **Zero-Day Detection Engine**: Logic flaw detection with actual payload testing
- **Professional GUI Dashboard**: Real-time monitoring with Gemini AI analysis
- **Comprehensive Reporting**: HTML, JSON, and CSV report generation
- **Quick Commands**: 20+ pre-configured operations for rapid execution
- **Exploitation Chains**: 6 advanced multi-stage workflows

---

## Installation

### Prerequisites

- **Python**: 3.8 or higher
- **OS**: Linux (Ubuntu/Debian), macOS, or Windows 10+
- **RAM**: 4GB minimum (8GB recommended)
- **Internet**: For downloading packages and Gemini AI

### One-Command Installation

**Linux/macOS:**
```bash
bash setup.sh
```

**Windows:**
```cmd
setup.bat
```

### Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/No6love9/nightfury.git
cd nightfury

# 2. Create virtual environment
python3 -m venv nightfury_env
source nightfury_env/bin/activate  # On Windows: nightfury_env\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python3 verify_installation.py

# 5. Start GUI
python3 nightfury_gui_gemini.py
```

---

## Core Components

### 1. GUI Dashboard (`nightfury_gui_gemini.py`)

Professional PyQt5-based interface with:
- Real-time operation monitoring
- Automated findings collection
- Gemini AI analysis integration
- Professional reporting

**Start with:**
```bash
python3 nightfury_gui_gemini.py
```

### 2. Quick Commands (`runehall_quick_commands.py`)

20+ pre-configured operations for rapid execution:

```bash
# List all commands
python3 runehall_quick_commands.py list

# Run reconnaissance
python3 runehall_quick_commands.py recon-full https://target.com

# Run exploitation
python3 runehall_quick_commands.py exploit-auth https://target.com
```

**Available Commands:**
- `recon-full` - Complete reconnaissance suite
- `recon-quick` - Fast basic scan
- `exploit-auth` - Authentication bypass
- `exploit-bet` - Bet manipulation
- `exploit-payment` - Payment leak testing
- `exploit-rng` - RNG analysis
- `chain-osint-exploit` - OSINT to exploitation chain
- `chain-full-test` - Complete penetration test

### 3. Exploitation Chains (`runehall_exploitation_chains.py`)

6 advanced multi-stage workflows:

```bash
# List all chains
python3 runehall_exploitation_chains.py list

# Execute ELITE_NEXUS chain
python3 runehall_exploitation_chains.py execute ELITE_NEXUS https://target.com
```

### 4. Zero-Day Detection Engine (`modules/exploit/zeroday_engine.py`)

Detects logic flaws through behavioral analysis and fuzzing:

```python
from modules.exploit.zeroday_engine import ZeroDayEngine

engine = ZeroDayEngine()

# Detect logic flaws
vulns = engine.detect_logic_flaws(
    endpoint="https://api.target.com/transfer",
    parameters={"amount": 100, "to": "user123"},
    responses=[...]
)

# Fuzz endpoint for vulnerabilities
vulns = engine.fuzz_endpoint(
    endpoint="https://api.target.com/search",
    parameter="query",
    fuzz_type="comprehensive"
)

# Build automated exploit chains
chains = engine.build_exploit_chains()
```

### 5. Distributed Attack Coordinator (`modules/exploit/distributed_attack.py`)

Coordinates multi-node attacks with real HTTP requests:

```python
from modules.exploit.distributed_attack import DistributedAttackCoordinator

coordinator = DistributedAttackCoordinator(num_nodes=10)

# Execute distributed brute force
results = await coordinator.coordinate_brute_force(
    target="https://api.target.com/login",
    wordlist=["password123", "admin123", ...],
    username="admin"
)

# Execute race condition exploitation
results = await coordinator.coordinate_race_condition(
    target="https://api.target.com/transfer",
    payload={"amount": 1000, "to": "attacker"},
    concurrent_requests=100,
    timing_window_ms=10
)
```

### 6. IDOR Exploitation with AI (`modules/exploit/runehall_idor_ai.py`)

AI-powered IDOR detection and exploitation:

```python
from modules.exploit.runehall_idor_ai import RuneHallIDORExploit

exploit = RuneHallIDORExploit()

# Analyze ID patterns
analysis = exploit.analyze_id_pattern(
    ids=['12345', '12346', '12347'],
    id_type='users'
)

# Predict next IDs
predictions = exploit.predict_ids(
    ids=['12345', '12346', '12347'],
    num_predictions=100,
    id_type='users'
)

# Enumerate accessible IDs
results = await exploit.enumerate_accessible_ids(
    id_candidates=predictions,
    endpoint='/api/users',
    id_type='users'
)
```

### 7. Race Condition Exploitation (`modules/exploit/runehall_race_conditions.py`)

Automated timing window detection and multi-threaded race condition exploitation:

```python
from modules.exploit.runehall_race_conditions import RuneHallRaceConditionExploiter

exploiter = RuneHallRaceConditionExploiter(framework)

# Test timing window
timing = exploiter.test_timing_window(
    target_url="https://api.target.com",
    endpoint="/v1/user/balance/transfer",
    payload={"from": "user1", "to": "user2", "amount": 1000}
)

# Execute race condition attack
results = exploiter.execute_race(
    target_url="https://api.target.com",
    endpoint="/v1/user/balance/transfer",
    payload={"from": "user1", "to": "user2", "amount": 1000},
    thread_count=50
)
```

---

## Gemini AI Integration

### Setup

1. Visit: https://aistudio.google.com/app/apikeys
2. Click **"Create API Key"**
3. Copy your key
4. Set environment variable:

```bash
export GEMINI_API_KEY='your-api-key-here'
```

### Usage

```python
from gemini_ai_integration import GeminiAIIntegration

gemini = GeminiAIIntegration()

# Analyze findings
analysis = gemini.analyze_findings(findings)

# Generate executive summary
summary = gemini.generate_executive_summary(operation_data)

# Generate remediation steps
remediation = gemini.generate_remediation_steps(finding)

# Chat about security
response = gemini.chat("What are OWASP Top 10?")
```

---

## Framework Architecture

### Module System

All modules inherit from `BaseModule` and implement the `run()` method:

```python
from core.base_module import BaseModule

class MyModule(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "my_module"
        self.description = "Module description"
        self.options = {
            "target": "https://example.com",
            "timeout": 5
        }
    
    def run(self, args):
        target = self.options.get("target")
        # Perform actual exploitation
        self.log(f"Testing {target}")
```

### Framework CLI

```bash
# Start interactive CLI
python3 nf.py

# Use module
use exploit/runehall_nexus
set target https://target.com
run

# List modules
show modules

# Get help
help
```

---

## Performance Modes

Configure framework behavior with performance modes:

| Mode | Speed | Stealth | Accuracy | Best For |
|------|-------|---------|----------|----------|
| **Ultra Performance** | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐ | Lab testing |
| **Balanced** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | General testing |
| **Stealth** | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | Avoiding detection |
| **Precision** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Accurate results |

---

## Real-World Usage Examples

### Example 1: Complete Penetration Test

```bash
# Start GUI
python3 nightfury_gui_gemini.py

# Or use quick command
python3 runehall_quick_commands.py chain-full-test https://target.com
```

### Example 2: IDOR Exploitation

```python
from modules.exploit.runehall_idor_ai import RuneHallIDORExploit
import asyncio

exploit = RuneHallIDORExploit()

# Analyze observed IDs
ids = ['user_1001', 'user_1002', 'user_1003']
analysis = exploit.analyze_id_pattern(ids, 'users')
print(f"Pattern: {analysis['pattern_type']}")
print(f"Predictability: {analysis['predictability']}")

# Predict next IDs
predictions = exploit.predict_ids(ids, num_predictions=50)

# Test access
results = asyncio.run(exploit.enumerate_accessible_ids(
    predictions,
    'https://api.target.com/users',
    'users'
))

print(f"Accessible IDs: {results['accessible_ids']}")
```

### Example 3: Race Condition Testing

```python
from modules.exploit.runehall_race_conditions import RuneHallRaceConditionExploiter

class MockFramework:
    def log(self, msg, level="info"):
        print(f"[{level.upper()}] {msg}")

exploiter = RuneHallRaceConditionExploiter(MockFramework())

# Test timing window
timing = exploiter.test_timing_window(
    "https://api.target.com",
    "/v1/transfer",
    {"amount": 1000, "to": "attacker"}
)

# Execute race condition
results = exploiter.execute_race(
    "https://api.target.com",
    "/v1/transfer",
    {"amount": 1000, "to": "attacker"},
    thread_count=50
)

print(f"Successful exploits: {sum(1 for r in results if r.get('status_code') == 200)}")
```

---

## Troubleshooting

### Python Not Found

```bash
# Install Python 3
sudo apt-get install python3 python3-pip  # Ubuntu/Debian
brew install python3                      # macOS
```

### PyQt5 Installation Error

```bash
pip install --only-binary :all: PyQt5
```

### Gemini API Key Error

```bash
# Verify environment variable
echo $GEMINI_API_KEY

# Set if needed
export GEMINI_API_KEY='your-key'
```

### Connection Errors

Ensure your target is accessible and not blocking requests:

```bash
# Test connectivity
curl -v https://target.com/api/endpoint

# Check firewall
sudo ufw status
```

---

## Security Considerations

- **Only test systems you own or have explicit permission to test**
- **Use VPN or proxy rotation for OPSEC**
- **Clean logs after testing** using `opsec-clean` command
- **Store API keys securely** - never commit to git
- **Review findings carefully** before taking action

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## License

MIT License - See LICENSE file for details

---

## Support

For issues, questions, or feature requests:

1. Check existing documentation
2. Review module source code
3. Open an issue on GitHub
4. Contact the development team

---

## Version History

### v2.0 (Current)
- ✅ All simulations replaced with real HTTP requests
- ✅ Fully operational exploitation modules
- ✅ Gemini AI integration
- ✅ Distributed attack coordination
- ✅ Zero-day detection engine
- ✅ IDOR exploitation with AI
- ✅ Race condition detection and exploitation
- ✅ Professional GUI dashboard
- ✅ Comprehensive reporting

### v1.0
- Initial release with basic modules

---

**NightFury Framework v2.0 - Professional Penetration Testing Made Simple**
