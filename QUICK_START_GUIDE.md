# NightFury Framework - Quick Start Guide

**Get up and running in 5 minutes**

---

## Installation (Choose One Method)

### Linux/macOS
```bash
git clone https://github.com/No6love9/nightfury.git
cd nightfury
bash setup-unix.sh
source nightfury_env/bin/activate
```

### Windows
```cmd
git clone https://github.com/No6love9/nightfury.git
cd nightfury
setup-windows.bat
nightfury_env\Scripts\activate.bat
```

### Universal (Any OS)
```bash
git clone https://github.com/No6love9/nightfury.git
cd nightfury
python3 setup.py
source nightfury_env/bin/activate  # Linux/macOS
# or
nightfury_env\Scripts\activate.bat  # Windows
```

---

## Start Using NightFury

### Option 1: GUI Dashboard (Recommended)
```bash
python3 nightfury_gui_gemini.py
```
Then open the GUI and start creating operations.

### Option 2: Quick Commands
```bash
# List all commands
python3 runehall_quick_commands.py list

# Run reconnaissance
python3 runehall_quick_commands.py recon-full runehall.com

# Run exploitation
python3 runehall_quick_commands.py exploit-all runehall.com
```

### Option 3: Exploitation Chains
```bash
# Run complete exploitation chain
python3 runehall_exploitation_chains.py ELITE_NEXUS runehall.com

# Run fast exploitation
python3 runehall_exploitation_chains.py RAPID_STRIKE runehall.com

# Run stealthy exploitation
python3 runehall_exploitation_chains.py STEALTH_OPERATION runehall.com
```

---

## Essential Commands

### Reconnaissance
```bash
python3 runehall_quick_commands.py recon-full <target>      # Full scan
python3 runehall_quick_commands.py recon-quick <target>     # Quick scan
python3 runehall_quick_commands.py recon-users <target>     # User enumeration
python3 runehall_quick_commands.py recon-chat <target>      # Chat analysis
python3 runehall_quick_commands.py recon-dns <target>       # DNS enumeration
```

### Exploitation
```bash
python3 runehall_quick_commands.py exploit-auth <target>    # Auth bypass
python3 runehall_quick_commands.py exploit-bet <target>     # Betting logic
python3 runehall_quick_commands.py exploit-payment <target> # Payment system
python3 runehall_quick_commands.py exploit-rng <target>     # RNG analysis
python3 runehall_quick_commands.py exploit-all <target>     # All vectors
```

### Reporting
```bash
python3 nightfury_reporting_engine.py                        # Generate reports
```

---

## Configure Gemini AI (Optional but Recommended)

### Get Free API Key
1. Visit: https://aistudio.google.com/app/apikeys
2. Click "Create API Key"
3. Copy the key

### Set API Key
```bash
export GEMINI_API_KEY='your-key-here'
```

Or set it in the GUI Settings tab.

---

## Directory Structure

```
nightfury/
├── nightfury_reports/      # Generated reports
├── nightfury_logs/         # Operation logs
├── nightfury_data/         # Cached data
├── nightfury_gui_gemini.py # GUI Dashboard
├── runehall_quick_commands.py
├── runehall_exploitation_chains.py
├── gemini_ai_integration.py
└── requirements.txt
```

---

## Common Workflows

### Workflow 1: Quick Vulnerability Assessment
```bash
python3 runehall_quick_commands.py recon-quick runehall.com
python3 runehall_quick_commands.py exploit-all runehall.com
python3 nightfury_reporting_engine.py
```

### Workflow 2: Comprehensive Penetration Test
```bash
python3 runehall_exploitation_chains.py ELITE_NEXUS runehall.com
python3 nightfury_reporting_engine.py
```

### Workflow 3: Stealthy Operation
```bash
python3 runehall_exploitation_chains.py STEALTH_OPERATION runehall.com
python3 nightfury_reporting_engine.py
```

---

## Troubleshooting

**Setup fails?**
```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

**GUI won't start?**
```bash
python3 -c "import PyQt5; print('OK')"
pip install PyQt5
```

**Gemini API not working?**
```bash
echo $GEMINI_API_KEY  # Verify key is set
```

---

## Next Steps

1. Read the full [USER_MANUAL.md](USER_MANUAL.md)
2. Check [RUNEHALL_QUICK_REFERENCE.md](RUNEHALL_QUICK_REFERENCE.md)
3. Review [GEMINI_SETUP.md](GEMINI_SETUP.md)
4. Visit GitHub: https://github.com/No6love9/nightfury

---

**Ready to start? Run your first command now!**
