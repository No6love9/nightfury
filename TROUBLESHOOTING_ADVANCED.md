# NightFury Framework - Troubleshooting & Advanced Usage Guide

---

## Troubleshooting

### Installation Issues

#### Problem: "Python 3 not found" or "python3: command not found"

**Cause**: Python 3 is not installed or not in the system PATH.

**Solution**:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
python3 --version
```

**CentOS/RHEL:**
```bash
sudo yum install python3 python3-pip
python3 --version
```

**macOS:**
```bash
brew install python3
python3 --version
```

**Windows:**
1. Download Python from https://www.python.org/downloads/
2. Run the installer
3. **Important**: Check "Add Python to PATH" during installation
4. Restart your terminal
5. Verify: `python --version`

---

#### Problem: "Permission denied" when running setup script

**Cause**: The setup script doesn't have execute permissions.

**Solution**:
```bash
chmod +x setup-unix.sh
bash setup-unix.sh
```

---

#### Problem: "pip: command not found"

**Cause**: pip is not installed or not in PATH.

**Solution**:

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-pip
```

**CentOS/RHEL:**
```bash
sudo yum install python3-pip
```

**macOS:**
```bash
brew install python3-pip
```

**Windows:**
```cmd
python -m ensurepip --upgrade
```

---

#### Problem: "No module named 'venv'"

**Cause**: Python venv module is not installed.

**Solution**:

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-venv
```

**CentOS/RHEL:**
```bash
sudo yum install python3-venv
```

**macOS:**
```bash
brew install python3-venv
```

---

#### Problem: Virtual environment activation fails

**Cause**: Virtual environment doesn't exist or activation script is missing.

**Solution**:

**Verify venv exists:**
```bash
ls -la nightfury_env/
```

**Recreate if missing:**
```bash
python3 -m venv nightfury_env
source nightfury_env/bin/activate  # Linux/macOS
# or
nightfury_env\Scripts\activate.bat  # Windows
```

---

#### Problem: "ModuleNotFoundError: No module named 'X'"

**Cause**: Required Python package is not installed.

**Solution**:

**Reinstall all dependencies:**
```bash
source nightfury_env/bin/activate  # Activate venv first
pip install --upgrade pip
pip install -r requirements.txt
```

**Install specific package:**
```bash
pip install <package_name>
```

---

### Runtime Issues

#### Problem: GUI fails to start with "No module named 'PyQt5'"

**Cause**: PyQt5 is not installed.

**Solution**:
```bash
source nightfury_env/bin/activate
pip install PyQt5==5.15.11
python3 nightfury_gui_gemini.py
```

---

#### Problem: "ModuleNotFoundError: No module named 'google.generativeai'"

**Cause**: Google Generative AI package is not installed.

**Solution**:
```bash
source nightfury_env/bin/activate
pip install google-generativeai
```

---

#### Problem: Gemini API key not working / "Invalid API key"

**Cause**: API key is invalid, expired, or not properly set.

**Solution**:

**Verify API key is set:**
```bash
echo $GEMINI_API_KEY
```

**If empty, set it:**
```bash
export GEMINI_API_KEY='your-actual-api-key'
```

**Verify API key is valid:**
1. Visit https://aistudio.google.com/app/apikeys
2. Check that your key is listed and active
3. If not, create a new key
4. Copy the full key (including any special characters)
5. Set it again: `export GEMINI_API_KEY='new-key'`

**Test the key:**
```python
import os
from google.generativeai import genai

api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("API key not set")
else:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    response = model.generate_content("Hello")
    print("API key works!")
```

---

#### Problem: Operations timeout / "Timeout exceeded"

**Cause**: Operation takes longer than configured timeout.

**Solution**:

**Increase timeout in GUI:**
1. Open GUI dashboard
2. Go to Settings tab
3. Increase "Timeout" value (in seconds)
4. Click Save

**Increase timeout via command line:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --timeout 600
```

**Use Precision mode (slower but more thorough):**
```bash
python3 setup.py --mode precision
```

---

#### Problem: "Out of memory" or "Memory error"

**Cause**: Too many threads or large dataset processing.

**Solution**:

**Reduce thread count in GUI:**
1. Go to Settings tab
2. Set "Thread Count" to 2-4
3. Click Save

**Reduce thread count via command line:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --threads 2
```

**Check system memory:**
```bash
free -h          # Linux
vm_stat          # macOS
wmic OS get TotalVisibleMemorySize  # Windows
```

---

#### Problem: "Connection refused" or "Network error"

**Cause**: Target is unreachable or network connectivity issue.

**Solution**:

**Test connectivity:**
```bash
ping runehall.com
curl -I https://runehall.com
```

**Check firewall:**
```bash
sudo ufw status  # Linux
sudo pfctl -s rules  # macOS
```

**Use proxy:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --proxy http://127.0.0.1:8080
```

---

#### Problem: "SSL certificate verification failed"

**Cause**: SSL certificate validation error.

**Solution**:

**Disable SSL verification (use with caution):**
```bash
export PYTHONHTTPSVERIFY=0
python3 runehall_quick_commands.py recon-full runehall.com
```

Or in code:
```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

---

### Performance Issues

#### Problem: Framework running slowly

**Cause**: Too many threads, large dataset, or system resource constraints.

**Solution**:

**Switch to Stealth mode:**
```bash
python3 setup.py --mode stealth
```

**Reduce thread count:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --threads 2
```

**Disable caching:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --no-cache
```

**Monitor system resources:**
```bash
top              # Linux/macOS
tasklist         # Windows
```

---

#### Problem: High CPU usage

**Cause**: Too many threads or intensive operations.

**Solution**:

**Reduce thread count:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --threads 1
```

**Increase timeout:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --timeout 600
```

---

### Data & Reporting Issues

#### Problem: Reports not generating / "Report generation failed"

**Cause**: Missing output directory or permission issues.

**Solution**:

**Create directories:**
```bash
mkdir -p nightfury_reports nightfury_logs nightfury_data
```

**Check permissions:**
```bash
ls -la nightfury_reports/
chmod -R 755 nightfury_reports/
```

**Generate report manually:**
```bash
python3 nightfury_reporting_engine.py --output-dir ./nightfury_reports
```

---

#### Problem: "No results found" or empty findings

**Cause**: Target is not vulnerable or operation didn't complete.

**Solution**:

**Check operation logs:**
```bash
tail -f nightfury_logs/operations.log
```

**Verify target is accessible:**
```bash
curl -I https://runehall.com
```

**Run with verbose logging:**
```bash
python3 runehall_quick_commands.py recon-full runehall.com --verbose
```

---

## Advanced Usage

### Custom Configuration

Edit `nightfury_config.json` to customize framework behavior:

```json
{
  "framework": {
    "mode": "balanced",
    "threads": 8,
    "timeout": 300,
    "max_retries": 3
  },
  "security": {
    "proxy_rotation": true,
    "evasion_enabled": true,
    "cache_enabled": true,
    "cache_size_mb": 1024
  },
  "ai": {
    "auto_analysis": true,
    "confidence_threshold": 0.85
  }
}
```

### Performance Modes

**Ultra Performance** (Fast, High Resource Usage):
```bash
python3 setup.py --mode ultra-performance
```
- 32 threads
- 30 second timeout
- No evasion
- Aggressive scanning

**Balanced** (Default):
```bash
python3 setup.py --mode balanced
```
- 8 threads
- 300 second timeout
- Standard evasion
- Moderate scanning

**Stealth** (Slow, Low Detection):
```bash
python3 setup.py --mode stealth
```
- 2 threads
- 600 second timeout
- Advanced evasion
- Conservative scanning

**Precision** (Thorough, Accurate):
```bash
python3 setup.py --mode precision
```
- 4 threads
- 900 second timeout
- Verification enabled
- Comprehensive scanning

### Custom Exploitation Chains

Create custom exploitation chains by modifying `runehall_exploitation_chains.py`:

```python
from runehall_exploitation_chains import ExploitationChain

# Create custom chain
custom_chain = ExploitationChain(
    name="CUSTOM_CHAIN",
    phases=[
        ("recon/runehall_scan", {"deep_scan": True}),
        ("exploit/runehall_nexus", {"vector": "auth_bypass"}),
        ("exploit/runehall_nexus", {"vector": "payment_leak"}),
    ],
    ai_analysis=True,
    proxy_rotation=True
)

# Execute chain
custom_chain.execute("runehall.com")
```

### Batch Operations

Process multiple targets:

```bash
# Create target list
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "target3.com" >> targets.txt

# Run batch operation
python3 runehall_quick_commands.py batch-users targets.txt
```

### Continuous Monitoring

Monitor a target continuously:

```bash
python3 runehall_quick_commands.py continuous-monitor runehall.com --interval 3600
```

This will scan the target every hour and generate reports.

### API Integration

Use NightFury as a library in your own code:

```python
from gemini_ai_integration import GeminiAI
from runehall_quick_commands import QuickCommands

# Initialize
qc = QuickCommands()
ai = GeminiAI(api_key="your-key")

# Run reconnaissance
findings = qc.recon_full("runehall.com")

# Analyze with AI
analysis = ai.analyze_findings(findings)

# Generate report
report = ai.generate_executive_summary(analysis)
print(report)
```

### Proxy Configuration

Configure proxy rotation:

```bash
# Create proxy list
echo "http://proxy1.com:8080" > proxies.txt
echo "http://proxy2.com:8080" >> proxies.txt
echo "socks5://proxy3.com:1080" >> proxies.txt

# Use proxies
python3 runehall_quick_commands.py opsec-proxy proxies.txt
python3 runehall_quick_commands.py recon-full runehall.com
```

### Logging and Debugging

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python3 nightfury_gui_gemini.py
```

View logs:

```bash
tail -f nightfury_logs/operations.log
tail -f nightfury_logs/errors.log
tail -f nightfury_logs/debug.log
```

---

## Performance Optimization

### Memory Optimization

```bash
# Reduce cache size
python3 runehall_quick_commands.py recon-full runehall.com --cache-size 256

# Disable caching
python3 runehall_quick_commands.py recon-full runehall.com --no-cache
```

### Network Optimization

```bash
# Increase timeout for slow networks
python3 runehall_quick_commands.py recon-full runehall.com --timeout 600

# Reduce thread count for limited bandwidth
python3 runehall_quick_commands.py recon-full runehall.com --threads 2
```

### CPU Optimization

```bash
# Use Stealth mode for CPU-constrained systems
python3 setup.py --mode stealth
```

---

## Security Best Practices

1. **Always get authorization** before testing any system
2. **Use VPN or proxy** to protect your identity
3. **Enable proxy rotation** for large-scale operations
4. **Use evasion techniques** to avoid detection
5. **Clean logs** after operations: `python3 runehall_quick_commands.py opsec-clean`
6. **Secure your API key**: Never commit it to version control
7. **Use strong passwords** for any accounts created during testing
8. **Document all operations** for compliance purposes

---

## Getting Help

- **GitHub Issues**: https://github.com/No6love9/nightfury/issues
- **Documentation**: See USER_MANUAL.md and QUICK_START_GUIDE.md
- **Gemini AI Docs**: https://ai.google.dev/
- **Python Docs**: https://docs.python.org/3/

---

**Need more help? Check the GitHub repository or open an issue!**
