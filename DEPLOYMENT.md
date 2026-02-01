# NightFury Framework - Deployment Guide

**Repository:** https://github.com/No6love9/nightfury  
**Version:** 2.0  
**Status:** Private Repository

---

## Quick Deployment

### Prerequisites

- WSL2 with Kali Linux (recommended)
- Git installed
- Sudo access
- GitHub access configured

### One-Command Deployment

```bash
# Clone and deploy
git clone https://github.com/No6love9/nightfury.git
cd nightfury
sudo bash scripts/setup.sh
```

---

## Detailed Deployment Steps

### 1. Clone Repository

```bash
# Clone from GitHub
git clone https://github.com/No6love9/nightfury.git

# Navigate to directory
cd nightfury
```

### 2. Run Setup Script

```bash
# Execute setup with sudo
sudo bash scripts/setup.sh
```

The setup script will:
- Detect your environment (WSL2/Kali/Linux)
- Install all dependencies
- Configure the framework
- Set up authentication
- Create Windows integration (if WSL2)

### 3. Interactive Configuration

During setup, you'll be prompted for:

- **Operator Information**: Name, role, team
- **API Keys**: Gemini, OpenAI (optional)
- **OPSEC Level**: low/medium/high/paranoid
- **Module Selection**: Enable/disable modules
- **Export Settings**: Output formats

### 4. Finalize Installation

```bash
# Source shell configuration
source ~/.bashrc

# Verify installation
nightfury health
```

---

## Post-Deployment Configuration

### Change Default Password

**CRITICAL**: Change the default password immediately:

```bash
nightfury auth passwd admin nightfury2024 <NEW_PASSWORD>
```

### Configure API Keys

If you skipped API configuration during setup:

```bash
# Edit API keys file
nano /opt/nightfury/config/api_keys.yaml
```

Add your API keys:

```yaml
api_keys:
  gemini: "YOUR_GEMINI_API_KEY"
  openai: "YOUR_OPENAI_API_KEY"
```

### Adjust OPSEC Settings

Edit OPSEC rules to match your requirements:

```bash
nano /opt/nightfury/config/opsec_rules/default.yaml
```

---

## WSL2-Specific Configuration

### Windows Integration

The framework automatically creates:

- **C:\NightFury\exports** - Exported data
- **C:\NightFury\reports** - Generated reports
- **C:\NightFury\logs** - Operation logs

Access these from Windows Explorer or PowerShell.

### Network Configuration

For optimal WSL2 networking:

```bash
# Add to /etc/wsl.conf
[network]
generateResolvConf = false

# Configure DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

---

## Verification

### Health Check

```bash
# Run comprehensive health check
nightfury health
```

Expected output:
- ✓ WSL Version: WSL2
- ✓ Compatibility Score: 90+/100
- ✓ All core modules operational

### Test Commands

```bash
# View status
nightfury status

# Test OSINT module
nightfury dork example.com -s

# Start web interface
nightfury web
```

---

## Updating the Framework

### Pull Latest Changes

```bash
# Update from GitHub
cd /opt/nightfury
nightfury update
```

### Manual Update

```bash
cd /opt/nightfury
git pull origin master
```

---

## Backup and Restore

### Create Backup

```bash
# Backup configuration
nightfury backup nightfury_backup.tar.gz
```

### Restore from Backup

```bash
# Restore configuration
nightfury restore nightfury_backup.tar.gz
```

---

## Troubleshooting

### Setup Failed

Check the setup log:

```bash
cat /tmp/nightfury_setup_*.log
```

Resume from checkpoint:

```bash
# Setup will automatically resume from last successful phase
sudo bash scripts/setup.sh
```

### Permission Issues

Ensure proper permissions:

```bash
sudo chown -R $USER:$USER /opt/nightfury
sudo chmod +x /opt/nightfury/nightfury.sh
```

### Module Not Working

Check module status:

```bash
nightfury status
```

View error logs:

```bash
nightfury logs error
```

---

## Security Considerations

### Access Control

- **Default Codeword**: SHEBA
- **Default Admin**: admin / nightfury2024
- **Change immediately after deployment**

### OPSEC

- Configure OPSEC level in `/opt/nightfury/config/opsec_rules/default.yaml`
- Enable VPN/Proxy for operational use
- Review forensic countermeasures

### Network Security

- Web interface uses HTTPS (self-signed cert)
- Bind to localhost by default
- Configure firewall rules as needed

---

## Production Deployment

### Recommended Configuration

For production red team operations:

1. **OPSEC Level**: High or Paranoid
2. **VPN Required**: Yes
3. **Proxy Chain**: Enabled
4. **Log Encryption**: Enabled
5. **Auto Cleanup**: Enabled

### Multi-Operator Setup

Add additional operators:

```bash
# Add operator
nightfury auth add <username> <password> operator --created-by admin

# Add student
nightfury auth add <username> <password> student --created-by admin
```

### Monitoring

Enable continuous monitoring:

```bash
# Tail all logs
nightfury logs all

# Monitor specific log type
nightfury logs error
```

---

## Support

For issues or questions:

1. Check documentation in `/opt/nightfury/docs/`
2. Review logs in `/opt/nightfury/logs/`
3. Open issue on GitHub (private repository)

---

**Last Updated**: 2026-01-31  
**Deployed By**: D4M13N - OPSEC OWASP RED TEAM COORDINATOR
