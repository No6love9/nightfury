# NightFury Framework - Deployment Guide

**Repository:** https://github.com/no6love9/nightfury  
**Version:** 10.1-RUNEHALL  
**Status:** Production-Ready

---

## Quick Deployment

NightFury is optimized for WSL2 Kali Linux with a streamlined deployment process.

### One-Command Deployment

```bash
# Clone and deploy
git clone https://github.com/no6love9/nightfury.git
cd nightfury
./nightfury.sh setup
```

The setup command will:
- Detect your environment (WSL2/Kali/Linux)
- Install all dependencies
- Create a universal `.env` file from template
- Run the interactive configuration wizard

---

## Universal Configuration (.env)

NightFury now utilizes a universal `.env` file for all sensitive configurations. This allows you to easily import or copy-paste your environment fields.

### Key Fields

| Variable | Description | Default |
|----------|-------------|---------|
| `NF_MASTER_CODEWORD` | SHEBA Master Codeword | `SHEBA` |
| `OPENAI_API_KEY` | OpenAI API Key for AI Recon | `None` |
| `NF_C2_PORT` | C2 Listener Port | `8080` |
| `NF_ENCRYPTION_ENABLED` | Enable C2 Traffic Encryption | `true` |

To update your configuration:
```bash
nano .env
```

---

## Master Control Script (`nightfury.sh`)

The `nightfury.sh` script is the centralized management tool for the framework.

| Command | Action |
|---------|--------|
| `./nightfury.sh setup` | Initial installation and configuration |
| `./nightfury.sh run` | Launches the NightFury CLI |
| `./nightfury.sh status` | Checks system compatibility and environment |
| `./nightfury.sh clean` | Executes forensic cleanup of operation artifacts |

---

## Module System

Once the framework is running (`./nightfury.sh run`), you can use specialized modules:

### Featured Modules

- **recon/runehall_scan**: Unified scanner for Runehall targets (Subdomains + OSINT + Infra).
- **recon/ai_recon**: AI-powered target analysis and vulnerability prioritization.
- **recon/google_dorking**: Advanced automated Google search queries.
- **exploit/injection_engine**: Advanced payload delivery and overlay injection.

### CLI Commands

- `show modules`: List all available modules.
- `use <module>`: Select a module for use.
- `set <option> <value>`: Configure module parameters.
- `run`: Execute the current module.

---

## OPSEC & Anti-Forensics

NightFury is designed with operational security as a priority.

### Forensic Cleaner

To maintain a clean environment and remove artifacts after an operation:
```bash
./nightfury.sh clean
```
This securely clears bash history, removes temporary files, sanitizes logs, and clears memory caches.

---

## Verification

### Health Check
```bash
./nightfury.sh status
```
Expected output should show a high compatibility score and identify your WSL/Kali environment correctly.

---

**Last Updated**: 2026-02-02  
**Classification**: OPERATIONAL USE ONLY  
**Distribution**: RESTRICTED TO AUTHORIZED PERSONNEL
