# NightFury Framework Architecture

**Version:** 2.0  
**Status:** Production-Ready  
**Architecture:** Microservices  
**Deployment:** Single-Command  
**Access Control:** SHEBA-Protected

---

## Overview

NightFury is a comprehensive red team operations framework designed for professional penetration testing, OSINT reconnaissance, web exploitation, and command & control operations. Built specifically for WSL2 Kali Linux environments with seamless Windows integration.

## Core Principles

1. **Operational Security First** - All operations include forensic countermeasures
2. **AI-Enhanced Intelligence** - Gemini API integration for automated analysis
3. **Modular Architecture** - Independent modules with fallback mechanisms
4. **Role-Based Access** - Multi-tier operator permissions with SHEBA authentication
5. **Automated Reporting** - Real-time export to multiple formats (TXT, CSV, PDF, JSON)
6. **Error Resilience** - Comprehensive error handling with automatic recovery

---

## Directory Structure

```
nightfury/
├── nightfury.sh                 # Master control script
├── config/
│   ├── operators.yaml          # Role-based access control (SHEBA-protected)
│   ├── api_keys.yaml           # API credentials (encrypted)
│   ├── c2_profiles/            # Malleable C2 configurations
│   └── opsec_rules/            # Operational security policies
├── core/
│   ├── detection_engine.py     # WSL2/Kali/Windows auto-detection
│   ├── dependency_manager.py   # Smart dependency resolver
│   ├── error_handler.py        # Global exception management
│   ├── auth_manager.py         # SHEBA authentication system
│   └── interactive_setup.py    # Prompted configuration wizard
├── modules/
│   ├── c2_nexus/               # Command & Control operations
│   │   ├── beacon_generator.py # AI-powered beaconing patterns
│   │   ├── listener_http3.py   # HTTP/3 with QUIC support
│   │   └── payload_factory.py  # AV-evasion payload generation
│   ├── phantom_network/        # Network operations
│   │   ├── proxy_orchestrator.py # Multi-protocol proxy chains
│   │   ├── vpn_detector.py     # VPN/Proxy detection
│   │   └── traffic_morpher.py  # TLS fingerprint randomization
│   ├── ivory_tower/            # AI integration
│   │   ├── llm_integration.py  # Gemini/Claude API handlers
│   │   └── ai_analyst.py       # Automated analysis
│   ├── osint_engine/           # OSINT reconnaissance
│   │   ├── google_dorking.py   # Advanced Google Dork queries
│   │   ├── domain_profiler.py  # Domain reconnaissance
│   │   ├── subdomain_enum.py   # Subdomain enumeration
│   │   └── metadata_extractor.py # Document metadata analysis
│   └── web_exploitation/       # Web application testing
│       ├── vuln_scanner.py     # Vulnerability scanning
│       ├── sqli_engine.py      # SQL injection automation
│       ├── xss_tester.py       # XSS payload testing
│       └── auth_bypass.py      # Authentication bypass techniques
├── web_interface/
│   ├── server.py               # Flask + Socket.IO backend
│   ├── static/                 # React frontend assets
│   ├── templates/              # HTML templates
│   └── api/                    # REST API endpoints
├── utilities/
│   ├── forensic_cleaner.py     # WSL2 artifact removal
│   ├── report_builder.py       # Multi-format report generation
│   ├── log_manager.py          # Centralized logging
│   └── backup_manager.py       # Configuration backup/restore
├── data/
│   ├── exports/                # Automated data exports
│   └── reports/                # Generated reports
├── logs/                       # Operation logs
├── scripts/
│   ├── setup.sh                # One-command installation
│   ├── health_check.sh         # System validation
│   └── emergency_cleanup.sh    # Forensic cleanup
├── docs/                       # Documentation
└── tests/                      # Unit and integration tests
```

---

## Component Architecture

### 1. Core System

#### Detection Engine
- **Purpose:** Auto-detect WSL1/WSL2, Kali version, network configuration
- **Capabilities:** 
  - WSL version identification
  - Network stack analysis
  - VPN/Proxy detection
  - Firewall rule enumeration
  - System resource profiling

#### Dependency Manager
- **Purpose:** Intelligent package installation with fallbacks
- **Features:**
  - Automatic package resolution
  - Multiple package manager support (apt, pip, npm)
  - Offline mode with cached packages
  - Version conflict resolution

#### Error Handler
- **Purpose:** Global exception management with recovery
- **Strategies:**
  - Network failures → Offline mode
  - Permission errors → Privilege escalation or alternative methods
  - Resource exhaustion → Cleanup and retry
  - Security alerts → Sanitize and evacuate

#### Authentication Manager (SHEBA)
- **Purpose:** Secure access control with codeword authentication
- **Features:**
  - Multi-factor authentication
  - Role-based permissions (Admin, Operator, Student)
  - Session management
  - Audit logging

---

### 2. Module System

#### C2 Nexus (Command & Control)
- **AI-Powered Beaconing:** Gemini API generates evasive communication patterns
- **Protocol Support:** HTTP/3, QUIC, DNS, ICMP
- **Payload Generation:** Polymorphic implants with AV evasion
- **OPSEC Features:** 
  - Configurable jitter and sleep patterns
  - Domain fronting support
  - Traffic encryption
  - Anti-forensic measures

#### Phantom Network
- **Proxy Orchestration:** Multi-protocol proxy chains (SOCKS5, HTTP, V2Ray, Shadowsocks)
- **VPN Detection:** Identify active VPN connections
- **Traffic Morphing:** Randomize TLS fingerprints
- **Health Monitoring:** Automatic proxy failover

#### Ivory Tower (AI Integration)
- **LLM Integration:** Gemini, Claude, and OpenAI API support
- **Automated Analysis:** AI-powered vulnerability assessment
- **Report Generation:** Natural language security reports
- **Decision Support:** AI-recommended attack vectors

#### OSINT Engine
- **Google Dorking:** Advanced search query automation
- **Domain Profiling:** WHOIS, DNS, SSL certificate analysis
- **Subdomain Enumeration:** Passive and active discovery
- **Metadata Extraction:** Document and image metadata analysis
- **Social Media OSINT:** Profile and relationship mapping

#### Web Exploitation
- **Vulnerability Scanning:** Automated web app security testing
- **SQL Injection:** Advanced SQLi detection and exploitation
- **XSS Testing:** Reflected, stored, and DOM-based XSS
- **Authentication Bypass:** Session hijacking and privilege escalation
- **Directory Traversal:** Path traversal and file inclusion

---

### 3. Web Interface

#### Frontend (React)
- **Real-time Dashboard:** System health and module status
- **Interactive Terminal:** Web-based command execution
- **Proxy Builder:** Visual proxy chain configuration
- **C2 Controller:** Beacon management interface
- **Report Viewer:** Integrated report viewing

#### Backend (Flask + Socket.IO)
- **REST API:** Module control and data retrieval
- **WebSocket:** Real-time updates and notifications
- **Authentication:** SHEBA-based access control
- **Command Dispatcher:** Secure command execution

---

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Operator Interface                       │
│  (Web UI / CLI / API)                                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Authentication Layer (SHEBA)                    │
│  - Codeword verification                                    │
│  - Role-based access control                                │
│  - Session management                                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  Core Orchestration                          │
│  - Command routing                                          │
│  - Module coordination                                      │
│  - Error handling                                           │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┼───────────┬───────────┬────────────┐
         ▼           ▼           ▼           ▼            ▼
    ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐
    │C2 Nexus│  │Phantom │  │ Ivory  │  │ OSINT  │  │  Web   │
    │        │  │Network │  │ Tower  │  │ Engine │  │ Exploit│
    └────┬───┘  └────┬───┘  └────┬───┘  └────┬───┘  └────┬───┘
         │           │           │           │           │
         └───────────┴───────────┴───────────┴───────────┘
                              │
                              ▼
         ┌─────────────────────────────────────────────┐
         │         Data Processing & Export             │
         │  - Log aggregation                          │
         │  - Report generation (TXT/CSV/PDF/JSON)     │
         │  - Backup to WSL2 & Windows directories     │
         └─────────────────────────────────────────────┘
```

---

## Security Architecture

### OPSEC Measures

1. **Forensic Countermeasures**
   - Automatic log sanitization
   - Memory-only operation modes
   - Secure deletion of artifacts
   - Anti-forensic file timestamps

2. **Network Security**
   - Encrypted C2 communications
   - Proxy chain obfuscation
   - Traffic randomization
   - DNS over HTTPS (DoH)

3. **Access Control**
   - SHEBA codeword authentication
   - Role-based permissions
   - Command whitelisting
   - Audit logging

4. **Data Protection**
   - Encrypted configuration files
   - Secure API key storage
   - Encrypted report archives
   - Secure backup mechanisms

---

## Deployment Architecture

### WSL2 Integration

```
┌──────────────────────────────────────────────────────────┐
│                    Windows Host                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │              WSL2 Instance (Kali)                  │ │
│  │  ┌──────────────────────────────────────────────┐ │ │
│  │  │         NightFury Framework                  │ │ │
│  │  │  - Core modules                              │ │ │
│  │  │  - Web interface (localhost:7443)            │ │ │
│  │  │  - Data exports → /mnt/c/NightFury/          │ │ │
│  │  └──────────────────────────────────────────────┘ │ │
│  │                                                    │ │
│  │  Network Bridge: WSL2 ↔ Windows                   │ │
│  │  File Access: /mnt/c/ ↔ C:\                       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  Accessible from Windows:                                │
│  - https://localhost:7443 (Web UI)                       │
│  - C:\NightFury\exports\ (Reports)                       │
└──────────────────────────────────────────────────────────┘
```

---

## Performance Characteristics

- **Startup Time:** < 5 seconds (cached dependencies)
- **Memory Footprint:** ~500MB (base) + modules
- **Concurrent Operations:** Up to 100 parallel tasks
- **Report Generation:** < 2 seconds for standard reports
- **API Response Time:** < 100ms (local operations)

---

## Extensibility

### Adding New Modules

1. Create module directory in `modules/`
2. Implement module class with standard interface
3. Register module in `core/module_registry.py`
4. Add configuration template to `config/`
5. Update documentation

### Custom C2 Profiles

1. Create profile YAML in `config/c2_profiles/`
2. Define beacon parameters, headers, URIs
3. Specify OPSEC rules
4. Test with `nightfury.sh --test-c2-profile <name>`

### Integration with External Tools

- **API Endpoints:** RESTful API for external integrations
- **Webhook Support:** Real-time notifications
- **Plugin System:** Python-based plugin architecture
- **Data Export:** Standard formats (JSON, CSV, XML)

---

## Maintenance & Updates

### Automatic Updates
```bash
nightfury.sh --update
```

### Health Checks
```bash
nightfury.sh --health-check
```

### Backup & Restore
```bash
nightfury.sh --backup
nightfury.sh --restore <backup-file>
```

### Emergency Cleanup
```bash
nightfury.sh --emergency-cleanup
```

---

## Support & Documentation

- **Full Documentation:** `/docs/`
- **API Reference:** `/docs/API.md`
- **Module Guides:** `/docs/modules/`
- **Troubleshooting:** `/docs/TROUBLESHOOTING.md`
- **GitHub Repository:** [Private Repository]

---

**Classification:** OPERATIONAL USE ONLY  
**Distribution:** RESTRICTED TO AUTHORIZED PERSONNEL  
**Last Updated:** 2026-01-31
