# NightFury Framework

**Version 2.0 | Professional Red Team Operations Platform**

---

![NightFury Banner](https://raw.githubusercontent.com/manus-team/nightfury-framework/main/assets/nightfury_banner.png)

---

## Overview

**NightFury** is a comprehensive, clandestine framework for professional red team operations, designed for elite security teams and educational purposes. It provides a full-scope solution for penetration testing, OSINT reconnaissance, web exploitation, and command & control (C2) operations, with a strong emphasis on operational security (OPSEC) and automation.

Built for **WSL2 Kali Linux** with seamless Windows integration, NightFury combines sophisticated tooling with an intuitive, modular architecture, making it accessible for both seasoned operators and students.

---

## Key Features

- **Automated Setup:** One-command installation with an interactive setup wizard for personalized configuration.
- **AI-Powered Intelligence:** Gemini API integration for automated analysis, C2 beacon generation, and decision support.
- **Advanced OSINT:** Comprehensive OSINT engine with automated Google Dorking, domain profiling, and subdomain enumeration.
- **Modular Architecture:** Independent modules for C2, OSINT, web exploitation, and network operations, with fallback mechanisms.
- **SHEBA Access Control:** Secure, role-based access control with codeword authentication (Admin, Operator, Student).
- **OPSEC First:** Built-in forensic countermeasures, log sanitization, and configurable OPSEC rules.
- **WSL2 Integration:** Seamless file and network integration between Kali Linux and Windows host.
- **Automated Reporting:** Real-time export of pentesting results to multiple formats (TXT, CSV, JSON, PDF).
- **Web Interface:** Real-time dashboard for system monitoring, module control, and interactive terminal.
- **Error Resilience:** Comprehensive error handling with automatic recovery and fallback strategies.

---

## Getting Started

### Prerequisites

- **OS:** Kali Linux (recommended) or other Debian-based distribution
- **Environment:** WSL2 (recommended) or native Linux
- **Permissions:** `sudo` access for installation

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/D4M13N/nightfury.git
    cd nightfury
    ```

2.  **Run the setup script:**

    ```bash
    sudo bash scripts/setup.sh
    ```

    The setup script will guide you through an interactive configuration process to tailor the framework to your needs.

3.  **Source your shell:**

    ```bash
    source ~/.bashrc
    ```

### Quick Start

- **View all commands:**

  ```bash
  nightfury --help
  ```

- **Run a health check:**

  ```bash
  nightfury health
  ```

- **Start the web interface:**

  ```bash
  nightfury web
  ```

  Access the dashboard at `https://localhost:7443`.

- **Run an OSINT scan:**

  ```bash
  nightfury osint example.com
  ```

---

## Documentation

For detailed information on installation, usage, and architecture, please refer to the `/docs` directory:

- **[Installation Guide](./docs/INSTALL.md)**
- **[Usage Guide](./docs/USAGE.md)**
- **[Architecture Overview](./docs/ARCHITECTURE.md)**
- **[Security Policy](./docs/SECURITY.md)**
- **[Contribution Guidelines](./docs/CONTRIBUTING.md)**

---

## Disclaimer

NightFury is intended for authorized security testing and educational purposes only. Any unauthorized use of this framework is strictly prohibited. The developers are not responsible for any misuse or damage caused by this tool.

**Always obtain proper authorization before conducting any security assessments.**

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](./LICENSE) file for details.
