# NightFury Framework v1.2

**Professional Red Team Operations Platform**

---

## Overview

**NightFury** is a comprehensive, clandestine framework for professional red team operations. It provides a full-scope solution for penetration testing, OSINT reconnaissance, web exploitation, and command & control (C2) operations.

The framework has been recently enhanced with a **modular architecture** that allows for dynamic loading of modules, a unified CLI, and better organization of the extensive toolset.

---

## Key Features

- **Modular Architecture**: Easily add new modules to the `modules/` directory.
- **Dynamic Loading**: Modules are loaded at runtime.
- **Unified CLI**: A central command-line interface to manage all operations.
- **Auto-dependency Management**: Automatically installs required Python packages.
- **Integrated OSINT & Exploitation**: Includes tools for reconnaissance, payload generation, and web exploitation.
- **WSL2 Integration:** Seamless file and network integration between Kali Linux and Windows host.

---

## Directory Structure

- `main.py`: The primary entry point for the framework.
- `core/`: Core framework logic and base classes.
- `modules/`: Functional modules organized by category (recon, exploit, c2).
- `scripts/`: Standalone scripts and legacy tools.
- `web/`: Web-based tools and interfaces.
- `data/`: Logs, reports, and configuration files.
- `backups/`: Original versions of scripts and files.

---

## Getting Started

### Prerequisites

- **OS:** Kali Linux (recommended) or other Debian-based distribution
- **Python:** 3.8+
- **Permissions:** `sudo` access for installation

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/no6love9/nightfury.git
    cd nightfury
    ```

2.  **Run the framework:**

    ```bash
    python3 main.py
    ```

    The framework will automatically install any missing dependencies on the first run.

---

## Available Modules

### Reconnaissance
- `basic_recon`: Network scanning and port discovery.
- `osint`: Username and domain OSINT search.

### Exploitation
- `payload_gen`: Multi-platform reverse shell generator.
- `web_exploit`: SQLi and XSS vulnerability testing.

### Command & Control
- `c2_server`: Simple Flask-based C2 beacon receiver.

---

## Disclaimer

NightFury is intended for authorized security testing and educational purposes only. Any unauthorized use of this framework is strictly prohibited. The developers are not responsible for any misuse or damage caused by this tool.

**Always obtain proper authorization before conducting any security assessments.**

---

## License

This project is licensed under the **MIT License**.
