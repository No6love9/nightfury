> ✨ **FULL STACK/SCOPE ALL IN ONE SOLUTION**

# **Installation Guide**

This guide provides detailed instructions for installing the **NightFury Framework** on your system. The recommended environment is **WSL2 with Kali Linux**, but it can also be installed on other Debian-based distributions.

## **Prerequisites**

Before you begin, ensure your system meets the following requirements:

- **Operating System**: Kali Linux (recommended), Ubuntu, or Debian.
- **Environment**: WSL2 (recommended for Windows users) or a native Linux environment.
- **Permissions**: You must have `sudo` or `root` access to run the installation script.
- **Required Tools**: `git`, `python3`, and `pip3` must be installed. The setup script will attempt to install them if they are missing.

## **Installation Steps**

The installation process is designed to be straightforward with a single command. Follow these steps to get started:

### **1. Clone the Repository**

First, clone the NightFury repository from GitHub to your local machine:

```bash
# Clone the repository
git clone https://github.com/D4M13N/nightfury.git

# Navigate to the project directory
cd nightfury
```

### **2. Run the Setup Script**

Next, execute the master setup script with `sudo` privileges. This script will handle all dependencies, configurations, and installations.

```bash
# Run the setup script
sudo bash scripts/setup.sh
```

The setup script will perform the following actions:

- **Environment Check**: Detects your operating system and environment (WSL2, Kali, etc.).
- **Dependency Installation**: Installs all required system packages and Python libraries.
- **Framework Installation**: Copies the framework files to `/opt/nightfury`.
- **Interactive Setup**: Launches a wizard to help you configure the framework, including API keys, OPSEC settings, and module configurations.
- **Authentication Setup**: Initializes the **SHEBA** authentication system with a default admin account.
- **WSL2 Integration**: Sets up shared directories between your Kali instance and Windows host for seamless data access.

### **3. Interactive Configuration**

The setup script will prompt you for various configuration options. Here is an overview of what you will be asked to configure:

- **Operator Information**: Your name, role (admin, operator, or student), and team name.
- **API Keys**: Optionally, you can provide API keys for **Gemini** and other LLMs to enable AI-powered features.
- **OPSEC Level**: Choose from `low`, `medium`, `high`, or `paranoid` to set the operational security level.
- **Module Selection**: Enable or disable specific modules, such as the C2 Nexus, OSINT Engine, and Web Exploitation tools.
- **Export Settings**: Configure the default formats for exporting reports (e.g., TXT, CSV, PDF, JSON).

### **4. Finalize Installation**

Once the setup script is complete, you need to source your shell configuration to enable the custom aliases:

```bash
# Source your .bashrc file
source ~/.bashrc
```

This will activate the `nightfury` and `nf` commands for easy access to the framework.

## **Verifying the Installation**

To ensure the framework is installed correctly, you can run a comprehensive health check:

```bash
# Run the health check
nightfury health
```

This command will verify that all components are correctly installed and configured. If any issues are detected, it will provide recommendations for resolving them.

## **Default Credentials**

The installation creates a default administrator account with the following credentials:

- **Username**: `admin`
- **Password**: `nightfury2024`
- **Codeword**: `SHEBA`

> **IMPORTANT**: For security reasons, you must change the default password immediately after your first login. You can do this by running:
> `nightfury auth passwd admin <current_password> <new_password>`

## **Updating the Framework**

To update the framework to the latest version, navigate to the project directory and run:

```bash
# Update the framework
nightfury update
```

This will pull the latest changes from the GitHub repository and apply any necessary updates.

## **Troubleshooting**

If you encounter any issues during the installation, you can refer to the setup log for detailed information:

```bash
# View the setup log
cat /tmp/nightfury_setup_*.log
```

For additional support, please consult the [**Troubleshooting Guide**](TROUBLESHOOTING.md) or open an issue on the GitHub repository.
