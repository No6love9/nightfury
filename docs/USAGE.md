# **Usage Guide**

This guide provides a comprehensive overview of how to use the **NightFury Framework**. It covers the main commands, modules, and workflows to help you get started with your red team operations.

## **Command-Line Interface (CLI)**

The primary way to interact with NightFury is through its command-line interface. The main command is `nightfury` (or its alias `nf`).

To see a full list of available commands, run:

```bash
nightfury --help
```

### **Core Commands**

- **`nightfury status`**: Displays the current status of the framework, including environment details, system resources, and module status.
- **`nightfury health`**: Runs a comprehensive health check to ensure all components are working correctly.
- **`nightfury web`**: Starts the web interface, which provides a real-time dashboard for monitoring and controlling the framework.
- **`nightfury stop`**: Stops all running NightFury services, including the web interface and any background tasks.

### **OSINT Commands**

- **`nightfury osint <domain>`**: Launches a full OSINT reconnaissance scan on the specified domain. This includes Google Dorking, subdomain enumeration, and domain profiling.
- **`nightfury dork <domain> [options]`**: Generates targeted Google Dorks for a domain. You can specify categories, output formats, and generate a full report.

### **Authentication Commands**

- **`nightfury auth login <user> <pass> --codeword <codeword>`**: Authenticates a user with their credentials and the **SHEBA** codeword.
- **`nightfury auth add <user> <pass> <role> --created-by <admin>`**: Adds a new operator to the framework (requires admin privileges).
- **`nightfury auth list`**: Lists all registered operators and their roles.
- **`nightfury auth passwd <user> <old> <new>`**: Changes the password for a specified user.

### **System Management**

- **`nightfury logs [type]`**: Tails the framework logs in real-time. You can specify `error`, `recovery`, `critical`, or `all`.
- **`nightfury update`**: Updates the framework to the latest version from the GitHub repository.
- **`nightfury backup [file]`**: Creates a backup of the framework's configuration.
- **`nightfury restore <file>`**: Restores the framework's configuration from a backup file.
- **`nightfury clean`**: Removes all logs and temporary files.

## **Web Interface**

NightFury includes a powerful web interface for real-time monitoring and control. To start it, run:

```bash
nightfury web
```

Then, open your browser and navigate to **`https://localhost:7443`**.

The web interface provides the following features:

- **Dashboard**: An overview of system health, active modules, and real-time alerts.
- **Interactive Terminal**: A web-based terminal for executing commands within the framework.
- **Module Control**: A graphical interface for managing and configuring modules.
- **Report Viewer**: An integrated viewer for all generated reports.

## **Workflows**

Here are some common workflows to help you get started:

### **1. Initial Reconnaissance**

Start by gathering information about your target domain:

```bash
# Run a full OSINT scan
nightfury osint example.com

# Generate a specific dork report
nightfury dork example.com -c sensitive_files -r
```

All results will be saved in the `/opt/nightfury/data/exports` directory.

### **2. Web Exploitation**

Once you have identified potential web vulnerabilities, you can use the web exploitation module to test them. This is typically done through the web interface, where you can configure and launch scans.

### **3. C2 Operations**

For more advanced operations, you can use the C2 Nexus module to generate payloads and establish command and control channels. The AI-powered beacon generator helps create evasive communication patterns to avoid detection.

### **4. Reporting**

Throughout your operation, NightFury automatically logs all activities and generates reports in your configured formats. You can access these reports in the `/opt/nightfury/data/reports` directory or through the web interface.

## **Operational Security (OPSEC)**

NightFury is designed with OPSEC in mind. Here are some key features to be aware of:

- **Forensic Cleaner**: The `nightfury clean` command can be used to remove all traces of your activity.
- **OPSEC Rules**: The OPSEC level can be configured in `/opt/nightfury/config/opsec_rules/default.yaml` to match your operational requirements.
- **SHEBA Authentication**: Access to the framework is protected by the **SHEBA** codeword, providing an additional layer of security.

## **Customization**

NightFury is highly customizable. You can modify the configuration files in `/opt/nightfury/config` to tailor the framework to your needs. This includes adding new C2 profiles, defining custom OPSEC rules, and configuring module settings.

For more advanced customization, you can develop your own modules and integrate them into the framework. See the [**Contribution Guide**](CONTRIBUTING.md) for more details.
