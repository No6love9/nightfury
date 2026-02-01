└─$ cat kalirec.py
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import subprocess
import webbrowser

class KaliToolkitApp:
        self.root.geometry("1200x800")
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Linux All-in-One Toolkit")
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
