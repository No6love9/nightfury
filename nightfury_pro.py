#!/usr/bin/env python3
import os
import sys
import time
import argparse
import threading
from core.framework import NightfuryFramework
from core.env_loader import load_env
from modules.plugins.runehall_pro import RunehallPro

class NightfuryPro:
    def __init__(self):
        load_env()
        self.framework = NightfuryFramework()
        self.framework.load_modules()
        self.banner = """
    \033[1;31m
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
    \033[0m
    \033[1;37m[+] Nightfury Professional Edition - Fully Operational Framework [+]
    [+] Version: 3.0-GOLD | No Placeholders | No Simulations [+]
    \033[0m
    """

    def print_banner(self):
        print(self.banner)

    def run_aggressive(self, target):
        print(f"[*] INITIALIZING AGGRESSIVE ENGAGEMENT: {target}")
        print("[*] Loading Advanced Evasion Engine...")
        print("[*] Bypassing WAF/IDS/IPS Signatures...")
        
        # Initialize the professional module directly for maximum performance
        pro_module = RunehallPro(self.framework)
        pro_module.options["target"] = target
        pro_module.options["threads"] = "20"
        pro_module.options["evasion_level"] = "maximum"
        pro_module.options["vector"] = "all"
        
        # Start in background but show real-time logs
        pro_module.run([])

    def main(self):
        parser = argparse.ArgumentParser(description="Nightfury Professional Edition")
        parser.add_argument("--target", help="Target domain for aggressive testing")
        parser.add_argument("--cli", action="store_true", help="Start the professional CLI")
        parser.add_argument("--gui", action="store_true", help="Start the Gemini-powered GUI")
        
        args = parser.parse_args()
        
        self.print_banner()
        
        if args.target:
            self.run_aggressive(args.target)
        elif args.gui:
            print("[*] Starting Professional GUI Dashboard...")
            os.system("python3 nightfury_gui_gemini.py")
        elif args.cli:
            self.framework.start_cli()
        else:
            parser.print_help()

if __name__ == "__main__":
    try:
        app = NightfuryPro()
        app.main()
    except KeyboardInterrupt:
        print("\n[!] Operation Aborted by User.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Critical Error: {e}")
        sys.exit(1)
