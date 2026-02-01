import os
import sys
import yaml
import secrets
import string
from pathlib import Path

class NightFurySetup:
    """
    Interactive Setup Wizard for NightFury Framework.
    Optimized for WSL2 Kali Linux.
    """
    def __init__(self):
        self.home = Path("/home/ubuntu/nightfury")
        self.config_dir = self.home / "config"
        self.config_file = self.config_dir / "operators.yaml"
        self.colors = {
            "blue": "\033[94m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "red": "\033[91m",
            "end": "\033[0m",
            "bold": "\033[1m"
        }

    def _print_banner(self):
        print(f"{self.colors['blue']}{self.colors['bold']}")
        print("    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗")
        print("    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝")
        print("    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ ")
        print("    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  ")
        print("    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   ")
        print("    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ")
        print(f"                                SETUP WIZARD v2.6{self.colors['end']}")

    def _input(self, prompt, default=None):
        if default:
            val = input(f"{self.colors['yellow']}[?]{self.colors['end']} {prompt} [{default}]: ").strip()
            return val if val else default
        return input(f"{self.colors['yellow']}[?]{self.colors['end']} {prompt}: ").strip()

    def run(self):
        self._print_banner()
        print(f"\n{self.colors['green']}[*] Starting Interactive Configuration...{self.colors['end']}")
        
        config = {}
        
        # 1. Operator Identity
        print(f"\n{self.colors['bold']}--- Operator Identity ---{self.colors['end']}")
        config['operator_name'] = self._input("Enter Operator Name", "Nightshade")
        config['codeword'] = self._input("Set SHEBA Master Codeword", "SHEBA_2026")
        
        # 2. C2 Server Configuration
        print(f"\n{self.colors['bold']}--- C2 Server Configuration ---{self.colors['end']}")
        config['c2_host'] = self._input("C2 Listen Host", "0.0.0.0")
        config['c2_port'] = int(self._input("C2 Listen Port", "8080"))
        config['encryption_enabled'] = self._input("Enable Fernet Encryption? (y/n)", "y").lower() == 'y'
        
        # 3. WSL2/Kali Integration
        print(f"\n{self.colors['bold']}--- Environment Optimization ---{self.colors['end']}")
        config['wsl_integration'] = self._input("Enable WSL2 Windows Interop? (y/n)", "y").lower() == 'y'
        config['kali_repo_sync'] = self._input("Auto-sync with Kali repositories? (y/n)", "n").lower() == 'y'
        
        # 4. Save Configuration
        print(f"\n{self.colors['green']}[*] Saving configuration to {self.config_file}...{self.colors['end']}")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f)
            
        # 5. Generate Encryption Key if needed
        if config['encryption_enabled']:
            key_file = self.config_dir / "c2_encryption.key"
            if not key_file.exists():
                print(f"{self.colors['green']}[*] Generating fresh encryption key...{self.colors['end']}")
                from cryptography.fernet import Fernet
                with open(key_file, "wb") as kf:
                    kf.write(Fernet.generate_key())

        print(f"\n{self.colors['blue']}{self.colors['bold']}[+] Setup Complete! Welcome, {config['operator_name']}.{self.colors['end']}")
        print(f"{self.colors['blue']}Run './nightfury.sh status' to verify your installation.{self.colors['end']}")

if __name__ == "__main__":
    try:
        setup = NightFurySetup()
        setup.run()
    except KeyboardInterrupt:
        print("\n[!] Setup aborted.")
        sys.exit(1)
