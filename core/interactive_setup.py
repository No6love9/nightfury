#!/usr/bin/env python3
"""
NightFury Interactive Setup Wizard
Guided configuration for operators
"""

import os
import sys
import json
import getpass
from pathlib import Path
from typing import Dict, Any, Optional
import yaml


class InteractiveSetup:
    """Interactive configuration wizard"""
    
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.nightfury_home = Path("/opt/nightfury")
        self.config_dir = self.nightfury_home / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def run(self) -> Dict[str, Any]:
        """Run interactive setup wizard"""
        self.print_banner()
        
        print("\n" + "="*60)
        print("NightFury Framework - Interactive Setup Wizard")
        print("="*60 + "\n")
        
        # Operator Information
        self.setup_operator_info()
        
        # API Keys
        self.setup_api_keys()
        
        # OPSEC Settings
        self.setup_opsec_settings()
        
        # Module Configuration
        self.setup_modules()
        
        # Export Settings
        self.setup_export_settings()
        
        # Save configuration
        self.save_configuration()
        
        print("\n" + "="*60)
        print("Configuration Complete!")
        print("="*60 + "\n")
        
        return self.config
    
    def print_banner(self):
        """Print NightFury banner"""
        banner = """
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                        Professional Red Team Operations Framework
        """
        print(banner)
    
    def setup_operator_info(self):
        """Setup operator information"""
        print("\n[1/5] Operator Information")
        print("-" * 60)
        
        operator_name = self.prompt("Operator Name", default=os.getenv('USER', 'operator'))
        operator_role = self.prompt_choice(
            "Operator Role",
            choices=['admin', 'operator', 'student'],
            default='operator'
        )
        team_name = self.prompt("Team/Organization Name", default="Red Team")
        
        self.config['operator'] = {
            'name': operator_name,
            'role': operator_role,
            'team': team_name
        }
    
    def setup_api_keys(self):
        """Setup API keys"""
        print("\n[2/5] API Configuration")
        print("-" * 60)
        print("Configure API keys for AI-powered features (optional)")
        
        use_gemini = self.prompt_yes_no("Configure Gemini API?", default=False)
        
        api_keys = {}
        
        if use_gemini:
            gemini_key = self.prompt_password("Gemini API Key")
            if gemini_key:
                api_keys['gemini'] = gemini_key
        
        use_openai = self.prompt_yes_no("Configure OpenAI API?", default=False)
        if use_openai:
            openai_key = self.prompt_password("OpenAI API Key")
            if openai_key:
                api_keys['openai'] = openai_key
        
        self.config['api_keys'] = api_keys
        
        if api_keys:
            print(f"✓ Configured {len(api_keys)} API key(s)")
        else:
            print("⚠ No API keys configured - AI features will be disabled")
    
    def setup_opsec_settings(self):
        """Setup OPSEC settings"""
        print("\n[3/5] OPSEC Configuration")
        print("-" * 60)
        
        opsec_level = self.prompt_choice(
            "OPSEC Level",
            choices=['low', 'medium', 'high', 'paranoid'],
            default='high'
        )
        
        auto_cleanup = self.prompt_yes_no("Enable automatic log cleanup?", default=True)
        forensic_counter = self.prompt_yes_no("Enable forensic countermeasures?", default=True)
        
        self.config['opsec'] = {
            'level': opsec_level,
            'auto_cleanup': auto_cleanup,
            'forensic_countermeasures': forensic_counter,
            'min_beacon_time': 30 if opsec_level in ['high', 'paranoid'] else 10,
            'max_exfil_size': 1024 * 1024 if opsec_level == 'paranoid' else 10 * 1024 * 1024
        }
    
    def setup_modules(self):
        """Setup module configuration"""
        print("\n[4/5] Module Configuration")
        print("-" * 60)
        
        modules = {}
        
        # C2 Nexus
        enable_c2 = self.prompt_yes_no("Enable C2 Nexus module?", default=True)
        if enable_c2:
            modules['c2_nexus'] = {
                'enabled': True,
                'default_protocol': 'http',
                'beacon_interval': 60
            }
        
        # OSINT Engine
        enable_osint = self.prompt_yes_no("Enable OSINT Engine?", default=True)
        if enable_osint:
            modules['osint_engine'] = {
                'enabled': True,
                'google_dorking': True,
                'subdomain_enum': True
            }
        
        # Web Exploitation
        enable_web = self.prompt_yes_no("Enable Web Exploitation module?", default=True)
        if enable_web:
            modules['web_exploitation'] = {
                'enabled': True,
                'auto_scan': False
            }
        
        # Phantom Network
        enable_proxy = self.prompt_yes_no("Enable Phantom Network (Proxy)?", default=True)
        if enable_proxy:
            modules['phantom_network'] = {
                'enabled': True,
                'auto_chain': True
            }
        
        self.config['modules'] = modules
    
    def setup_export_settings(self):
        """Setup export settings"""
        print("\n[5/5] Export Configuration")
        print("-" * 60)
        
        export_formats = []
        
        if self.prompt_yes_no("Export to TXT?", default=True):
            export_formats.append('txt')
        
        if self.prompt_yes_no("Export to CSV?", default=True):
            export_formats.append('csv')
        
        if self.prompt_yes_no("Export to JSON?", default=True):
            export_formats.append('json')
        
        if self.prompt_yes_no("Export to PDF?", default=False):
            export_formats.append('pdf')
        
        # Windows integration for WSL
        windows_export = False
        if self.is_wsl():
            windows_export = self.prompt_yes_no(
                "Enable Windows export directory (C:\\NightFury)?",
                default=True
            )
        
        self.config['export'] = {
            'formats': export_formats,
            'auto_export': True,
            'windows_integration': windows_export
        }
    
    def save_configuration(self):
        """Save configuration to files"""
        print("\nSaving configuration...")
        
        # Save main configuration
        config_file = self.config_dir / "nightfury.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        print(f"✓ Configuration saved: {config_file}")
        
        # Save API keys separately (encrypted in production)
        if self.config.get('api_keys'):
            api_keys_file = self.config_dir / "api_keys.yaml"
            with open(api_keys_file, 'w') as f:
                yaml.dump({'api_keys': self.config['api_keys']}, f, default_flow_style=False)
            # Set restrictive permissions
            os.chmod(api_keys_file, 0o600)
            print(f"✓ API keys saved: {api_keys_file}")
        
        # Save OPSEC rules
        opsec_file = self.config_dir / "opsec_rules" / "default.yaml"
        opsec_file.parent.mkdir(parents=True, exist_ok=True)
        with open(opsec_file, 'w') as f:
            yaml.dump({'opsec': self.config['opsec']}, f, default_flow_style=False)
        print(f"✓ OPSEC rules saved: {opsec_file}")
    
    def prompt(self, message: str, default: Optional[str] = None) -> str:
        """Prompt user for input"""
        if default:
            prompt_text = f"{message} [{default}]: "
        else:
            prompt_text = f"{message}: "
        
        response = input(prompt_text).strip()
        return response if response else default
    
    def prompt_password(self, message: str) -> str:
        """Prompt for password (hidden input)"""
        return getpass.getpass(f"{message}: ")
    
    def prompt_yes_no(self, message: str, default: bool = True) -> bool:
        """Prompt for yes/no answer"""
        default_str = "Y/n" if default else "y/N"
        response = input(f"{message} [{default_str}]: ").strip().lower()
        
        if not response:
            return default
        
        return response in ['y', 'yes']
    
    def prompt_choice(self, message: str, choices: list, default: Optional[str] = None) -> str:
        """Prompt for choice from list"""
        print(f"\n{message}:")
        for i, choice in enumerate(choices, 1):
            marker = "*" if choice == default else " "
            print(f"  {marker} {i}. {choice}")
        
        while True:
            if default:
                prompt_text = f"Select [1-{len(choices)}] (default: {default}): "
            else:
                prompt_text = f"Select [1-{len(choices)}]: "
            
            response = input(prompt_text).strip()
            
            if not response and default:
                return default
            
            try:
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                pass
            
            print("Invalid choice, please try again")
    
    def is_wsl(self) -> bool:
        """Check if running in WSL"""
        try:
            with open('/proc/version', 'r') as f:
                return 'microsoft' in f.read().lower()
        except:
            return False


def main():
    """Main entry point"""
    try:
        setup = InteractiveSetup()
        config = setup.run()
        
        # Output configuration as JSON for shell script
        print("\n" + "="*60)
        print("Configuration JSON:")
        print(json.dumps(config, indent=2))
        
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n[!] Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Setup failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
