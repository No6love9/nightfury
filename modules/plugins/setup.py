from core.base_module import BaseModule
import json
import os

class Setup(BaseModule):
    def __init__(self, framework):
        super().__init__(framework)
        self.name = "setup"
        self.description = "Guided configuration for the Nightfury framework."
        self.options = {}

    def run(self, args):
        print("\n[*] Nightfury Guided Configuration\n")
        
        config = self.framework.config
        
        # General Settings
        print("[+] General Settings")
        config['lhost'] = input(f"    LHOST (current: {config.get('lhost', '127.0.0.1')}): ").strip() or config.get('lhost', '127.0.0.1')
        config['lport'] = input(f"    LPORT (current: {config.get('lport', '4444')}): ").strip() or config.get('lport', '4444')
        
        # C2 Settings
        print("\n[+] C2 Settings")
        config['c2_url'] = input(f"    C2 URL (current: {config.get('c2_url', 'http://c2.example.com')}): ").strip() or config.get('c2_url', 'http://c2.example.com')
        
        # Save config
        config_path = os.path.join(self.framework.project_root, 'nightfury_config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
            
        self.framework.config = config
        print(f"\n[+] Configuration saved to {config_path}")
        print("[*] Restart the framework to apply changes if necessary.\n")
