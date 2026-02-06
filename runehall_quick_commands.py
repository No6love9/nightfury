#!/usr/bin/env python3
"""
NightFury Runehall Quick Commands System
Advanced command shortcuts for rapid penetration testing operations
Version: 2.0 - Enhanced for maximum capabilities
"""

import os
import sys
import json
from typing import Dict, List, Optional
from datetime import datetime
from core.framework import NightfuryFramework

class RunehallQuickCommands:
    """Provides simplified, powerful commands for Runehall pentesting"""
    
    def __init__(self):
        self.commands = self._initialize_commands()
        self.execution_log = []
        self.framework = NightfuryFramework()
        self.framework.load_modules()
        
    def _initialize_commands(self) -> Dict:
        """Initialize all available quick commands"""
        return {
            # RECONNAISSANCE COMMANDS
            "recon-full": {
                "description": "Full reconnaissance suite on target",
                "modules": [
                    "recon/runehall_scan",
                    "recon/runehall_osint",
                    "recon/advanced_scan",
                    "recon/proxy_orchestrator"
                ],
                "config": {
                    "depth": "thorough",
                    "rotation_interval": "30"
                }
            },
            "recon-quick": {
                "description": "Quick reconnaissance scan",
                "modules": ["recon/runehall_scan"],
                "config": {"depth": "basic"}
            },
            "recon-users": {
                "description": "Scrape and analyze user data",
                "modules": [
                    "recon/user_scraper",
                    "recon/runehall_osint"
                ],
                "config": {"output": "users.json"}
            },
            "recon-chat": {
                "description": "Monitor real-time chat activity",
                "modules": ["recon/runehall_chat"],
                "config": {"monitor_duration": "continuous"}
            },
            "recon-dns": {
                "description": "Advanced DNS and infrastructure analysis",
                "modules": [
                    "recon/dns_bypass",
                    "recon/advanced_scan"
                ],
                "config": {"scan_type": "dns_enumeration"}
            },
            
            # EXPLOITATION COMMANDS
            "exploit-auth": {
                "description": "Authentication bypass testing",
                "modules": ["exploit/runehall_nexus"],
                "config": {"vector": "auth_bypass"}
            },
            "exploit-bet": {
                "description": "Bet manipulation and game logic testing",
                "modules": ["exploit/runehall_nexus"],
                "config": {"vector": "bet_manipulation"}
            },
            "exploit-payment": {
                "description": "Payment and PII leak testing",
                "modules": ["exploit/runehall_nexus"],
                "config": {"vector": "payment_leak"}
            },
            "exploit-rng": {
                "description": "RNG and game fairness analysis",
                "modules": ["exploit/runehall_nexus"],
                "config": {"vector": "game_logic"}
            },
            "exploit-all": {
                "description": "Execute all exploitation vectors sequentially",
                "modules": ["exploit/runehall_nexus"],
                "config": {"vector": "all"}
            },
            "exploit-web": {
                "description": "General web exploitation",
                "modules": [
                    "exploit/web_exploit",
                    "exploit/xss_generator",
                    "exploit/injection_engine"
                ],
                "config": {}
            },
            "exploit-race": {
                "description": "Race condition exploitation",
                "modules": ["exploit/runehall_race_conditions"],
                "config": {"thread_count": "50"}
            },
            "exploit-graphql": {
                "description": "GraphQL API exploitation",
                "modules": ["exploit/runehall_graphql"],
                "config": {"attack_type": "introspection"}
            },
            "exploit-session": {
                "description": "Session intelligence and hijacking",
                "modules": ["exploit/runehall_session_intel"],
                "config": {"analysis_mode": "predictive"}
            },
            "exfil-advanced": {
                "description": "Advanced data exfiltration",
                "modules": ["exploit/runehall_exfil_advanced"],
                "config": {"exfil_method": "dns"}
            },
            
            # ADVANCED COMMANDS
            "chain-osint-exploit": {
                "description": "Chain OSINT data gathering with targeted exploitation",
                "modules": [
                    "recon/user_scraper",
                    "recon/runehall_osint",
                    "exploit/runehall_nexus"
                ],
                "config": {"chain_mode": "enabled"}
            },
            "chain-full-test": {
                "description": "Complete penetration test workflow",
                "modules": [
                    "recon/runehall_scan",
                    "recon/advanced_scan",
                    "recon/runehall_osint",
                    "exploit/runehall_nexus",
                    "exploit/web_exploit"
                ],
                "config": {"workflow": "complete"}
            },
            "chain-monalisa": {
                "description": "Advanced access chain using monalisavivivi unlock key",
                "modules": [
                    "recon/runehall_scan",
                    "recon/runehall_osint",
                    "exploit/runehall_nexus_prime",
                    "exploit/runehall_idor_ai"
                ],
                "config": {
                    "unlock_key": "monalisavivivi",
                    "access_level": "maximum"
                }
            },
            "evasion-payload": {
                "description": "Generate evasive payloads with JIT compilation",
                "modules": ["exploit/jit_payload_gen"],
                "config": {
                    "evasion_techniques": "obfuscation,polymorphism,jit",
                    "payload_type": "javascript"
                }
            },
            "lateral-movement": {
                "description": "Execute lateral movement techniques",
                "modules": ["exploit/lateral_movement"],
                "config": {}
            },
            
            # AUTOMATION & BATCH COMMANDS
            "batch-users": {
                "description": "Batch test all discovered users",
                "modules": ["exploit/runehall_nexus"],
                "config": {"batch_mode": "enabled", "input_file": "users.json"}
            },
            "batch-vectors": {
                "description": "Batch test all exploitation vectors",
                "modules": ["exploit/runehall_nexus"],
                "config": {"batch_mode": "enabled", "test_all_vectors": "true"}
            },
            "continuous-monitor": {
                "description": "Continuous monitoring and exploitation",
                "modules": [
                    "recon/runehall_chat",
                    "recon/proxy_orchestrator",
                    "exploit/runehall_nexus"
                ],
                "config": {"continuous": "true", "interval": "60"}
            },
            
            # OPSEC COMMANDS
            "opsec-proxy": {
                "description": "Enable advanced proxy rotation and anonymization",
                "modules": ["recon/proxy_orchestrator"],
                "config": {
                    "rotation_interval": "15",
                    "proxy_diversity": "maximum"
                }
            },
            "opsec-clean": {
                "description": "Clean logs and remove traces",
                "modules": [],
                "config": {"cleanup": "enabled"}
            },
            
            # REPORTING & ANALYSIS
            "report-generate": {
                "description": "Generate comprehensive penetration test report",
                "modules": [],
                "config": {"report_format": "html"}
            },
            "analyze-results": {
                "description": "Analyze and correlate all findings",
                "modules": [],
                "config": {"analysis_depth": "comprehensive"}
            }
        }
    
    def list_commands(self) -> None:
        """Display all available quick commands"""
        print("\n" + "="*80)
        print("RUNEHALL QUICK COMMANDS - AVAILABLE OPERATIONS")
        print("="*80 + "\n")
        
        categories = {
            "RECONNAISSANCE": [k for k in self.commands.keys() if k.startswith("recon-")],
            "EXPLOITATION": [k for k in self.commands.keys() if k.startswith("exploit-")],
            "ADVANCED CHAINS": [k for k in self.commands.keys() if k.startswith("chain-")],
            "AUTOMATION": [k for k in self.commands.keys() if k.startswith("batch-") or k.startswith("continuous-")],
            "OPERATIONAL SECURITY": [k for k in self.commands.keys() if k.startswith("opsec-")],
            "REPORTING": [k for k in self.commands.keys() if k.startswith("report-") or k.startswith("analyze-")]
        }
        
        for category, cmds in categories.items():
            if cmds:
                print(f"\n[{category}]")
                print("-" * 80)
                for cmd in cmds:
                    desc = self.commands[cmd]["description"]
                    print(f"  {cmd:<25} → {desc}")
        
        print("\n" + "="*80 + "\n")
    
    def execute_command(self, command_name: str, target: str = "runehall.com", 
                       additional_config: Optional[Dict] = None) -> bool:
        """Execute a quick command with specified configuration"""
        
        if command_name not in self.commands:
            print(f"[ERROR] Command '{command_name}' not found")
            return False
        
        cmd_config = self.commands[command_name]
        print(f"\n[*] Executing: {command_name}")
        print(f"[*] Description: {cmd_config['description']}")
        print(f"[*] Target: {target}")
        print(f"[*] Timestamp: {datetime.now().isoformat()}\n")
        
        # Merge additional config
        final_config = cmd_config["config"].copy()
        if additional_config:
            final_config.update(additional_config)
        
        # Execute modules
        for module_name in cmd_config["modules"]:
            if module_name in self.framework.modules:
                module = self.framework.modules[module_name]
                print(f"[*] Running module: {module_name}")
                
                # Set options
                for key, value in final_config.items():
                    if key in module.options:
                        module.options[key] = value
                
                # Set target
                for key in ['target', 'target_url', 'domain']:
                    if key in module.options:
                        module.options[key] = target
                
                try:
                    module.run([])
                except Exception as e:
                    print(f"[-] Error running module {module_name}: {e}")
            else:
                print(f"[-] Module {module_name} not found in framework")
        
        # Log execution
        self.execution_log.append({
            "timestamp": datetime.now().isoformat(),
            "command": command_name,
            "target": target,
            "status": "completed"
        })
        
        return True

    def create_custom_command(self, name: str, modules: List[str], 
                            description: str, config: Dict) -> None:
        """Create a custom quick command"""
        self.commands[name] = {
            "description": description,
            "modules": modules,
            "config": config
        }
        print(f"[+] Custom command '{name}' created successfully")
    
    def export_commands(self, filename: str = "runehall_commands.json") -> None:
        """Export all commands to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.commands, f, indent=2)
        print(f"[+] Commands exported to {filename}")
    
    def get_command_info(self, command_name: str) -> Optional[Dict]:
        """Get detailed information about a specific command"""
        return self.commands.get(command_name)


def main():
    """Main entry point for quick commands CLI"""
    qc = RunehallQuickCommands()
    
    if len(sys.argv) < 2:
        print("Usage: python3 runehall_quick_commands.py <command> [target] [options]")
        print("       python3 runehall_quick_commands.py list")
        print("       python3 runehall_quick_commands.py info <command>")
        qc.list_commands()
        return
    
    action = sys.argv[1]
    
    if action == "list":
        qc.list_commands()
    elif action == "info" and len(sys.argv) > 2:
        cmd_name = sys.argv[2]
        info = qc.get_command_info(cmd_name)
        if info:
            print(f"\n[*] Command: {cmd_name}")
            print(f"[*] Description: {info['description']}")
            print(f"[*] Modules: {', '.join(info['modules'])}")
            print(f"[*] Configuration: {json.dumps(info['config'], indent=2)}\n")
        else:
            print(f"[ERROR] Command '{cmd_name}' not found")
    else:
        target = sys.argv[2] if len(sys.argv) > 2 else "runehall.com"
        qc.execute_command(action, target)


if __name__ == "__main__":
    main()
