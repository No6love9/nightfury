import os
import sys
import json
import logging
import importlib
import readline
import threading
import time
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

class NightfuryFramework:
    def __init__(self):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config = self.load_config()
        self.setup_logging()
        self.modules = {}
        self.current_module = None
        self.logger = logging.getLogger("NIGHTFURY")
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_workers", 10))
        self.running_tasks = []

    def load_config(self) -> Dict[str, Any]:
        config_path = os.path.join(self.project_root, 'nightfury_config.json')
        default_config = {
            "max_workers": 10,
            "timeout": 300,
            "verbose": True,
            "colors": True
        }
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[-] Error loading config: {e}")
        return default_config

    def setup_logging(self):
        log_file = os.path.join(self.project_root, "nightfury.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def log(self, message: str, level: str = "info"):
        level = level.lower()
        if level == "success":
            print(f"\033[1;32m[+]\033[0m {message}")
            self.logger.info(message)
        elif level == "error":
            print(f"\033[1;31m[-]\033[0m {message}")
            self.logger.error(message)
        elif level == "warning":
            print(f"\033[1;33m[!]\033[0m {message}")
            self.logger.warning(message)
        else:
            print(f"\033[1;34m[*]\033[0m {message}")
            self.logger.info(message)

    def load_modules(self):
        modules_path = os.path.join(self.project_root, 'modules')
        if not os.path.exists(modules_path):
            os.makedirs(modules_path)
            return

        if self.project_root not in sys.path:
            sys.path.append(self.project_root)

        self.modules = {}
        for root, _, files in os.walk(modules_path):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    rel_path = os.path.relpath(os.path.join(root, file), self.project_root)
                    module_import_path = rel_path.replace(os.path.sep, '.')[:-3]
                    try:
                        # Clear from sys.modules to allow reloading
                        if module_import_path in sys.modules:
                            importlib.reload(sys.modules[module_import_path])
                        mod = importlib.import_module(module_import_path)
                        
                        for name, obj in mod.__dict__.items():
                            if isinstance(obj, type) and name != 'BaseModule':
                                # Check if it inherits from BaseModule without string comparison
                                if any(base.__name__ == 'BaseModule' for base in obj.__bases__):
                                    instance = obj(self)
                                    m_name = getattr(instance, 'name', file[:-3])
                                    category = os.path.basename(root)
                                    full_name = f"{category}/{m_name}"
                                    self.modules[full_name] = instance
                    except Exception as e:
                        self.logger.error(f"Failed to load {module_import_path}: {e}")

    def print_banner(self):
        banner = r"""
    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗██╗   ██╗██████╗ ██╗   ██╗
    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                                             
                         HYPERION - RUNEHALL EDITION                       
        """
        if self.config.get("colors"):
            print("\033[1;35m" + banner + "\033[0m")
            print(f"       =[ \033[1;37mNightfury v2.1-PRO\033[0m                           ]")
            print(f" + -- --=[ {len(self.modules)} specialized modules loaded             ]\n")
        else:
            print(banner)
            print(f"       =[ Nightfury v2.1-PRO                           ]")
            print(f" + -- --=[ {len(self.modules)} specialized modules loaded             ]\n")

    def start_cli(self, args=None):
        self.load_modules()
        
        if args and len(args) > 0:
            self.handle_batch_mode(args)
            return

        self.print_banner()
        
        # Setup tab completion
        def completer(text, state):
            commands = ['help', 'use', 'set', 'show', 'run', 'exploit', 'back', 'exit', 'quit', 'list', 'reload', 'sessions']
            options = [cmd for cmd in commands if cmd.startswith(text)]
            
            if text.startswith('exploit/') or text.startswith('recon/') or text.startswith('c2/'):
                options.extend([m for m in self.modules if m.startswith(text)])
            elif self.current_module:
                options.extend([opt for opt in self.current_module.options if opt.startswith(text)])
            
            if state < len(options):
                return options[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

        while True:
            try:
                prompt = "\033[1;34mnf\033[0m"
                if self.current_module:
                    prompt += f" \033[1;31m{self.current_module.name}\033[0m"
                
                cmd_line = input(f"{prompt} > ").strip()
                if not cmd_line: continue
                
                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ['exit', 'quit']: break
                elif cmd == 'help': self.show_help()
                elif cmd == 'show': self.handle_show(args)
                elif cmd == 'use': self.handle_use(args)
                elif cmd == 'set': self.handle_set(args)
                elif cmd == 'back': self.current_module = None
                elif cmd in ['run', 'exploit']: self.handle_run()
                elif cmd == 'reload': self.load_modules(); self.log("Modules reloaded", "success")
                elif cmd == 'sessions': self.handle_sessions()
                else: self.log(f"Unknown command: {cmd}", "error")
            except KeyboardInterrupt: print("\n[*] Interrupt caught, use 'exit' to quit.")
            except EOFError: break
            except Exception as e: self.log(f"Error: {e}", "error")

    def show_help(self):
        help_text = """
Core Commands
=============

    Command       Description
    -------       -----------
    help          Help menu
    use <mod>     Select a module (e.g., use exploit/runehall_nexus)
    show <type>   Displays modules, options, or sessions
    set <var> <v> Sets a module-specific variable
    run           Launch the current module
    reload        Reload all modules from disk
    sessions      List active background tasks
    back          Move back from the current context
    exit          Exit the framework
"""
        print(help_text)

    def handle_show(self, args):
        if not args:
            self.log("Usage: show <modules|options|sessions>", "warning")
            return
        
        target = args[0].lower()
        if target == 'modules':
            print("\nModules\n=======\n")
            print(f"  {'Name':<35} {'Description'}")
            print(f"  {'-'*4:<35} {'-'*11}")
            for name, mod in sorted(self.modules.items()):
                print(f"  {name:<35} {mod.description}")
            print("")
        elif target == 'options':
            if self.current_module:
                print(f"\nModule options ({self.current_module.name}):\n")
                print(f"  {'Name':<15} {'Current Setting':<20} {'Description'}")
                print(f"  {'-'*4:<15} {'-'*15:<20} {'-'*11}")
                for name, val in self.current_module.options.items():
                    print(f"  {name:<15} {str(val):<20} Module option")
                print("")
            else: self.log("No module selected.", "error")
        elif target == 'sessions':
            self.handle_sessions()

    def handle_use(self, args):
        if not args:
            self.log("Usage: use <module_name>", "warning")
            return
        
        name = args[0]
        if name in self.modules:
            self.current_module = self.modules[name]
        else:
            # Try fuzzy matching
            matches = [m for m in self.modules if name in m]
            if len(matches) == 1:
                self.current_module = self.modules[matches[0]]
            elif len(matches) > 1:
                self.log(f"Multiple matches found: {', '.join(matches)}", "warning")
            else:
                self.log(f"Failed to load module: {name}", "error")

    def handle_set(self, args):
        if len(args) < 2:
            self.log("Usage: set <option> <value>", "warning")
            return
        
        if self.current_module:
            key, val = args[0], " ".join(args[1:])
            self.current_module.options[key] = val
            print(f"{key} => {val}")
        else: self.log("No module selected.", "error")

    def handle_run(self):
        if not self.current_module:
            self.log("No module selected.", "error")
            return

        self.log(f"Launching {self.current_module.name}...", "info")
        
        # Run in a separate thread to keep CLI responsive
        future = self.executor.submit(self.current_module.run, [])
        self.running_tasks.append({
            "module": self.current_module.name,
            "future": future,
            "start_time": time.time()
        })
        self.log(f"Module {self.current_module.name} started in background.", "success")

    def handle_sessions(self):
        print("\nActive Sessions / Background Tasks\n=================================\n")
        print(f"  {'ID':<5} {'Module':<25} {'Status':<15} {'Runtime'}")
        print(f"  {'-'*2:<5} {'-'*6:<25} {'-'*6:<15} {'-'*7}")
        
        active_tasks = []
        for i, task in enumerate(self.running_tasks):
            status = "Running"
            if task["future"].done():
                status = "Finished"
                try:
                    task["future"].result()
                except Exception as e:
                    status = f"Failed ({e})"
            
            runtime = int(time.time() - task["start_time"])
            print(f"  {i:<5} {task['module']:<25} {status:<15} {runtime}s")
            
            if not task["future"].done():
                active_tasks.append(task)
        
        # Cleanup finished tasks (optional, maybe keep for history)
        # self.running_tasks = active_tasks
        print("")

    def handle_batch_mode(self, args):
        # Implementation for non-interactive execution
        import argparse
        parser = argparse.ArgumentParser(description='Nightfury Batch Mode')
        parser.add_argument('--module', required=True, help='Module to run')
        parser.add_argument('--options', nargs='*', help='Options in key=value format')
        
        parsed, unknown = parser.parse_known_args(args)
        
        if parsed.module in self.modules:
            module = self.modules[parsed.module]
            if parsed.options:
                for opt in parsed.options:
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                        module.options[k] = v
            
            self.log(f"Executing {parsed.module} in batch mode...", "info")
            module.run([])
        else:
            self.log(f"Module {parsed.module} not found.", "error")

if __name__ == "__main__":
    nf = NightfuryFramework()
    nf.start_cli()
