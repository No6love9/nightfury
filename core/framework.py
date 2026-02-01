import os
import sys
import json
import logging
import importlib
from typing import Dict, Any

class NightfuryFramework:
    def __init__(self):
        self.config = self.load_config()
        self.setup_logging()
        self.modules = {}
        self.logger = logging.getLogger("NIGHTFURY")

    def load_config(self) -> Dict[str, Any]:
        config_path = 'nightfury_config.json'
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                try:
                    return json.load(f)
                except:
                    return {}
        return {}

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("nightfury.log"),
                logging.StreamHandler()
            ]
        )

    def log(self, message: str, level: str = "info"):
        if level.lower() == "info":
            self.logger.info(message)
        elif level.lower() == "warning":
            self.logger.warning(message)
        elif level.lower() == "error":
            self.logger.error(message)
        elif level.lower() == "critical":
            self.logger.critical(message)

    def load_modules(self):
        """Dynamically load modules from the modules directory."""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.join(project_root, 'modules')
        self.log(f"Loading modules from {modules_path}...")
        
        if not os.path.exists(modules_path):
            os.makedirs(modules_path)
            return

        for root, dirs, files in os.walk(modules_path):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    # Convert file path to module path
                    rel_path = os.path.relpath(os.path.join(root, file), project_root)
                    module_path = rel_path.replace(os.path.sep, '.')[:-3]
                    
                    try:
                        # Ensure the parent packages are in sys.path
                        if project_root not in sys.path:
                            sys.path.append(project_root)
                            
                        mod = importlib.import_module(module_path)
                        for name, obj in mod.__dict__.items():
                            if isinstance(obj, type) and name != 'BaseModule':
                                # Check if it inherits from BaseModule (checking by name to avoid import issues)
                                if any(base.__name__ == 'BaseModule' for base in obj.__bases__):
                                    module_instance = obj(self)
                                    self.modules[module_name := getattr(module_instance, 'name', file[:-3])] = module_instance
                                    self.log(f"Loaded module: {module_name}")
                    except Exception as e:
                        self.log(f"Failed to load module {module_path}: {e}", "error")

    def run_module(self, name: str, args: Any):
        if name in self.modules:
            try:
                self.modules[name].run(args)
            except Exception as e:
                self.log(f"Error running module {name}: {e}", "error")
        else:
            self.log(f"Module {name} not found.", "warning")

    def print_banner(self):
        banner = r"""
   _  _ _  ____ _  _ ___ ____ _  _ ____ _   _ 
   |\ | |  | __ |__|  |  |___ |  | |__/  \_/  
   | \| |  |__] |  |  |  |    |__| |  \   |   
                                              
           NIGHTFURY FRAMEWORK v1.2
        Enhanced & Modular Pentest Suite
        """
        print("\033[1;36m" + banner + "\033[0m")

    def install_dependencies(self):
        """Auto-install required dependencies."""
        deps = ["requests", "flask", "cryptography", "rich"]
        import subprocess
        for dep in deps:
            try:
                __import__(dep)
            except ImportError:
                self.log(f"Installing missing dependency: {dep}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep])

    def start_cli(self):
        try:
            import readline
        except ImportError:
            pass # Readline not available on Windows without pyreadline
            
        self.print_banner()
        self.install_dependencies()
        self.load_modules()
        
        while True:
            try:
                cmd_input = input("\033[1;32mnightfury\033[0m > ").strip()
                if not cmd_input: continue
                cmd = cmd_input.split()
                
                if cmd[0] in ['exit', 'quit']: break
                if cmd[0] == 'help':
                    print("\nAvailable commands:")
                    print("  help           Show this help message")
                    print("  list           List all available modules")
                    print("  info <module>  Show details about a module")
                    print("  use <module>   Execute a module")
                    print("  exit           Exit the framework\n")
                elif cmd[0] == 'list':
                    print("\nAvailable modules:")
                    for m in self.modules:
                        print(f"  - {m:15} : {getattr(self.modules[m], 'description', 'No description')}")
                    print("")
                elif cmd[0] == 'info':
                    if len(cmd) > 1:
                        m_name = cmd[1]
                        if m_name in self.modules:
                            m = self.modules[m_name]
                            print(f"\nModule: {m.name}")
                            print(f"Description: {m.description}")
                            print(f"Options: {m.options}\n")
                        else:
                            print(f"Module {m_name} not found.")
                    else:
                        print("Usage: info <module>")
                elif cmd[0] == 'use':
                    if len(cmd) > 1:
                        self.run_module(cmd[1], cmd[2:] if len(cmd) > 2 else [])
                    else:
                        print("Usage: use <module> [args]")
                else:
                    print(f"Unknown command: {cmd[0]}")
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit.")
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")
