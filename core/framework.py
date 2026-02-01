import os
import sys
import json
import logging
import importlib
import readline
from typing import Dict, Any, List

class NightfuryFramework:
    def __init__(self):
        self.config = self.load_config()
        self.setup_logging()
        self.modules = {}
        self.current_module = None
        self.logger = logging.getLogger("NIGHTFURY")
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler("nightfury.log"),
                logging.StreamHandler()
            ]
        )

    def log(self, message: str, level: str = "info"):
        getattr(self.logger, level.lower())(message)

    def load_modules(self):
        modules_path = os.path.join(self.project_root, 'modules')
        if not os.path.exists(modules_path):
            os.makedirs(modules_path)
            return

        if self.project_root not in sys.path:
            sys.path.append(self.project_root)

        for root, _, files in os.walk(modules_path):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    rel_path = os.path.relpath(os.path.join(root, file), self.project_root)
                    module_path = rel_path.replace(os.path.sep, '.')[:-3]
                    try:
                        mod = importlib.import_module(module_path)
                        for name, obj in mod.__dict__.items():
                            if isinstance(obj, type) and name != 'BaseModule':
                                if any(base.__name__ == 'BaseModule' for base in obj.__bases__):
                                    module_instance = obj(self)
                                    m_name = getattr(module_instance, 'name', file[:-3])
                                    # Use category/name format like MSF
                                    category = os.path.basename(root)
                                    full_name = f"{category}/{m_name}"
                                    self.modules[full_name] = module_instance
                    except Exception as e:
                        self.log(f"Failed to load {module_path}: {e}", "error")

    def print_banner(self):
        banner = r"""
      _   _ _       _     _  _____                
     | \ | (_)     | |   | ||  ___|               
     |  \| |_  __ _| |__ | || |__ _   _ _ __ _   _ 
     | . ` | |/ _` | '_ \| ||  __| | | | '__| | | |
     | |\  | | (_| | | | | || |__| |_| | |  | |_| |
     |_| \_|_|\__, |_| |_|_|\____/\__,_|_|   \__, |
               __/ |                          __/ |
              |___/                          |___/ 
        """
        print("\033[1;31m" + banner + "\033[0m")
        print(f"       =[ Nightfury v2.0-dev                           ]")
        print(f" + -- --=[ {len(self.modules)} modules loaded                           ]\n")

    def start_cli(self):
        self.load_modules()
        self.print_banner()
        
        # Setup tab completion
        def completer(text, state):
            options = [cmd for cmd in ['help', 'use', 'set', 'show', 'run', 'exploit', 'back', 'exit', 'quit', 'list'] if cmd.startswith(text)]
            if self.current_module:
                options.extend([opt for opt in self.current_module.options if opt.startswith(text)])
            if text.startswith('exploit/') or text.startswith('recon/') or text.startswith('c2/'):
                options.extend([m for m in self.modules if m.startswith(text)])
            
            if state < len(options):
                return options[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

        while True:
            try:
                prompt = "nf"
                if self.current_module:
                    prompt += f" \033[1;31m{self.current_module.name}\033[0m"
                cmd_input = input(f"{prompt} > ").strip()
                if not cmd_input: continue
                
                parts = cmd_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ['exit', 'quit']: break
                elif cmd == 'help': self.show_help()
                elif cmd == 'show': self.handle_show(args)
                elif cmd == 'use': self.handle_use(args)
                elif cmd == 'set': self.handle_set(args)
                elif cmd == 'back': self.current_module = None
                elif cmd in ['run', 'exploit']: self.handle_run()
                else: print(f"[-] Unknown command: {cmd}")
            except KeyboardInterrupt: print("\n[*] Interrupt caught, use 'exit' to quit.")
            except EOFError: break
            except Exception as e: print(f"[-] Error: {e}")

    def show_help(self):
        print("\nCore Commands\n=============\n")
        print("  Command       Description")
        print("  -------       -----------")
        print("  help          Help menu")
        print("  use <mod>     Select a module")
        print("  show <type>   Displays modules of a given type, or 'options'")
        print("  set <var> <v> Sets a context-specific variable to a value")
        print("  run           Launch the current module")
        print("  back          Move back from the current context")
        print("  exit          Exit the framework\n")

    def handle_show(self, args):
        if not args: return
        target = args[0].lower()
        if target == 'modules':
            print("\nModules\n=======\n")
            print("  Name                          Description")
            print("  ----                          -----------")
            for name, mod in self.modules.items():
                print(f"  {name:30} {mod.description}")
            print("")
        elif target == 'options':
            if self.current_module:
                print(f"\nModule options ({self.current_module.name}):\n")
                print("  Name       Current Setting  Description")
                print("  ----       ---------------  -----------")
                for name, val in self.current_module.options.items():
                    print(f"  {name:10} {str(val):16} Module option")
                print("")
            else: print("[-] No module selected.")

    def handle_use(self, args):
        if not args: return
        name = args[0]
        if name in self.modules:
            self.current_module = self.modules[name]
        else:
            # Try to find by short name
            matches = [m for m in self.modules if m.endswith(f"/{name}")]
            if matches: self.current_module = self.modules[matches[0]]
            else: print(f"[-] Failed to load module: {name}")

    def handle_set(self, args):
        if len(args) < 2: return
        if self.current_module:
            self.current_module.options[args[0]] = args[1]
            print(f"{args[0]} => {args[1]}")
        else: print("[-] No module selected.")

    def handle_run(self):
        if self.current_module:
            print(f"[*] Launching {self.current_module.name}...")
            self.current_module.run([])
        else: print("[-] No module selected.")

if __name__ == "__main__":
    nf = NightfuryFramework()
    nf.start_cli()
