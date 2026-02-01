#!/usr/bin/env python3
import sys
import os

# Add the current directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.framework import NightfuryFramework

if __name__ == "__main__":
    try:
        app = NightfuryFramework()
        app.start_cli(sys.argv[1:])
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)
