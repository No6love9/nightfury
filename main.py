#!/usr/bin/env python3
import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.framework import NightfuryFramework

def main():
    framework = NightfuryFramework()
    framework.start_cli()

if __name__ == "__main__":
    main()
