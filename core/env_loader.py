import os
from pathlib import Path

def load_env(env_path=".env"):
    """
    Simple .env loader to avoid extra dependencies for core functionality.
    """
    env_file = Path(env_path)
    if not env_file.exists():
        return False
    
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                if key:
                    os.environ[key] = value
    return True

def get_env(key, default=None):
    """Helper to get environment variables with defaults."""
    return os.environ.get(key, default)
