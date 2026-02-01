import os
import subprocess
from datetime import datetime

class GitHubExporter:
    """
    Automates the export of reconnaissance data to the GitHub repository.
    Ensures that all findings are backed up and versioned.
    """
    def __init__(self, repo_path="/home/ubuntu/nightfury"):
        self.repo_path = repo_path

    def export_file(self, file_path, commit_message=None):
        """
        Adds, commits, and pushes a specific file to the GitHub repository.
        """
        if not os.path.exists(file_path):
            print(f"[!] File not found: {file_path}")
            return False

        if not commit_message:
            commit_message = f"Auto-export: {os.path.basename(file_path)} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        try:
            # Change directory to repo root
            os.chdir(self.repo_path)
            
            # Git operations
            subprocess.run(["git", "add", file_path], check=True)
            subprocess.run(["git", "commit", "-m", commit_message], check=True)
            subprocess.run(["git", "push", "origin", "master"], check=True)
            
            print(f"[+] Successfully exported {file_path} to GitHub.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Git export failed: {str(e)}")
            return False
        except Exception as e:
            print(f"[!] Unexpected error during export: {str(e)}")
            return False

if __name__ == "__main__":
    exporter = GitHubExporter()
    # Test with a dummy file if needed
