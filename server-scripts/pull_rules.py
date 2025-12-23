#!/usr/bin/env python3
"""
Wazuh Server Rules Puller
Run on each Wazuh server node to pull rules from the central Git repo
COMPATIBLE WITH EXISTING REPO STRUCTURE - NO CHANGES NEEDED
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
import hashlib

class WazuhRulesPuller:
    def __init__(self, config_path="/etc/wazuh/puller_config.json"):
        self.config = self.load_config(config_path)
        self.backup_dir = Path(f"/backup/wazuh-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.repo_dir = Path(self.config.get("repo_clone_path", "/opt/wazuh-rules"))
        self.wazuh_rules_dir = Path("/var/ossec/etc/rules")
        self.wazuh_decoders_dir = Path("/var/ossec/etc/decoders")
    
    def load_config(self, config_path):
        """Load configuration file"""
        default_config = {
            "repo_url": "https://github.com/YOUR_ORG/YOUR_REPO.git",
            "branch": "main",
            "auto_restart": True,
            "create_backup": True,
            "server_id": "unknown"
        }
        
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def backup_current(self):
        """Backup current rules and decoders"""
        if not self.config.get("create_backup", True):
            return True
        
        print(f"Creating backup at {self.backup_dir}")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Backup rules
            if self.wazuh_rules_dir.exists():
                shutil.copytree(self.wazuh_rules_dir, self.backup_dir / "rules")
                print(f"  ✓ Rules backed up")
            
            # Backup decoders
            if self.wazuh_decoders_dir.exists():
                shutil.copytree(self.wazuh_decoders_dir, self.backup_dir / "decoders")
                print(f"  ✓ Decoders backed up")
            
            return True
        except Exception as e:
            print(f"  ✗ Backup failed: {e}")
            return False
    
    def clone_or_pull_repo(self):
        """Clone or update the repository"""
        try:
            if self.repo_dir.exists():
                # Update existing repo
                print(f"Updating repository at {self.repo_dir}")
                os.chdir(self.repo_dir)
                
                # Fetch latest
                subprocess.run(["git", "fetch", "origin"], check=True, capture_output=True)
                
                # Checkout specified branch
                branch = self.config.get("branch", "main")
                subprocess.run(["git", "checkout", branch], check=True, capture_output=True)
                subprocess.run(["git", "pull", "origin", branch], check=True, capture_output=True)
                
                print(f"  ✓ Repository updated to latest {branch}")
            else:
                # Clone new repo
                print(f"Cloning repository to {self.repo_dir}")
                self.repo_dir.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["git", "clone", self.config["repo_url"], str(self.repo_dir)],
                    check=True,
                    capture_output=True
                )
                
                # Checkout specified branch
                branch = self.config.get("branch", "main")
                os.chdir(self.repo_dir)
                subprocess.run(["git", "checkout", branch], check=True, capture_output=True)
                
                print(f"  ✓ Repository cloned to {self.repo_dir}")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Git operation failed: {e.stderr.decode() if e.stderr else e}")
            return False
        except Exception as e:
            print(f"  ✗ Repository operation failed: {e}")
            return False
    
    def deploy_files(self):
        """Deploy rules and decoders to Wazuh"""
        print("Deploying files to Wazuh...")
        
        # Ensure target directories exist
        self.wazuh_rules_dir.mkdir(parents=True, exist_ok=True)
        self.wazuh_decoders_dir.mkdir(parents=True, exist_ok=True)
        
        rule_count = 0
        decoder_count = 0
        
        # Deploy rules
        repo_rules_dir = self.repo_dir / "rules"
        if repo_rules_dir.exists():
            # Clear existing rules
            for xml_file in self.wazuh_rules_dir.glob("*.xml"):
                xml_file.unlink()
            
            # Copy new rules
            for xml_file in repo_rules_dir.glob("*.xml"):
                shutil.copy2(xml_file, self.wazuh_rules_dir / xml_file.name)
                rule_count += 1
        
        # Deploy decoders
        repo_decoders_dir = self.repo_dir / "decoders"
        if repo_decoders_dir.exists():
            # Clear existing decoders
            for xml_file in self.wazuh_decoders_dir.glob("*.xml"):
                xml_file.unlink()
            
            # Copy new decoders
            for xml_file in repo_decoders_dir.glob("*.xml"):
                shutil.copy2(xml_file, self.wazuh_decoders_dir / xml_file.name)
                decoder_count += 1
        
        # Set permissions (same as your existing workflow)
        subprocess.run(
            ["chown", "-R", "wazuh:wazuh", str(self.wazuh_rules_dir)], 
            check=False, capture_output=True
        )
        subprocess.run(
            ["chown", "-R", "wazuh:wazuh", str(self.wazuh_decoders_dir)], 
            check=False, capture_output=True
        )
        
        print(f"  ✓ Deployed {rule_count} rules and {decoder_count} decoders")
        return rule_count, decoder_count
    
    def restart_wazuh(self):
        """Restart Wazuh manager if configured"""
        if not self.config.get("auto_restart", True):
            print("Auto-restart disabled in config")
            return True
        
        try:
            print("Restarting Wazuh manager...")
            result = subprocess.run(
                ["systemctl", "restart", "wazuh-manager"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("  ✓ Wazuh manager restarted successfully")
                
                # Verify it's running
                subprocess.run(
                    ["systemctl", "is-active", "wazuh-manager"],
                    check=True,
                    capture_output=True
                )
                return True
            else:
                print(f"  ✗ Failed to restart Wazuh: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("  ✗ Restart timed out")
            return False
        except Exception as e:
            print(f"  ✗ Error restarting Wazuh: {e}")
            return False
    
    def rollback(self):
        """Rollback to backup if deployment failed"""
        if not self.backup_dir.exists():
            print("No backup found for rollback")
            return False
        
        print(f"Rolling back to backup: {self.backup_dir}")
        
        try:
            # Restore rules
            backup_rules = self.backup_dir / "rules"
            if backup_rules.exists():
                shutil.rmtree(self.wazuh_rules_dir, ignore_errors=True)
                shutil.copytree(backup_rules, self.wazuh_rules_dir)
            
            # Restore decoders
            backup_decoders = self.backup_dir / "decoders"
            if backup_decoders.exists():
                shutil.rmtree(self.wazuh_decoders_dir, ignore_errors=True)
                shutil.copytree(backup_decoders, self.wazuh_decoders_dir)
            
            print("  ✓ Rollback completed")
            
            # Restart to apply rollback
            if self.config.get("auto_restart", True):
                self.restart_wazuh()
            
            return True
        except Exception as e:
            print(f"  ✗ Rollback failed: {e}")
            return False
    
    def pull_and_deploy(self, force=False):
        """Main method to pull and deploy"""
        print(f"=== Wazuh Rules Pull - Server: {self.config.get('server_id', 'unknown')} ===")
        print(f"Repository: {self.config['repo_url']}")
        print(f"Branch: {self.config.get('branch', 'main')}")
        print("-" * 50)
        
        # Step 1: Backup
        if not self.backup_current():
            if not force:
                print("Backup failed. Aborting.")
                return False
        
        # Step 2: Update repository
        if not self.clone_or_pull_repo():
            print("Failed to update repository. Aborting.")
            return False
        
        # Step 3: Deploy
        try:
            rule_count, decoder_count = self.deploy_files()
            
            # Step 4: Restart if needed
            if rule_count > 0 or decoder_count > 0:
                restart_success = self.restart_wazuh()
                if not restart_success:
                    print("Wazuh restart failed, attempting rollback...")
                    self.rollback()
                    return False
            else:
                print("No files to deploy")
            
            print(f"\n✓ Successfully deployed rules from repository")
            print(f"  Rules: {rule_count} files")
            print(f"  Decoders: {decoder_count} files")
            print(f"  Backup: {self.backup_dir}")
            
            # Log the deployment
            self.log_deployment(True, rule_count, decoder_count)
            return True
            
        except Exception as e:
            print(f"\n✗ Deployment failed: {e}")
            print("Attempting rollback...")
            self.rollback()
            self.log_deployment(False, 0, 0, str(e))
            return False
    
    def log_deployment(self, success, rule_count, decoder_count, error=""):
        """Log deployment result"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "server_id": self.config.get("server_id", "unknown"),
            "success": success,
            "rules_deployed": rule_count,
            "decoders_deployed": decoder_count,
            "error": error,
            "repo_url": self.config["repo_url"],
            "branch": self.config.get("branch", "main")
        }
        
        log_file = Path("/var/log/wazuh/rules_pull.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Pull Wazuh rules from central repository")
    parser.add_argument("--config", default="/etc/wazuh/puller_config.json", 
                       help="Path to configuration file")
    parser.add_argument("--force", action="store_true", 
                       help="Force deployment even if backup fails")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Simulate without making changes")
    
    args = parser.parse_args()
    
    puller = WazuhRulesPuller(args.config)
    
    if args.dry_run:
        print("DRY RUN - No changes will be made")
        print(f"Config: {puller.config}")
        return True
    
    success = puller.pull_and_deploy(args.force)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
