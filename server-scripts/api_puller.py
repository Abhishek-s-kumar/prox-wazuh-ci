#!/usr/bin/env python3
"""
Wazuh Server API Puller
Pulls rules from API server instead of directly from Git
"""

import requests
import json
import zipfile
import tarfile
import io
import os
import sys
import argparse
from datetime import datetime
import subprocess
import hashlib
from pathlib import Path

class WazuhAPIPuller:
    def __init__(self, config_path="/etc/wazuh/api_puller_config.json"):
        self.config = self.load_config(config_path)
        self.api_url = self.config['api_url']
        self.api_key = self.config['api_key']
        self.server_id = self.config['server_id']
        self.backup_dir = Path(f"/backup/wazuh-{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        # Wazuh directories
        self.wazuh_rules_dir = Path("/var/ossec/etc/rules")
        self.wazuh_decoders_dir = Path("/var/ossec/etc/decoders")
        
        # Headers for API requests
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-Server-ID": self.server_id,
            "User-Agent": f"Wazuh-API-Puller/{self.server_id}"
        }
    
    def load_config(self, config_path):
        """Load configuration file"""
        default_config = {
            "api_url": "http://localhost:8000",
            "api_key": "your-api-key-here",
            "server_id": "unknown-server",
            "auto_restart": True,
            "create_backup": True,
            "package_format": "zip"
        }
        
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
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
                subprocess.run(
                    ["cp", "-r", str(self.wazuh_rules_dir), str(self.backup_dir / "rules")],
                    check=True
                )
                print(f"  ✓ Rules backed up")
            
            # Backup decoders
            if self.wazuh_decoders_dir.exists():
                subprocess.run(
                    ["cp", "-r", str(self.wazuh_decoders_dir), str(self.backup_dir / "decoders")],
                    check=True
                )
                print(f"  ✓ Decoders backed up")
            
            return True
        except Exception as e:
            print(f"  ✗ Backup failed: {e}")
            return False
    
    def get_available_files(self):
        """Get list of available files from API"""
        try:
            response = requests.get(
                f"{self.api_url}/rules",
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error connecting to API: {e}")
            return None
    
    def download_package(self):
        """Download rules package from API"""
        format = self.config.get("package_format", "zip")
        
        try:
            response = requests.get(
                f"{self.api_url}/rules/latest",
                headers=self.headers,
                params={"format": format},
                stream=True,
                timeout=60
            )
            
            if response.status_code == 200:
                # Get content
                content = response.content
                
                # Log download
                self.log_api_call("download_package", len(content))
                
                return content
            else:
                print(f"Failed to download: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error downloading package: {e}")
            return None
    
    def extract_package(self, package_content, format="zip"):
        """Extract package to temporary directory"""
        import tempfile
        
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            if format == "zip":
                with zipfile.ZipFile(io.BytesIO(package_content)) as zip_ref:
                    zip_ref.extractall(temp_dir)
            elif format == "tar.gz":
                with tarfile.open(fileobj=io.BytesIO(package_content), mode='r:gz') as tar_ref:
                    tar_ref.extractall(temp_dir)
            else:
                print(f"Unsupported format: {format}")
                return None
            
            return temp_dir
        except Exception as e:
            print(f"Error extracting package: {e}")
            return None
    
    def deploy_files(self, extract_dir):
        """Deploy extracted files to Wazuh"""
        temp_dir = Path(extract_dir)
        
        rule_count = 0
        decoder_count = 0
        
        # Deploy rules
        temp_rules_dir = temp_dir / "rules"
        if temp_rules_dir.exists():
            # Clear existing rules
            for xml_file in self.wazuh_rules_dir.glob("*.xml"):
                xml_file.unlink()
            
            # Copy new rules
            for xml_file in temp_rules_dir.glob("*.xml"):
                shutil.copy2(xml_file, self.wazuh_rules_dir / xml_file.name)
                rule_count += 1
        
        # Deploy decoders
        temp_decoders_dir = temp_dir / "decoders"
        if temp_decoders_dir.exists():
            # Clear existing decoders
            for xml_file in self.wazuh_decoders_dir.glob("*.xml"):
                xml_file.unlink()
            
            # Copy new decoders
            for xml_file in temp_decoders_dir.glob("*.xml"):
                shutil.copy2(xml_file, self.wazuh_decoders_dir / xml_file.name)
                decoder_count += 1
        
        # Set permissions
        subprocess.run(
            ["chown", "-R", "wazuh:wazuh", str(self.wazuh_rules_dir)],
            check=False
        )
        subprocess.run(
            ["chown", "-R", "wazuh:wazuh", str(self.wazuh_decoders_dir)],
            check=False
        )
        
        return rule_count, decoder_count
    
    def restart_wazuh(self):
        """Restart Wazuh manager"""
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
                return True
            else:
                print(f"  ✗ Failed to restart Wazuh: {result.stderr}")
                return False
        except Exception as e:
            print(f"  ✗ Error restarting Wazuh: {e}")
            return False
    
    def log_api_call(self, action, size=0):
        """Log API call to server"""
        try:
            log_data = {
                "action": action,
                "package_size": size,
                "timestamp": datetime.now().isoformat()
            }
            
            # This would be sent to API in real implementation
            # For now, log locally
            log_file = Path("/var/log/wazuh/api_puller.log")
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_data) + "\n")
                
        except Exception as e:
            print(f"Warning: Failed to log API call: {e}")
    
    def report_deployment(self, success, rule_count, decoder_count, error=""):
        """Report deployment status to API"""
        try:
            deployment_data = {
                "rules_count": rule_count,
                "decoders_count": decoder_count,
                "success": success,
                "error": error,
                "server_id": self.server_id,
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.api_url}/deploy",
                headers=self.headers,
                json=deployment_data,
                timeout=10
            )
            
            if response.status_code == 200:
                print("Deployment logged to API")
                return True
            else:
                print(f"Failed to log deployment: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error reporting deployment: {e}")
            return False
    
    def pull_and_deploy(self, force=False):
        """Main method to pull and deploy via API"""
        print(f"=== Wazuh Rules API Pull - Server: {self.server_id} ===")
        print(f"API Server: {self.api_url}")
        print("-" * 50)
        
        # Step 1: Check API connectivity
        print("Checking API connectivity...")
        available = self.get_available_files()
        if not available:
            print("✗ Cannot connect to API or no files available")
            return False
        
        print(f"  ✓ API connected. {available['total_rules']} rules, {available['total_decoders']} decoders available")
        
        # Step 2: Backup
        if not self.backup_current():
            if not force:
                print("Backup failed. Aborting.")
                return False
        
        # Step 3: Download package
        print("Downloading rules package...")
        package_content = self.download_package()
        if not package_content:
            print("✗ Failed to download package")
            return False
        
        print(f"  ✓ Downloaded {len(package_content)} bytes")
        
        # Step 4: Extract
        format = self.config.get("package_format", "zip")
        extract_dir = self.extract_package(package_content, format)
        if not extract_dir:
            print("✗ Failed to extract package")
            return False
        
        # Step 5: Deploy
        try:
            rule_count, decoder_count = self.deploy_files(extract_dir)
            
            # Step 6: Restart if needed
            if rule_count > 0 or decoder_count > 0:
                restart_success = self.restart_wazuh()
                if not restart_success:
                    print("Wazuh restart failed")
                    self.report_deployment(False, rule_count, decoder_count, "Restart failed")
                    return False
            else:
                print("No new files to deploy")
            
            # Step 7: Report success
            self.report_deployment(True, rule_count, decoder_count)
            
            print(f"\n✓ Successfully deployed via API")
            print(f"  Rules: {rule_count} files")
            print(f"  Decoders: {decoder_count} files")
            print(f"  Backup: {self.backup_dir}")
            
            return True
            
        except Exception as e:
            print(f"\n✗ Deployment failed: {e}")
            self.report_deployment(False, 0, 0, str(e))
            return False
        finally:
            # Clean up temporary directory
            import shutil
            if extract_dir and Path(extract_dir).exists():
                shutil.rmtree(extract_dir, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser(description="Pull Wazuh rules from API server")
    parser.add_argument("--config", default="/etc/wazuh/api_puller_config.json",
                       help="Path to configuration file")
    parser.add_argument("--force", action="store_true",
                       help="Force deployment even if backup fails")
    parser.add_argument("--dry-run", action="store_true",
                       help="Simulate without making changes")
    
    args = parser.parse_args()
    
    puller = WazuhAPIPuller(args.config)
    
    if args.dry_run:
        print("DRY RUN - No changes will be made")
        print(f"Config: {puller.config}")
        return True
    
    success = puller.pull_and_deploy(args.force)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
