#!/usr/bin/env python3
"""
Wazuh Rules API Server
Provides secure API access to rules with authentication and audit logging
"""

from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
import uvicorn
from datetime import datetime, timedelta
import yaml
import json
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional
import sqlite3
import git

# Import modules
from auth import verify_api_key, create_jwt_token, verify_jwt_token
from models import init_db, log_deployment, get_deployment_stats

app = FastAPI(
    title="Wazuh Rules API",
    description="Secure API for Wazuh rules distribution",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Load config
CONFIG_PATH = Path(__file__).parent / "config.yaml"
with open(CONFIG_PATH, 'r') as f:
    config = yaml.safe_load(f)

# Git repository path
REPO_PATH = Path(config['git']['repo_path'])
RULES_DIR = REPO_PATH / "rules"
DECODERS_DIR = REPO_PATH / "decoders"

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    init_db()
    
    # Ensure git repo exists
    if not REPO_PATH.exists():
        print(f"Cloning repository to {REPO_PATH}")
        REPO_PATH.parent.mkdir(parents=True, exist_ok=True)
        git.Repo.clone_from(config['git']['repo_url'], REPO_PATH)
    
    print(f"API Server started. Serving from: {REPO_PATH}")

@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "service": "Wazuh Rules API",
        "version": "1.0.0",
        "endpoints": {
            "/rules": "Get available rules",
            "/rules/latest": "Get latest rules package",
            "/rules/hash/{file}": "Get file hash for sync",
            "/deploy": "Deploy rules to server (POST)",
            "/admin/stats": "Get deployment statistics",
            "/admin/servers": "Manage registered servers"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "git_repo": str(REPO_PATH),
        "rules_count": len(list(RULES_DIR.glob("*.xml"))),
        "decoders_count": len(list(DECODERS_DIR.glob("*.xml")))
    }

@app.get("/rules")
async def list_rules(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    server_id: Optional[str] = Header(None)
):
    """List all available rules and decoders"""
    # Verify API key
    if not verify_api_key(credentials.credentials):
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    rules = []
    decoders = []
    
    # Get rules
    for xml_file in RULES_DIR.glob("*.xml"):
        stat = xml_file.stat()
        rules.append({
            "name": xml_file.name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hash": calculate_file_hash(xml_file)
        })
    
    # Get decoders
    for xml_file in DECODERS_DIR.glob("*.xml"):
        stat = xml_file.stat()
        decoders.append({
            "name": xml_file.name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hash": calculate_file_hash(xml_file)
        })
    
    return {
        "rules": sorted(rules, key=lambda x: x["name"]),
        "decoders": sorted(decoders, key=lambda x: x["name"]),
        "total_rules": len(rules),
        "total_decoders": len(decoders),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/rules/latest")
async def get_latest_rules_package(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    server_id: str = Header(..., description="Server identifier"),
    format: str = "zip"
):
    """Get the latest rules package (zip or tar.gz)"""
    # Verify API key
    if not verify_api_key(credentials.credentials):
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    # Create package
    if format == "zip":
        package_path = create_zip_package()
    elif format == "tar.gz":
        package_path = create_tar_package()
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'zip' or 'tar.gz'")
    
    # Log the request
    log_deployment(
        server_id=server_id,
        action="download_package",
        package_size=package_path.stat().st_size,
        client_ip="0.0.0.0"  # Would get from request in production
    )
    
    return FileResponse(
        path=package_path,
        filename=f"wazuh-rules-{datetime.now().strftime('%Y%m%d')}.{format}",
        media_type="application/zip" if format == "zip" else "application/gzip"
    )

@app.get("/rules/hash/{filename}")
async def get_file_hash(
    filename: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    server_id: Optional[str] = Header(None)
):
    """Get hash of a specific file for sync verification"""
    # Verify API key
    if not verify_api_key(credentials.credentials):
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    # Check if file exists in rules or decoders
    file_path = None
    if (RULES_DIR / filename).exists():
        file_path = RULES_DIR / filename
    elif (DECODERS_DIR / filename).exists():
        file_path = DECODERS_DIR / filename
    else:
        raise HTTPException(status_code=404, detail="File not found")
    
    return {
        "filename": filename,
        "hash": calculate_file_hash(file_path),
        "size": file_path.stat().st_size,
        "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
    }

@app.post("/deploy")
async def deploy_rules(
    deployment_request: dict,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    server_id: str = Header(..., description="Server identifier")
):
    """Record a deployment (called after server deploys rules)"""
    # Verify API key
    if not verify_api_key(credentials.credentials):
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    # Extract deployment info
    rules_count = deployment_request.get("rules_count", 0)
    decoders_count = deployment_request.get("decoders_count", 0)
    success = deployment_request.get("success", False)
    error_message = deployment_request.get("error", "")
    
    # Log deployment
    deployment_id = log_deployment(
        server_id=server_id,
        action="deploy",
        rules_count=rules_count,
        decoders_count=decoders_count,
        success=success,
        error_message=error_message,
        client_ip="0.0.0.0"  # Would get from request in production
    )
    
    return {
        "deployment_id": deployment_id,
        "status": "logged",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/admin/stats")
async def get_deployment_statistics(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    days: int = 7
):
    """Admin endpoint: Get deployment statistics"""
    # Verify admin API key (different validation)
    if not verify_api_key(credentials.credentials, admin=True):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    stats = get_deployment_stats(days=days)
    
    return {
        "stats": stats,
        "timeframe_days": days,
        "generated": datetime.now().isoformat()
    }

@app.get("/admin/servers")
async def list_registered_servers(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Admin endpoint: List all registered servers"""
    # Verify admin API key
    if not verify_api_key(credentials.credentials, admin=True):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Connect to database
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT server_id, first_seen, last_seen, deployment_count, 
               last_success, is_active
        FROM servers
        ORDER BY last_seen DESC
    """)
    
    servers = []
    for row in cursor.fetchall():
        servers.append({
            "server_id": row[0],
            "first_seen": row[1],
            "last_seen": row[2],
            "deployment_count": row[3],
            "last_success": row[4],
            "is_active": row[5]
        })
    
    conn.close()
    
    return {
        "servers": servers,
        "total": len(servers),
        "active": len([s for s in servers if s['is_active']])
    }

# Helper functions
def calculate_file_hash(filepath: Path) -> str:
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def create_zip_package() -> Path:
    """Create a zip package of rules and decoders"""
    import zipfile
    import tempfile
    
    temp_dir = Path(tempfile.gettempdir())
    zip_path = temp_dir / f"wazuh-rules-{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add rules
        for xml_file in RULES_DIR.glob("*.xml"):
            zipf.write(xml_file, f"rules/{xml_file.name}")
        
        # Add decoders
        for xml_file in DECODERS_DIR.glob("*.xml"):
            zipf.write(xml_file, f"decoders/{xml_file.name}")
    
    return zip_path

def create_tar_package() -> Path:
    """Create a tar.gz package of rules and decoders"""
    import tarfile
    import tempfile
    
    temp_dir = Path(tempfile.gettempdir())
    tar_path = temp_dir / f"wazuh-rules-{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
    
    with tarfile.open(tar_path, 'w:gz') as tar:
        # Add rules
        for xml_file in RULES_DIR.glob("*.xml"):
            tar.add(xml_file, arcname=f"rules/{xml_file.name}")
        
        # Add decoders
        for xml_file in DECODERS_DIR.glob("*.xml"):
            tar.add(xml_file, arcname=f"decoders/{xml_file.name}")
    
    return tar_path

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=config['server']['host'],
        port=config['server']['port'],
        reload=config['server']['reload']
    )
