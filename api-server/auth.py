"""
Authentication and authorization module for API server
"""

import sqlite3
import yaml
from datetime import datetime, timedelta
import jwt
from typing import Dict, Optional
import hashlib

# Load config
with open("config.yaml", 'r') as f:
    config = yaml.safe_load(f)

SECRET_KEY = config['auth']['secret_key']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = config['auth']['token_expiry']

def verify_api_key(api_key: str, admin: bool = False) -> bool:
    """Verify API key against database"""
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    if admin:
        cursor.execute(
            "SELECT 1 FROM api_keys WHERE key = ? AND is_admin = 1 AND active = 1",
            (api_key,)
        )
    else:
        cursor.execute(
            "SELECT 1 FROM api_keys WHERE key = ? AND active = 1",
            (api_key,)
        )
    
    result = cursor.fetchone()
    conn.close()
    
    return result is not None

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def register_server(server_id: str, api_key: str, description: str = "") -> bool:
    """Register a new server"""
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO servers (server_id, description, first_seen, last_seen, is_active)
            VALUES (?, ?, ?, ?, 1)
        """, (server_id, description, datetime.now().isoformat(), datetime.now().isoformat()))
        
        # Generate API key for server
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        cursor.execute("""
            INSERT INTO api_keys (key, key_hash, server_id, created_at, active)
            VALUES (?, ?, ?, ?, 1)
        """, (api_key, api_key_hash, server_id, datetime.now().isoformat()))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def revoke_api_key(api_key: str) -> bool:
    """Revoke an API key"""
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE api_keys SET active = 0, revoked_at = ? WHERE key = ?",
        (datetime.now().isoformat(), api_key)
    )
    
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    return affected > 0
