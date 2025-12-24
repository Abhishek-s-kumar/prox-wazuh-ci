"""
Database models for deployment tracking
"""

import sqlite3
from datetime import datetime
import yaml

# Load config
with open("config.yaml", 'r') as f:
    config = yaml.safe_load(f)

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    # Servers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id TEXT UNIQUE NOT NULL,
            description TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            deployment_count INTEGER DEFAULT 0,
            last_success TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # API keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            key_hash TEXT NOT NULL,
            server_id TEXT,
            is_admin INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            revoked_at TEXT,
            FOREIGN KEY (server_id) REFERENCES servers (server_id)
        )
    """)
    
    # Deployments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id TEXT UNIQUE NOT NULL,
            server_id TEXT NOT NULL,
            action TEXT NOT NULL,
            rules_count INTEGER DEFAULT 0,
            decoders_count INTEGER DEFAULT 0,
            success INTEGER DEFAULT 0,
            error_message TEXT,
            package_size INTEGER,
            client_ip TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (server_id) REFERENCES servers (server_id)
        )
    """)
    
    # Create indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_deployments_server ON deployments(server_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_deployments_time ON deployments(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_servers_active ON servers(is_active)")
    
    conn.commit()
    conn.close()

def log_deployment(
    server_id: str,
    action: str,
    rules_count: int = 0,
    decoders_count: int = 0,
    success: bool = True,
    error_message: str = "",
    package_size: int = 0,
    client_ip: str = "0.0.0.0"
) -> str:
    """Log a deployment to database"""
    import uuid
    from datetime import datetime
    
    deployment_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    # Insert deployment log
    cursor.execute("""
        INSERT INTO deployments 
        (deployment_id, server_id, action, rules_count, decoders_count, 
         success, error_message, package_size, client_ip, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (deployment_id, server_id, action, rules_count, decoders_count,
          int(success), error_message, package_size, client_ip, timestamp))
    
    # Update server stats
    cursor.execute("""
        UPDATE servers 
        SET last_seen = ?, 
            deployment_count = deployment_count + 1,
            last_success = CASE WHEN ? = 1 THEN ? ELSE last_success END
        WHERE server_id = ?
    """, (timestamp, int(success), timestamp, server_id))
    
    # Create server record if it doesn't exist
    cursor.execute("SELECT 1 FROM servers WHERE server_id = ?", (server_id,))
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO servers (server_id, first_seen, last_seen, deployment_count)
            VALUES (?, ?, ?, 1)
        """, (server_id, timestamp, timestamp))
    
    conn.commit()
    conn.close()
    
    return deployment_id

def get_deployment_stats(days: int = 7) -> dict:
    """Get deployment statistics for specified days"""
    conn = sqlite3.connect(config['database']['path'])
    cursor = conn.cursor()
    
    # Calculate date cutoff
    from datetime import datetime, timedelta
    cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
    
    # Total deployments
    cursor.execute("""
        SELECT COUNT(*) as total,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
               SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed
        FROM deployments
        WHERE timestamp >= ?
    """, (cutoff_date,))
    
    total_row = cursor.fetchone()
    
    # Deployments by server
    cursor.execute("""
        SELECT server_id, 
               COUNT(*) as deployments,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
        FROM deployments
        WHERE timestamp >= ?
        GROUP BY server_id
        ORDER BY deployments DESC
    """, (cutoff_date,))
    
    by_server = []
    for row in cursor.fetchall():
        by_server.append({
            "server_id": row[0],
            "deployments": row[1],
            "successful": row[2]
        })
    
    # Daily deployment counts
    cursor.execute("""
        SELECT DATE(timestamp) as day,
               COUNT(*) as deployments,
               SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
        FROM deployments
        WHERE timestamp >= ?
        GROUP BY DATE(timestamp)
        ORDER BY day DESC
    """, (cutoff_date,))
    
    daily = []
    for row in cursor.fetchall():
        daily.append({
            "date": row[0],
            "deployments": row[1],
            "successful": row[2]
        })
    
    conn.close()
    
    return {
        "total_deployments": total_row[0] if total_row else 0,
        "successful": total_row[1] if total_row else 0,
        "failed": total_row[2] if total_row else 0,
        "success_rate": (total_row[1] / total_row[0] * 100) if total_row and total_row[0] > 0 else 0,
        "by_server": by_server,
        "daily": daily,
        "timeframe_days": days
    }
