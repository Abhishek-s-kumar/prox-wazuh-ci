#!/bin/bash
# install_api_puller.sh - Install API-based puller on Wazuh servers

set -e

echo "=== Installing Wazuh API Puller ==="

# Configuration
INSTALL_DIR="/opt/wazuh-api-puller"
CONFIG_DIR="/etc/wazuh"
SCRIPT_NAME="api_puller.py"
SERVICE_NAME="wazuh-api-puller"
SERVER_ID=$(hostname -s)

# Create directories
echo "Creating installation directory..."
sudo mkdir -p $INSTALL_DIR
sudo mkdir -p $CONFIG_DIR

# Copy script
echo "Copying API puller script..."
sudo cp $SCRIPT_NAME $INSTALL_DIR/
sudo chmod +x $INSTALL_DIR/$SCRIPT_NAME

# Create configuration
echo "Creating configuration file..."
read -p "API Server URL (e.g., https://api.yourdomain.com): " API_URL
read -p "API Key: " API_KEY

sudo tee $CONFIG_DIR/api_puller_config.json > /dev/null << EOF
{
    "api_url": "$API_URL",
    "api_key": "$API_KEY",
    "server_id": "$SERVER_ID",
    "auto_restart": true,
    "create_backup": true,
    "package_format": "zip"
}
EOF

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null << EOF
[Unit]
Description=Wazuh Rules API Puller
After=network.target wazuh-manager.service
Wants=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/$SCRIPT_NAME --config $CONFIG_DIR/api_puller_config.json
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create timer for scheduled pulls
echo "Creating systemd timer..."
sudo tee /etc/systemd/system/$SERVICE_NAME.timer > /dev/null << EOF
[Unit]
Description=Daily pull of Wazuh rules via API

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME.timer
sudo systemctl start $SERVICE_NAME.timer

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Service installed to: $INSTALL_DIR"
echo "Configuration: $CONFIG_DIR/api_puller_config.json"
echo ""
echo "To test:"
echo "  sudo python3 $INSTALL_DIR/$SCRIPT_NAME"
echo ""
echo "To check logs:"
echo "  journalctl -u $SERVICE_NAME -f"
echo ""
echo "API endpoints will track this server as: $SERVER_ID"
