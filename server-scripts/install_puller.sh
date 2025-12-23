#!/bin/bash
# install_puller.sh - Install Wazuh rules puller on a server
# Copy this script to each Wazuh server and run it

set -e

echo "=== Installing Wazuh Rules Puller ==="

# Configuration
INSTALL_DIR="/opt/wazuh-rules-puller"
CONFIG_DIR="/etc/wazuh"
SCRIPT_NAME="pull_rules.py"
SERVICE_NAME="wazuh-rules-puller"

# Create installation directory
echo "Creating installation directory..."
sudo mkdir -p $INSTALL_DIR
sudo mkdir -p $CONFIG_DIR

# Copy the pull script
echo "Copying pull script..."
sudo cp $SCRIPT_NAME $INSTALL_DIR/
sudo chmod +x $INSTALL_DIR/$SCRIPT_NAME

# Create configuration file
echo "Creating configuration file..."
sudo tee $CONFIG_DIR/puller_config.json > /dev/null << EOF
{
    "repo_url": "https://github.com/YOUR_ORG/YOUR_REPO.git",
    "branch": "main",
    "auto_restart": true,
    "create_backup": true,
    "server_id": "$(hostname -s)",
    "repo_clone_path": "/opt/wazuh-rules"
}
EOF

echo "Configuration file created at $CONFIG_DIR/puller_config.json"
echo "Please edit this file to set your actual repository URL."

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null << EOF
[Unit]
Description=Wazuh Rules Puller
After=network.target wazuh-manager.service
Wants=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/$SCRIPT_NAME --config $CONFIG_DIR/puller_config.json
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for automatic pulls (optional)
echo "Creating systemd timer for daily pulls..."
sudo tee /etc/systemd/system/$SERVICE_NAME.timer > /dev/null << EOF
[Unit]
Description=Daily pull of Wazuh rules

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start timer (optional)
read -p "Enable daily automatic pulls? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo systemctl daemon-reload
    sudo systemctl enable $SERVICE_NAME.timer
    sudo systemctl start $SERVICE_NAME.timer
    echo "Daily pulls enabled. To run manually: sudo systemctl start $SERVICE_NAME"
else
    echo "Manual mode. Run manually with: sudo python3 $INSTALL_DIR/$SCRIPT_NAME"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "1. Edit $CONFIG_DIR/puller_config.json to set your repository URL"
echo "2. Test the puller: sudo python3 $INSTALL_DIR/$SCRIPT_NAME"
echo "3. Check logs: tail -f /var/log/wazuh/rules_pull.log"
echo ""
echo "To pull rules manually at any time:"
echo "  sudo python3 /opt/wazuh-rules-puller/pull_rules.py"
