#!/bin/bash

# Installation script for the Pwnagotchi Deauth Whitelist Plugin
# Run this script as root: sudo bash install.sh

set -e

echo "🛡️  Installing Pwnagotchi Deauth Whitelist Plugin..."

# Define paths
PLUGIN_DIR="/usr/local/share/pwnagotchi/custom-plugins"
PLUGIN_FILE="deauth_whitelist.py"
CONFIG_FILE="/etc/pwnagotchi/config.toml"
BACKUP_CONFIG="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)"
   exit 1
fi

# Check if plugin file exists
if [[ ! -f "$PLUGIN_FILE" ]]; then
    echo "❌ Plugin file '$PLUGIN_FILE' not found!"
    echo "   Make sure you are in the plugin directory."
    exit 1
fi

# Create plugin directory if it doesn't exist
mkdir -p "$PLUGIN_DIR"

# Copy plugin file
echo "📁 Copying plugin file to $PLUGIN_DIR..."
cp "$PLUGIN_FILE" "$PLUGIN_DIR/"
chmod 644 "$PLUGIN_DIR/$PLUGIN_FILE"
chown root:root "$PLUGIN_DIR/$PLUGIN_FILE"

# Backup configuration
if [[ -f "$CONFIG_FILE" ]]; then
    echo "💾 Creating configuration backup: $BACKUP_CONFIG"
    cp "$CONFIG_FILE" "$BACKUP_CONFIG"
else
    echo "⚠️  Warning: Configuration file $CONFIG_FILE not found!"
    echo "   You must manually enable the plugin in the configuration."
fi

# Enable plugin in configuration (if config file exists)
if [[ -f "$CONFIG_FILE" ]]; then
    # Check if plugin is already configured
    if grep -q "main.plugins.deauth_whitelist.enabled" "$CONFIG_FILE"; then
        echo "✅ Plugin is already present in configuration"
    else
        echo "⚙️  Adding plugin configuration..."
        echo "" >> "$CONFIG_FILE"
        echo "# Deauth Whitelist Plugin" >> "$CONFIG_FILE"
        echo "main.plugins.deauth_whitelist.enabled = true" >> "$CONFIG_FILE"
        echo "✅ Plugin configuration added"
    fi
    
    # Check if Web UI is enabled
    if grep -q "ui.web.enabled = true" "$CONFIG_FILE"; then
        echo "✅ Web UI is already enabled"
    else
        echo "⚠️  Web UI does not seem to be enabled. The plugin requires the Web UI!"
        echo "   Add the following lines to $CONFIG_FILE:"
        echo "   ui.web.enabled = true"
        echo "   ui.web.address = \"0.0.0.0\""
        echo "   ui.web.port = 8080"
    fi
fi

# Create whitelist file
WHITELIST_FILE="/root/deauth_whitelist.json"
if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo "📝 Creating empty whitelist file..."
    cat > "$WHITELIST_FILE" << EOF
{
  "whitelist": [],
  "last_updated": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    chmod 600 "$WHITELIST_FILE"
    chown root:root "$WHITELIST_FILE"
else
    echo "✅ Whitelist file already exists"
fi

echo ""
echo "🎉 Installation completed!"
echo ""
echo "📋 Next steps:"
echo "   1. Restart Pwnagotchi: sudo systemctl restart pwnagotchi"
echo "   2. Open the Web UI: http://10.0.0.2:8080"
echo "   3. Navigate to: /plugins/deauth_whitelist"
echo ""
echo "📝 View logs: sudo journalctl -u pwnagotchi -f | grep deauth_whitelist"
echo ""
echo "🔧 Configuration file: $CONFIG_FILE"
if [[ -f "$BACKUP_CONFIG" ]]; then
    echo "💾 Configuration backed up: $BACKUP_CONFIG"
fi
echo ""

# Optional: Restart Pwnagotchi directly
read -p "Do you want to restart Pwnagotchi now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Restarting Pwnagotchi..."
    systemctl restart pwnagotchi
    echo "✅ Pwnagotchi has been restarted"
else
    echo "⚠️  Don't forget to restart Pwnagotchi manually!"
fi
