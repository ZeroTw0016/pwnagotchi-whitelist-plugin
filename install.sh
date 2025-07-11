#!/bin/bash

# Installationsskript für das Pwnagotchi Deauth Whitelist Plugin
# Führen Sie dieses Skript als root aus: sudo bash install.sh

set -e

echo "🛡️  Installing Pwnagotchi Deauth Whitelist Plugin..."

# Pfade definieren
PLUGIN_DIR="/usr/local/share/pwnagotchi/custom-plugins"
PLUGIN_FILE="deauth_whitelist.py"
CONFIG_FILE="/etc/pwnagotchi/config.toml"
BACKUP_CONFIG="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Überprüfen ob als root ausgeführt
if [[ $EUID -ne 0 ]]; then
   echo "❌ Dieses Skript muss als root ausgeführt werden (sudo)"
   exit 1
fi

# Überprüfen ob Plugin-Datei existiert
if [[ ! -f "$PLUGIN_FILE" ]]; then
    echo "❌ Plugin-Datei '$PLUGIN_FILE' nicht gefunden!"
    echo "   Stellen Sie sicher, dass Sie sich im Plugin-Verzeichnis befinden."
    exit 1
fi

# Plugin-Verzeichnis erstellen falls es nicht existiert
mkdir -p "$PLUGIN_DIR"

# Plugin-Datei kopieren
echo "📁 Kopiere Plugin-Datei nach $PLUGIN_DIR..."
cp "$PLUGIN_FILE" "$PLUGIN_DIR/"
chmod 644 "$PLUGIN_DIR/$PLUGIN_FILE"
chown root:root "$PLUGIN_DIR/$PLUGIN_FILE"

# Konfiguration sichern
if [[ -f "$CONFIG_FILE" ]]; then
    echo "💾 Erstelle Backup der Konfiguration: $BACKUP_CONFIG"
    cp "$CONFIG_FILE" "$BACKUP_CONFIG"
else
    echo "⚠️  Warnung: Konfigurationsdatei $CONFIG_FILE nicht gefunden!"
    echo "   Sie müssen das Plugin manuell in der Konfiguration aktivieren."
fi

# Plugin in Konfiguration aktivieren (falls Konfigurationsdatei existiert)
if [[ -f "$CONFIG_FILE" ]]; then
    # Überprüfen ob Plugin bereits konfiguriert ist
    if grep -q "main.plugins.deauth_whitelist.enabled" "$CONFIG_FILE"; then
        echo "✅ Plugin ist bereits in der Konfiguration vorhanden"
    else
        echo "⚙️  Füge Plugin-Konfiguration hinzu..."
        echo "" >> "$CONFIG_FILE"
        echo "# Deauth Whitelist Plugin" >> "$CONFIG_FILE"
        echo "main.plugins.deauth_whitelist.enabled = true" >> "$CONFIG_FILE"
        echo "✅ Plugin-Konfiguration hinzugefügt"
    fi
    
    # Überprüfen ob Web-UI aktiviert ist
    if grep -q "ui.web.enabled = true" "$CONFIG_FILE"; then
        echo "✅ Web-UI ist bereits aktiviert"
    else
        echo "⚠️  Web-UI scheint nicht aktiviert zu sein. Das Plugin benötigt die Web-UI!"
        echo "   Fügen Sie folgende Zeilen zu $CONFIG_FILE hinzu:"
        echo "   ui.web.enabled = true"
        echo "   ui.web.address = \"0.0.0.0\""
        echo "   ui.web.port = 8080"
    fi
fi

# Whitelist-Datei erstellen
WHITELIST_FILE="/root/deauth_whitelist.json"
if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo "📝 Erstelle leere Whitelist-Datei..."
    cat > "$WHITELIST_FILE" << EOF
{
  "whitelist": [],
  "last_updated": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    chmod 600 "$WHITELIST_FILE"
    chown root:root "$WHITELIST_FILE"
else
    echo "✅ Whitelist-Datei existiert bereits"
fi

echo ""
echo "🎉 Installation abgeschlossen!"
echo ""
echo "📋 Nächste Schritte:"
echo "   1. Starten Sie Pwnagotchi neu: sudo systemctl restart pwnagotchi"
echo "   2. Öffnen Sie die Web-UI: http://10.0.0.2:8080"
echo "   3. Navigieren Sie zu: /plugins/deauth_whitelist"
echo ""
echo "📝 Logs anzeigen: sudo journalctl -u pwnagotchi -f | grep deauth_whitelist"
echo ""
echo "🔧 Konfigurationsdatei: $CONFIG_FILE"
if [[ -f "$BACKUP_CONFIG" ]]; then
    echo "💾 Konfiguration gesichert: $BACKUP_CONFIG"
fi
echo ""

# Optional: Pwnagotchi direkt neustarten
read -p "Möchten Sie Pwnagotchi jetzt neustarten? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Starte Pwnagotchi neu..."
    systemctl restart pwnagotchi
    echo "✅ Pwnagotchi wurde neugestartet"
else
    echo "⚠️  Vergessen Sie nicht, Pwnagotchi manuell neu zu starten!"
fi
