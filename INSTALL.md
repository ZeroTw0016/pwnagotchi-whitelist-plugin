# Installation und Troubleshooting Guide

## Schnellinstallation

1. **Plugin kopieren**:
   ```bash
   sudo cp deauth_whitelist.py /usr/local/share/pwnagotchi/custom-plugins/
   sudo chmod 644 /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py
   ```

2. **Plugin in der Konfiguration aktivieren** (`/etc/pwnagotchi/config.toml`):
   ```toml
   main.plugins.deauth_whitelist.enabled = true
   ui.web.enabled = true
   ui.web.port = 8080
   ```

3. **Pwnagotchi neustarten**:
   ```bash
   sudo systemctl restart pwnagotchi
   ```

4. **Web-Interface aufrufen**:
   `http://10.0.0.2:8080/plugins/deauth_whitelist`

## Problem: "Page not found" bei `/plugins/deauth_whitelist`

### Lösung 1: Webhook-System prüfen

Das Plugin verwendet das Webhook-System von Pwnagotchi. Prüfen Sie:

```bash
# Plugin-Status prüfen
sudo journalctl -u pwnagotchi | grep "deauth_whitelist"

# Web-UI Status prüfen
sudo netstat -tlnp | grep :8080

# Plugin-Syntax validieren
python3 -m py_compile /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py
```

### Lösung 2: Konfiguration überprüfen

```bash
# Aktuelle Konfiguration anzeigen
grep -A5 -B5 "deauth_whitelist\|web" /etc/pwnagotchi/config.toml

# Web-UI muss aktiviert sein
grep "ui.web.enabled.*true" /etc/pwnagotchi/config.toml
```

### Lösung 3: Manuelle API-Tests

```bash
# Direkte API-Tests
curl -X GET http://10.0.0.2:8080/plugins/deauth_whitelist/api/list
curl -X POST -H "Content-Type: application/json" -d '{"entry":"test"}' http://10.0.0.2:8080/plugins/deauth_whitelist/api/add
```

### Lösung 4: Plugin-Debug

```bash
# Real-time Logs überwachen
sudo journalctl -u pwnagotchi -f | grep -E "(deauth_whitelist|webhook|plugin)"

# Plugin-Verzeichnis prüfen
ls -la /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py

# Whitelist-Datei prüfen
ls -la /root/deauth_whitelist.json
```

## Alternative Web-Interface URLs

Falls das Standard-Interface nicht funktioniert, probieren Sie:

- `http://10.0.0.2:8080/plugins/deauth_whitelist/`
- `http://10.0.0.2:8080/plugins/deauth_whitelist/api/list`
- Überprüfen Sie die IP-Adresse Ihres Pwnagotchi: `ip addr show`

## Fallback: Manuelle Whitelist-Verwaltung

Falls das Web-Interface nicht funktioniert, können Sie die Whitelist manuell bearbeiten:

```bash
# Whitelist anzeigen
sudo cat /root/deauth_whitelist.json

# Eintrag hinzufügen (Beispiel)
sudo nano /root/deauth_whitelist.json
```

Beispiel-Format:
```json
{
  "whitelist": [
    "aa:bb:cc:dd:ee:ff",
    "MeinWLAN-Name",
    "11:22:33:44:55:66"
  ],
  "last_updated": "2025-07-11 12:00:00"
}
```

## Häufige Fehlerquellen

1. **Web-UI nicht aktiviert**: `ui.web.enabled = true` fehlt in config.toml
2. **Plugin nicht aktiviert**: `main.plugins.deauth_whitelist.enabled = true` fehlt
3. **Falsche Berechtigungen**: Plugin-Datei nicht lesbar
4. **Syntax-Fehler**: Plugin-Code hat Fehler
5. **Pwnagotchi-Version**: Nicht kompatible Version (Webhook-System benötigt)

## Support

Bei anhaltenden Problemen:

1. Sammeln Sie Logs: `sudo journalctl -u pwnagotchi > pwnagotchi.log`
2. Überprüfen Sie die Pwnagotchi-Version: `pwnagotchi --version`
3. Erstellen Sie ein Issue mit den Logs und Ihrer Konfiguration
