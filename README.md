# Pwnagotchi Deauth Whitelist Plugin

Ein Plugin für Pwnagotchi, das eine Whitelist für Deauthentication-Angriffe verwaltet. Netzwerke auf der Whitelist werden nicht von Deauth-Angriffen betroffen.

## Features

- 🛡️ Schutz bestimmter Netzwerke vor Deauth-Angriffen
- 🌐 Web-Interface zur Verwaltung der Whitelist
- 📝 Unterstützung für MAC-Adressen und ESSID-Namen
- 💾 Persistente Speicherung der Whitelist
- 🔄 Echtzeitaktualisierung über die Web-UI

## Installation

1. Kopieren Sie `deauth_whitelist.py` in das Pwnagotchi-Plugin-Verzeichnis:
   ```bash
   sudo cp deauth_whitelist.py /usr/local/share/pwnagotchi/custom-plugins/
   ```

2. Aktivieren Sie das Plugin in der Pwnagotchi-Konfiguration (`/etc/pwnagotchi/config.toml`):
   ```toml
   main.plugins.deauth_whitelist.enabled = true
   ```

3. Starten Sie Pwnagotchi neu:
   ```bash
   sudo systemctl restart pwnagotchi
   ```

## Verwendung

### Web-Interface

1. Navigieren Sie zur Pwnagotchi-Web-UI (normalerweise `http://10.0.0.2:8080`)
2. Gehen Sie zu `/plugins/deauth_whitelist`
3. Fügen Sie Netzwerke zur Whitelist hinzu:
   - **MAC-Adresse**: `aa:bb:cc:dd:ee:ff`
   - **ESSID**: `MeinWiFi-Netzwerk`

### Programmgesteuert

Das Plugin stellt auch eine API zur Verfügung:

- **GET** `/plugins/deauth_whitelist/api/list` - Whitelist abrufen
- **POST** `/plugins/deauth_whitelist/api/add` - Eintrag hinzufügen
- **POST** `/plugins/deauth_whitelist/api/remove` - Eintrag entfernen

Beispiel:
```bash
# Eintrag hinzufügen
curl -X POST -H "Content-Type: application/json" \
  -d '{"entry":"aa:bb:cc:dd:ee:ff"}' \
  http://10.0.0.2:8080/plugins/deauth_whitelist/api/add

# Eintrag entfernen
curl -X POST -H "Content-Type: application/json" \
  -d '{"entry":"aa:bb:cc:dd:ee:ff"}' \
  http://10.0.0.2:8080/plugins/deauth_whitelist/api/remove
```

## Konfiguration

Die Whitelist wird in `/root/deauth_whitelist.json` gespeichert. Das Format ist:

```json
{
  "whitelist": [
    "aa:bb:cc:dd:ee:ff",
    "MeinHeimNetzwerk",
    "11:22:33:44:55:66"
  ],
  "last_updated": "2025-07-11 12:00:00"
}
```

## Funktionsweise

Das Plugin überwacht Deauth-Angriffe durch die `on_deauth`-Hook-Funktion. Wenn ein Angriff auf ein Netzwerk in der Whitelist versucht wird, blockiert das Plugin den Angriff und protokolliert die Aktion.

### Überprüfungslogik

Das Plugin überprüft sowohl:
1. **MAC-Adresse** des Access Points
2. **ESSID/Hostname** des Netzwerks

Wenn einer dieser Werte in der Whitelist steht, wird der Deauth-Angriff blockiert.

## Logs

Das Plugin protokolliert seine Aktivitäten in den Pwnagotchi-Logs:

```bash
# Logs anzeigen
sudo journalctl -u pwnagotchi -f | grep deauth_whitelist
```

Typische Log-Nachrichten:
- `[deauth_whitelist] Plugin loaded`
- `[deauth_whitelist] Blocking deauth for whitelisted network: MyNetwork (aa:bb:cc:dd:ee:ff)`
- `[deauth_whitelist] Loaded X entries from whitelist`

## Fehlerbehebung

### Plugin wird nicht geladen
1. Überprüfen Sie die Dateiberechtigungen:
   ```bash
   sudo chmod 644 /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py
   ```

2. Überprüfen Sie die Konfiguration in `/etc/pwnagotchi/config.toml`

3. Überprüfen Sie die Logs:
   ```bash
   sudo journalctl -u pwnagotchi -f
   ```

### Web-Interface nicht erreichbar
1. Stellen Sie sicher, dass die Pwnagotchi-Web-UI aktiviert ist
2. Überprüfen Sie, ob der Webserver läuft
3. Navigieren Sie direkt zu: `http://10.0.0.2:8080/plugins/deauth_whitelist`

### Whitelist wird nicht gespeichert
1. Überprüfen Sie die Berechtigungen für `/root/deauth_whitelist.json`
2. Stellen Sie sicher, dass genügend Speicherplatz vorhanden ist

## Lizenz

GPL v3 - Siehe LICENSE-Datei für Details.

## Beitragen

Pull Requests und Issues sind willkommen! Bitte folgen Sie den Pwnagotchi-Plugin-Entwicklungsrichtlinien.

## Haftungsausschluss

Dieses Plugin ist nur für autorisierte Penetrationstests und Bildungszwecke bestimmt. Der Benutzer ist für die ordnungsgemäße und legale Verwendung verantwortlich.
