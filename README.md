# Pwnagotchi Deauth Whitelist Plugin

A plugin for Pwnagotchi that manages a whitelist for deauthentication attacks. Networks on the whitelist will not be affected by deauth attacks.

## Features

- 🛡️ Protection of specific networks from deauth attacks
- 🌐 Web interface for whitelist management
- 📝 Support for MAC addresses and ESSID names
- 💾 Persistent whitelist storage
- 🔄 Real-time updates via Web UI

## Installation

1. Copy `deauth_whitelist.py` to the Pwnagotchi plugin directory:
   ```bash
   sudo cp deauth_whitelist.py /usr/local/share/pwnagotchi/custom-plugins/
   ```

2. Enable the plugin in the Pwnagotchi configuration (`/etc/pwnagotchi/config.toml`):
   ```toml
   main.plugins.deauth_whitelist.enabled = true
   ```

3. Restart Pwnagotchi:
   ```bash
   sudo systemctl restart pwnagotchi
   ```

## Usage

### Web Interface

1. Navigate to the Pwnagotchi Web UI (usually `http://10.0.0.2:8080`)
2. Go to `/plugins/deauth_whitelist`
3. Add networks to the whitelist:
   - **MAC Address**: `aa:bb:cc:dd:ee:ff`
   - **ESSID**: `MyWiFi-Network`

### Programmatic

The plugin also provides an API:

- **GET** `/plugins/deauth_whitelist/api/list` - Retrieve whitelist
- **POST** `/plugins/deauth_whitelist/api/add` - Add entry
- **POST** `/plugins/deauth_whitelist/api/remove` - Remove entry

Example:
```bash
# Add entry
curl -X POST -H "Content-Type: application/json" \
  -d '{"entry":"aa:bb:cc:dd:ee:ff"}' \
  http://10.0.0.2:8080/plugins/deauth_whitelist/api/add

# Remove entry
curl -X POST -H "Content-Type: application/json" \
  -d '{"entry":"aa:bb:cc:dd:ee:ff"}' \
  http://10.0.0.2:8080/plugins/deauth_whitelist/api/remove
```

## Configuration

The whitelist is stored in `/root/deauth_whitelist.json`. The format is:

```json
{
  "whitelist": [
    "aa:bb:cc:dd:ee:ff",
    "HomeNetwork",
    "11:22:33:44:55:66"
  ],
  "last_updated": "2025-07-11 12:00:00"
}
```

## How it works

The plugin monitors deauth attacks through the `on_deauth` hook function. When an attack on a network in the whitelist is attempted, the plugin blocks the attack and logs the action.

### Verification Logic

The plugin checks both:
1. **MAC Address** of the Access Point
2. **ESSID/Hostname** of the network

If either of these values is in the whitelist, the deauth attack will be blocked.

## Logs

The plugin logs its activities in the Pwnagotchi logs:

```bash
# View logs
sudo journalctl -u pwnagotchi -f | grep deauth_whitelist
```

Typical log messages:
- `[deauth_whitelist] Plugin loaded`
- `[deauth_whitelist] Blocking deauth for whitelisted network: MyNetwork (aa:bb:cc:dd:ee:ff)`
- `[deauth_whitelist] Loaded X entries from whitelist`

## Troubleshooting

### Plugin not loading
1. Check file permissions:
   ```bash
   sudo chmod 644 /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py
   ```

2. Check the configuration in `/etc/pwnagotchi/config.toml`:
   ```bash
   grep -n "deauth_whitelist" /etc/pwnagotchi/config.toml
   ```

3. Check the logs:
   ```bash
   sudo journalctl -u pwnagotchi -f | grep deauth_whitelist
   ```

### Web interface not accessible

**The web interface URL is: `http://10.0.0.2:8080/plugins/deauth_whitelist`**

1. **Ensure that the Pwnagotchi Web UI is enabled** in `/etc/pwnagotchi/config.toml`:
   ```toml
   ui.web.enabled = true
   ui.web.port = 8080
   ```

2. **Check if the web server is running**:
   ```bash
   sudo netstat -tlnp | grep :8080
   ```

3. **Verify plugin is loaded**:
   ```bash
   sudo journalctl -u pwnagotchi | grep "deauth_whitelist.*loaded"
   ```

4. **Check plugin webhook registration**:
   ```bash
   sudo journalctl -u pwnagotchi | grep -E "(webhook|deauth_whitelist)"
   ```

5. **Test direct API access**:
   ```bash
   curl -X GET http://10.0.0.2:8080/plugins/deauth_whitelist/api/list
   ```

6. **If still not working, restart Pwnagotchi**:
   ```bash
   sudo systemctl restart pwnagotchi
   ```

### Common Issues

**Error: "Page not found" for `/plugins/deauth_whitelist`**
- This usually means the plugin's webhook handler is not registered
- Check that the plugin is enabled and Pwnagotchi has been restarted
- Verify web UI is enabled in config

**Error: Plugin not appearing in logs**
- Check file permissions and syntax errors in the plugin file
- Ensure the plugin is enabled in config.toml
- Try manual validation: `python3 -m py_compile /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py`

**Error: API endpoints return 404**
- The plugin uses the webhook system introduced in newer Pwnagotchi versions
- Ensure you're running a compatible Pwnagotchi version

### Debugging Steps

1. **Check Pwnagotchi version**:
   ```bash
   pwnagotchi --version
   ```

2. **Validate plugin syntax**:
   ```bash
   python3 -m py_compile /usr/local/share/pwnagotchi/custom-plugins/deauth_whitelist.py
   ```

3. **Monitor real-time logs**:
   ```bash
   sudo journalctl -u pwnagotchi -f
   ```

4. **Check whitelist file**:
   ```bash
   ls -la /root/deauth_whitelist.json
   cat /root/deauth_whitelist.json
   ```

### Whitelist not being saved
1. Check permissions for `/root/deauth_whitelist.json`
2. Ensure sufficient disk space is available
3. Check for filesystem errors

## License

GPL v3 - See LICENSE file for details.

## Contributing

Pull requests and issues are welcome! Please follow the Pwnagotchi plugin development guidelines.

## Disclaimer

This plugin is intended only for authorized penetration testing and educational purposes. The user is responsible for proper and legal usage.
