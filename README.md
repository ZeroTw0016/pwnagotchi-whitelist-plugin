# Pwnagotchi Whitelist Plugin

A comprehensive pwnagotchi addon that provides network whitelisting functionality to prevent deauth attacks on specified networks. This plugin allows you to protect trusted networks from being attacked while maintaining full functionality for other targets.

![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)

## 🛡️ Features

### Core Functionality
- **Network Protection**: Prevent deauth attacks on whitelisted networks by BSSID or SSID
- **Persistent Storage**: JSON-based whitelist storage with automatic backups
- **Pattern Matching**: Support for wildcard patterns and regex matching in SSID
- **Import/Export**: Easy whitelist data management with JSON import/export
- **Audit Logging**: Comprehensive logging of all whitelist actions and blocked attacks

### Web Interface
- **Seamless Integration**: Integrates with pwnagotchi's existing web UI
- **Real-time Management**: Add, edit, and remove networks through a modern web interface
- **Search & Filter**: Powerful search and filtering capabilities for large whitelists
- **Statistics Dashboard**: Real-time stats showing whitelist status and activity
- **Responsive Design**: Mobile-friendly interface that works on all devices

### Security Features
- **Input Validation**: Comprehensive validation for all network identifiers
- **Rate Limiting**: Built-in protection against abuse and DoS attacks
- **Secure Operations**: Safe file operations with proper error handling
- **Audit Trail**: Complete audit log of all whitelist modifications

## 📦 Installation

### Prerequisites
- Pwnagotchi v1.5.0 or higher
- Python 3.7+
- Root access to pwnagotchi device

### Quick Install

1. **Download the plugin files**:
   ```bash
   cd /usr/local/share/pwnagotchi/custom-plugins/
   git clone https://github.com/ZeroTw0016/pwnagotchi-whitelist-plugin.git whitelist
   ```

2. **Install dependencies**:
   ```bash
   cd whitelist
   pip3 install -r requirements.txt
   ```

3. **Copy plugin files**:
   ```bash
   cp whitelist.py /usr/local/share/pwnagotchi/custom-plugins/
   cp -r templates/ /usr/local/share/pwnagotchi/custom-plugins/
   cp -r static/ /usr/local/share/pwnagotchi/custom-plugins/
   ```

4. **Configure the plugin** in `/etc/pwnagotchi/config.toml`:
   ```toml
   main.plugins.whitelist.enabled = true
   main.plugins.whitelist.whitelist_file = "/etc/pwnagotchi/whitelist.json"
   main.plugins.whitelist.enforcement_mode = "strict"
   ```

5. **Restart pwnagotchi**:
   ```bash
   systemctl restart pwnagotchi
   ```

### Manual Installation

1. **Create plugin directory**:
   ```bash
   mkdir -p /usr/local/share/pwnagotchi/custom-plugins/whitelist
   ```

2. **Copy files individually**:
   ```bash
   # Main plugin file
   cp whitelist.py /usr/local/share/pwnagotchi/custom-plugins/
   
   # Web interface files
   mkdir -p /usr/local/share/pwnagotchi/custom-plugins/templates
   mkdir -p /usr/local/share/pwnagotchi/custom-plugins/static
   cp templates/whitelist.html /usr/local/share/pwnagotchi/custom-plugins/templates/
   cp static/whitelist.js /usr/local/share/pwnagotchi/custom-plugins/static/
   cp static/whitelist.css /usr/local/share/pwnagotchi/custom-plugins/static/
   ```

3. **Set permissions**:
   ```bash
   chown -R pwnagotchi:pwnagotchi /usr/local/share/pwnagotchi/custom-plugins/
   chmod 644 /usr/local/share/pwnagotchi/custom-plugins/whitelist.py
   ```

## ⚙️ Configuration

### Basic Configuration

Add the following to your `/etc/pwnagotchi/config.toml`:

```toml
main.plugins.whitelist.enabled = true
main.plugins.whitelist.enforcement_mode = "strict"
main.plugins.whitelist.whitelist_file = "/etc/pwnagotchi/whitelist.json"
main.plugins.whitelist.audit_log_file = "/var/log/pwnagotchi_whitelist.log"
```

### Advanced Configuration

For complete configuration options, see `config.yml`:

```yaml
main:
  plugins:
    whitelist:
      enabled: true
      enforcement_mode: "strict"  # "strict" or "lenient"
      
      # File paths
      whitelist_file: "/etc/pwnagotchi/whitelist.json"
      audit_log_file: "/var/log/pwnagotchi_whitelist.log"
      
      # Backup settings
      auto_backup: true
      backup_frequency: "24h"
      max_backups: 5
      
      # Web interface
      web_interface:
        enabled: true
        entries_per_page: 25
        enable_search: true
        enable_filters: true
        
      # Security
      security:
        enable_rate_limiting: true
        max_requests_per_minute: 60
        enable_input_validation: true
        
      # Default entries (optional)
      default_entries:
        - bssid: "00:11:22:33:44:55"
          ssid: "MyHomeNetwork"
          description: "Home WiFi"
          enabled: true
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable the plugin |
| `enforcement_mode` | string | `"strict"` | `"strict"` blocks on errors, `"lenient"` allows attacks on errors |
| `whitelist_file` | string | `/etc/pwnagotchi/whitelist.json` | Path to whitelist storage file |
| `audit_log_file` | string | `/var/log/pwnagotchi_whitelist.log` | Path to audit log file |
| `auto_backup` | boolean | `true` | Enable automatic backups |
| `max_backups` | integer | `5` | Maximum number of backup files to keep |

## 🚀 Usage

### Web Interface

1. **Access the interface**: Navigate to `http://your-pwnagotchi-ip:8080/plugins/whitelist`

2. **Add a network**:
   - Click "➕ Add Network"
   - Enter BSSID (MAC address) and/or SSID (network name)
   - Add description and tags as needed
   - Enable wildcard or regex matching if required
   - Click "Save Network"

3. **Manage existing networks**:
   - Use the search bar to find specific networks
   - Filter by type (BSSID, SSID, wildcard, etc.)
   - Edit networks using the ✏️ button
   - Toggle networks on/off using the 🔒/🔓 button
   - Delete networks using the 🗑️ button

### Command Line Interface

While the web interface is recommended, you can also manage the whitelist programmatically:

```python
# Access the plugin instance
whitelist_plugin = pwnagotchi.plugins.loaded['whitelist']

# Add a network
whitelist_plugin.add_network(
    bssid="00:11:22:33:44:55",
    ssid="MyNetwork",
    description="Home WiFi",
    enabled=True
)

# Remove a network
whitelist_plugin.remove_network("MyNetwork")

# Check if a network is whitelisted
is_whitelisted = whitelist_plugin._is_whitelisted("00:11:22:33:44:55", "MyNetwork")
```

### Pattern Matching

#### Wildcard Patterns
Use asterisk (`*`) and question mark (`?`) for flexible matching:
- `Guest_*` - Matches any SSID starting with "Guest_"
- `COMPANY_???` - Matches SSIDs like "COMPANY_001", "COMPANY_ABC"
- `*_5G` - Matches any SSID ending with "_5G"

#### Regex Patterns
For advanced users, enable regex matching:
- `^MyNetwork.*$` - Matches SSIDs starting with "MyNetwork"
- `.*guest.*` - Matches SSIDs containing "guest" (case-insensitive)
- `^(HOME|WORK)_\d+$` - Matches "HOME_123" or "WORK_456" patterns

### Import/Export

#### Export Whitelist
```bash
# Via web interface - click "📤 Export" button
# Or via API
curl -X GET http://pwnagotchi-ip:8080/api/whitelist/export > whitelist_backup.json
```

#### Import Whitelist
1. Prepare a JSON file with this structure:
   ```json
   {
     "networks": [
       {
         "bssid": "00:11:22:33:44:55",
         "ssid": "MyNetwork",
         "description": "Home WiFi",
         "enabled": true,
         "use_wildcard": false,
         "use_regex": false
       }
     ],
     "version": "1.0"
   }
   ```

2. Import via web interface:
   - Click "📥 Import"
   - Select file or paste JSON data
   - Optionally create backup before import
   - Click "Import"

## 🔒 Security Considerations

### Access Control
- The web interface should only be accessible from trusted networks
- Consider using VPN or SSH tunneling for remote access
- Regularly review audit logs for unauthorized changes

### Input Validation
- All network identifiers are validated before processing
- BSSID format must be valid MAC address (XX:XX:XX:XX:XX:XX)
- SSID length cannot exceed 32 characters
- Regex patterns are validated before use

### Rate Limiting
- Web requests are rate-limited to prevent abuse
- Default limit: 60 requests per minute per IP
- Failed requests are logged for monitoring

## 📊 Monitoring & Logging

### Audit Logging
All whitelist actions are logged to the audit log file:
```
2024-01-15 10:30:15 - INFO - {"timestamp": "2024-01-15T10:30:15", "action": "Network added to whitelist", "details": {"bssid": "00:11:22:33:44:55", "ssid": "MyNetwork"}}
```

### Statistics
The web interface provides real-time statistics:
- Total networks in whitelist
- Active (enabled) networks
- BSSID vs SSID entries
- Wildcard and regex entries
- Plugin status

### Blocked Attacks
When a deauth attack is blocked, it's logged:
```
2024-01-15 10:35:22 - INFO - [whitelist] Blocking deauth attack on whitelisted network: MyNetwork (00:11:22:33:44:55)
```

## 🐛 Troubleshooting

### Common Issues

#### Plugin Not Loading
1. Check pwnagotchi logs: `tail -f /var/log/pwnagotchi.log`
2. Verify file permissions: `ls -la /usr/local/share/pwnagotchi/custom-plugins/whitelist.py`
3. Ensure dependencies are installed: `pip3 list | grep -E "(pwnagotchi|flask|pyyaml)"`

#### Web Interface Not Accessible
1. Check if web UI is enabled in pwnagotchi config
2. Verify plugin is loaded: Check logs for "[whitelist] Plugin loaded successfully"
3. Test API endpoints: `curl http://pwnagotchi-ip:8080/api/whitelist/stats`

#### Networks Still Being Attacked
1. Verify network is in whitelist and enabled
2. Check enforcement mode is set to "strict"
3. Review audit logs for any errors
4. Ensure BSSID/SSID spelling is exact (case-sensitive for SSID)

#### High Memory Usage
1. Check whitelist size: Large whitelists consume more memory
2. Review audit log size: Old logs should be rotated
3. Disable unnecessary features like auto-backup if needed

### Debug Mode
Enable debug logging in config:
```toml
main.plugins.whitelist.logging.level = "DEBUG"
```

### Reset Whitelist
To start fresh:
```bash
# Backup current whitelist
cp /etc/pwnagotchi/whitelist.json /etc/pwnagotchi/whitelist.json.backup

# Remove whitelist file (will be recreated on restart)
rm /etc/pwnagotchi/whitelist.json

# Restart pwnagotchi
systemctl restart pwnagotchi
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make changes**: Follow the existing code style
4. **Add tests**: Ensure new functionality is tested
5. **Update documentation**: Update README and comments
6. **Submit a pull request**: Describe your changes clearly

### Development Setup
```bash
# Clone the repository
git clone https://github.com/ZeroTw0016/pwnagotchi-whitelist-plugin.git
cd pwnagotchi-whitelist-plugin

# Install development dependencies
pip3 install -r requirements.txt

# Run tests (if available)
python3 -m pytest

# Code formatting
black whitelist.py
flake8 whitelist.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Pwnagotchi Project](https://pwnagotchi.ai/) - The amazing AI-powered WiFi hacking companion
- [Flask](https://flask.palletsprojects.com/) - Web framework used for the interface
- [jQuery](https://jquery.com/) - JavaScript library for DOM manipulation

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ZeroTw0016/pwnagotchi-whitelist-plugin/issues)
- **Documentation**: This README and inline code comments
- **Community**: Pwnagotchi Discord/Forums

## 🔄 Changelog

### v1.0.0 (2024-01-15)
- Initial release
- Core whitelist functionality
- Web interface implementation
- Pattern matching support (wildcards and regex)
- Import/export functionality
- Comprehensive audit logging
- Security features (rate limiting, input validation)
- Responsive web design
- Full documentation

---

**⚠️ Disclaimer**: This plugin is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.