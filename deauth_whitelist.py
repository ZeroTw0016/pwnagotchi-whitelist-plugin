"""
Deauth Whitelist Plugin for Pwnagotchi

This plugin manages a whitelist of networks that should not be deauthenticated.
It integrates with the existing web UI to allow adding/removing entries.
"""

import os
import json
import logging
import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from flask import render_template_string, request, jsonify, redirect, url_for


class DeauthWhitelist(plugins.Plugin):
    __author__ = 'pwnagotchi-user'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Manages a whitelist of networks to protect from deauth attacks'

    def __init__(self):
        self.ready = False
        self.whitelist_file = '/root/deauth_whitelist.json'
        self.whitelist = set()
        self.load_whitelist()

    def on_loaded(self):
        """Called when the plugin is loaded"""
        logging.info("[deauth_whitelist] Plugin loaded")
        self.ready = True
        
        # Register web routes if web UI is enabled
        if hasattr(plugins, '_loaded_plugins'):
            self._register_web_routes()

    def on_ready(self, agent):
        """Called when the agent is ready"""
        logging.info(f"[deauth_whitelist] Plugin ready with {len(self.whitelist)} whitelisted networks")

    def on_deauth(self, agent, access_point):
        """Called before a deauth attack - return False to prevent the attack"""
        if not self.ready:
            return True
            
        # Check if the AP is in the whitelist
        ap_mac = access_point.get('mac', '').lower()
        ap_essid = access_point.get('hostname', '') or access_point.get('name', '')
        
        # Check both MAC address and ESSID
        if ap_mac in self.whitelist or ap_essid in self.whitelist:
            logging.info(f"[deauth_whitelist] Blocking deauth for whitelisted network: {ap_essid} ({ap_mac})")
            return False
            
        return True

    def load_whitelist(self):
        """Load the whitelist from file"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    self.whitelist = set(entry.lower() for entry in data.get('whitelist', []))
                logging.info(f"[deauth_whitelist] Loaded {len(self.whitelist)} entries from whitelist")
            else:
                self.whitelist = set()
                self.save_whitelist()
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error loading whitelist: {e}")
            self.whitelist = set()

    def save_whitelist(self):
        """Save the whitelist to file"""
        try:
            data = {
                'whitelist': list(self.whitelist),
                'last_updated': StatusFile.timestamp()
            }
            with open(self.whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)
            logging.info(f"[deauth_whitelist] Saved {len(self.whitelist)} entries to whitelist")
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error saving whitelist: {e}")

    def add_to_whitelist(self, entry):
        """Add an entry to the whitelist"""
        if entry:
            self.whitelist.add(entry.lower())
            self.save_whitelist()
            return True
        return False

    def remove_from_whitelist(self, entry):
        """Remove an entry from the whitelist"""
        if entry and entry.lower() in self.whitelist:
            self.whitelist.remove(entry.lower())
            self.save_whitelist()
            return True
        return False

    def get_whitelist(self):
        """Get the current whitelist"""
        return sorted(list(self.whitelist))

    def _register_web_routes(self):
        """Register web routes for the plugin"""
        try:
            # Import the web application instance
            from pwnagotchi.ui.web import app
            
            @app.route('/plugins/deauth_whitelist')
            def deauth_whitelist_index():
                return render_template_string(WHITELIST_TEMPLATE, 
                                            whitelist=self.get_whitelist())
            
            @app.route('/plugins/deauth_whitelist/api/add', methods=['POST'])
            def deauth_whitelist_add():
                entry = request.json.get('entry', '').strip()
                if entry:
                    if self.add_to_whitelist(entry):
                        return jsonify({'success': True, 'message': f'Added "{entry}" to whitelist'})
                    else:
                        return jsonify({'success': False, 'message': 'Entry already exists'})
                return jsonify({'success': False, 'message': 'Invalid entry'})
            
            @app.route('/plugins/deauth_whitelist/api/remove', methods=['POST'])
            def deauth_whitelist_remove():
                entry = request.json.get('entry', '').strip()
                if self.remove_from_whitelist(entry):
                    return jsonify({'success': True, 'message': f'Removed "{entry}" from whitelist'})
                return jsonify({'success': False, 'message': 'Entry not found'})
            
            @app.route('/plugins/deauth_whitelist/api/list')
            def deauth_whitelist_list():
                return jsonify({'whitelist': self.get_whitelist()})
                
            logging.info("[deauth_whitelist] Web routes registered")
            
        except Exception as e:
            logging.error(f"[deauth_whitelist] Failed to register web routes: {e}")


# HTML template for the web interface
WHITELIST_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deauth Whitelist - Pwnagotchi</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #000;
            color: #0f0;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #111;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #0f0;
        }
        h1 {
            text-align: center;
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
            margin-bottom: 30px;
        }
        .add-form {
            background-color: #222;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border: 1px solid #0f0;
        }
        .add-form h3 {
            margin-top: 0;
            color: #0f0;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            background-color: #000;
            color: #0f0;
            border: 1px solid #0f0;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        button {
            padding: 10px 20px;
            background-color: #000;
            color: #0f0;
            border: 1px solid #0f0;
            border-radius: 3px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            margin-left: 10px;
        }
        button:hover {
            background-color: #0f0;
            color: #000;
        }
        .whitelist-container {
            background-color: #222;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid #0f0;
        }
        .whitelist-container h3 {
            margin-top: 0;
            color: #0f0;
        }
        .whitelist-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            margin: 5px 0;
            background-color: #333;
            border-radius: 3px;
            border-left: 3px solid #0f0;
        }
        .whitelist-item span {
            color: #0f0;
            font-weight: bold;
        }
        .remove-btn {
            background-color: #600;
            border-color: #f00;
            color: #f00;
            padding: 5px 10px;
            margin: 0;
        }
        .remove-btn:hover {
            background-color: #f00;
            color: #000;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
            text-align: center;
        }
        .success {
            background-color: #004400;
            border: 1px solid #0f0;
            color: #0f0;
        }
        .error {
            background-color: #440000;
            border: 1px solid #f00;
            color: #f00;
        }
        .help-text {
            font-size: 0.9em;
            color: #888;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Deauth Whitelist Manager</h1>
        
        <div class="add-form">
            <h3>Add Network to Whitelist</h3>
            <input type="text" id="entryInput" placeholder="Enter MAC address (aa:bb:cc:dd:ee:ff) or ESSID">
            <button onclick="addEntry()">Add Entry</button>
            <div class="help-text">
                💡 You can add either MAC addresses (e.g., aa:bb:cc:dd:ee:ff) or network names (ESSID).
                Networks in this list will be protected from deauth attacks.
            </div>
        </div>
        
        <div id="message"></div>
        
        <div class="whitelist-container">
            <h3>Current Whitelist ({{ whitelist|length }} entries)</h3>
            <div id="whitelistItems">
                {% if whitelist %}
                    {% for entry in whitelist %}
                    <div class="whitelist-item">
                        <span>{{ entry }}</span>
                        <button class="remove-btn" onclick="removeEntry('{{ entry }}')">Remove</button>
                    </div>
                    {% endfor %}
                {% else %}
                    <div style="text-align: center; color: #888; padding: 20px;">
                        No entries in whitelist. Add some networks to protect them from deauth attacks.
                    </div>
                {% endif %}
            </div>
        </div>
    </div>

    <script>
        function showMessage(text, type) {
            const messageDiv = document.getElementById('message');
            messageDiv.innerHTML = `<div class="message ${type}">${text}</div>`;
            setTimeout(() => {
                messageDiv.innerHTML = '';
            }, 3000);
        }

        function addEntry() {
            const input = document.getElementById('entryInput');
            const entry = input.value.trim();
            
            if (!entry) {
                showMessage('Please enter a MAC address or ESSID', 'error');
                return;
            }
            
            fetch('/plugins/deauth_whitelist/api/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({entry: entry})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage(data.message, 'success');
                    input.value = '';
                    refreshWhitelist();
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage('Error adding entry', 'error');
                console.error('Error:', error);
            });
        }

        function removeEntry(entry) {
            if (!confirm(`Are you sure you want to remove "${entry}" from the whitelist?`)) {
                return;
            }
            
            fetch('/plugins/deauth_whitelist/api/remove', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({entry: entry})
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showMessage(data.message, 'success');
                    refreshWhitelist();
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(error => {
                showMessage('Error removing entry', 'error');
                console.error('Error:', error);
            });
        }

        function refreshWhitelist() {
            fetch('/plugins/deauth_whitelist/api/list')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('whitelistItems');
                if (data.whitelist.length > 0) {
                    container.innerHTML = data.whitelist.map(entry => `
                        <div class="whitelist-item">
                            <span>${entry}</span>
                            <button class="remove-btn" onclick="removeEntry('${entry}')">Remove</button>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = `
                        <div style="text-align: center; color: #888; padding: 20px;">
                            No entries in whitelist. Add some networks to protect them from deauth attacks.
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error('Error refreshing whitelist:', error);
            });
        }

        // Allow Enter key to add entry
        document.getElementById('entryInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                addEntry();
            }
        });
    </script>
</body>
</html>
"""
