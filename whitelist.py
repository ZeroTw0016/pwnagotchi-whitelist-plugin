"""
Pwnagotchi Whitelist Plugin

A comprehensive plugin that provides network whitelisting functionality
to prevent deauth attacks on specified networks.

Author: ZeroTw0016
"""

import os
import json
import logging
import fnmatch
import re
from datetime import datetime
from typing import Dict, List, Optional, Union

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from flask import render_template, request, jsonify, Blueprint


class Whitelist(plugins.Plugin):
    __author__ = 'ZeroTw0016'
    __version__ = '1.0.0'
    __license__ = 'MIT'
    __description__ = 'Network whitelist plugin to prevent deauth attacks on specified networks'

    def __init__(self):
        self.ready = False
        self.whitelist_file = None
        self.whitelist_data = {
            'networks': [],
            'last_updated': None,
            'version': '1.0'
        }
        self.audit_log = []
        
    def on_loaded(self):
        """Initialize the plugin when loaded."""
        try:
            # Set up file paths
            self.whitelist_file = self.options.get('whitelist_file', '/etc/pwnagotchi/whitelist.json')
            self.audit_log_file = self.options.get('audit_log_file', '/var/log/pwnagotchi_whitelist.log')
            
            # Ensure directories exist
            os.makedirs(os.path.dirname(self.whitelist_file), exist_ok=True)
            os.makedirs(os.path.dirname(self.audit_log_file), exist_ok=True)
            
            # Load existing whitelist or create new one
            self._load_whitelist()
            
            # Set up logging
            self._setup_logging()
            
            logging.info("[whitelist] Plugin loaded successfully")
            self.ready = True
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to initialize: {e}")
            self.ready = False

    def on_ready(self, agent):
        """Called when the agent is ready."""
        if self.ready:
            logging.info("[whitelist] Plugin ready for operation")
            self._log_audit("Plugin initialized", {"version": self.__version__})

    def on_internet_available(self, agent):
        """Called when internet connection is available."""
        if self.ready and self.options.get('auto_backup', True):
            self._create_backup()

    def on_deauth(self, agent, access_point):
        """
        Hook into deauth attacks to check whitelist.
        This is the core functionality that prevents attacks on whitelisted networks.
        """
        if not self.ready:
            return
            
        try:
            bssid = access_point.get('mac', '').upper()
            ssid = access_point.get('hostname', '') or access_point.get('name', '')
            
            if self._is_whitelisted(bssid, ssid):
                # Network is whitelisted - prevent the attack
                logging.info(f"[whitelist] Blocking deauth attack on whitelisted network: {ssid} ({bssid})")
                self._log_audit("Blocked deauth attack", {
                    "bssid": bssid,
                    "ssid": ssid,
                    "reason": "Network is whitelisted"
                })
                
                # Return False to cancel the attack
                return False
                
        except Exception as e:
            logging.error(f"[whitelist] Error in deauth hook: {e}")
            
        # Allow the attack to proceed if not whitelisted or error occurred
        return True

    def on_handshake(self, agent, filename, access_point, client_station):
        """Log handshake captures for whitelisted networks."""
        if not self.ready:
            return
            
        try:
            bssid = access_point.get('mac', '').upper()
            ssid = access_point.get('hostname', '') or access_point.get('name', '')
            
            if self._is_whitelisted(bssid, ssid):
                self._log_audit("Handshake captured from whitelisted network", {
                    "bssid": bssid,
                    "ssid": ssid,
                    "filename": filename
                })
                
        except Exception as e:
            logging.error(f"[whitelist] Error in handshake hook: {e}")

    def _load_whitelist(self):
        """Load whitelist data from JSON file."""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    self.whitelist_data = json.load(f)
                    
                # Ensure required fields exist
                if 'networks' not in self.whitelist_data:
                    self.whitelist_data['networks'] = []
                if 'version' not in self.whitelist_data:
                    self.whitelist_data['version'] = '1.0'
                    
                logging.info(f"[whitelist] Loaded {len(self.whitelist_data['networks'])} whitelisted networks")
            else:
                # Create default whitelist file
                self.whitelist_data = {'networks': [], 'version': '1.0'}
                self._add_default_entries()
                self._save_whitelist()
                logging.info("[whitelist] Created new whitelist file with default entries")
                
        except Exception as e:
            logging.error(f"[whitelist] Failed to load whitelist: {e}")
            self.whitelist_data = {'networks': [], 'version': '1.0'}

    def _add_default_entries(self):
        """Add default whitelist entries from configuration."""
        try:
            default_entries = self.options.get('default_entries', [])
            for entry in default_entries:
                if self._validate_entry(entry):
                    # Add ID to entry
                    entry['id'] = len(self.whitelist_data['networks']) + 1
                    entry['added_date'] = datetime.now().isoformat()
                    self.whitelist_data['networks'].append(entry)
                    logging.info(f"[whitelist] Added default entry: {entry.get('ssid', entry.get('bssid', 'Unknown'))}")
        except Exception as e:
            logging.error(f"[whitelist] Failed to add default entries: {e}")

    def _save_whitelist(self):
        """Save whitelist data to JSON file."""
        try:
            self.whitelist_data['last_updated'] = datetime.now().isoformat()
            
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.whitelist_data, f, indent=2)
                
            logging.debug("[whitelist] Whitelist saved successfully")
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to save whitelist: {e}")

    def _is_whitelisted(self, bssid: str, ssid: str) -> bool:
        """
        Check if a network is whitelisted by BSSID or SSID.
        Supports wildcard patterns for SSID matching.
        """
        try:
            enforcement_mode = self.options.get('enforcement_mode', 'strict')
            
            for entry in self.whitelist_data['networks']:
                if not entry.get('enabled', True):
                    continue
                    
                # Check BSSID match
                if bssid and entry.get('bssid'):
                    if bssid.upper() == entry['bssid'].upper():
                        return True
                        
                # Check SSID match (with wildcard support)
                if ssid and entry.get('ssid'):
                    if entry.get('use_wildcard', False):
                        # Use fnmatch for wildcard pattern matching
                        if fnmatch.fnmatch(ssid, entry['ssid']):
                            return True
                    else:
                        # Exact match
                        if ssid == entry['ssid']:
                            return True
                            
                # Check regex patterns if enabled
                if ssid and entry.get('regex_pattern') and entry.get('use_regex', False):
                    try:
                        if re.match(entry['regex_pattern'], ssid, re.IGNORECASE):
                            return True
                    except re.error:
                        logging.warning(f"[whitelist] Invalid regex pattern: {entry['regex_pattern']}")
                        
            return False
            
        except Exception as e:
            logging.error(f"[whitelist] Error checking whitelist: {e}")
            # In strict mode, err on the side of caution and whitelist on error
            return enforcement_mode == 'strict'

    def add_network(self, bssid: str = None, ssid: str = None, **kwargs) -> bool:
        """Add a network to the whitelist."""
        try:
            if not bssid and not ssid:
                raise ValueError("Either BSSID or SSID must be provided")
                
            # Validate inputs
            if bssid:
                bssid = self._validate_bssid(bssid)
            if ssid:
                ssid = self._validate_ssid(ssid)
                
            # Check for duplicates
            for entry in self.whitelist_data['networks']:
                if (bssid and entry.get('bssid') == bssid) or \
                   (ssid and entry.get('ssid') == ssid and not entry.get('use_wildcard', False)):
                    return False  # Already exists
                    
            # Create new entry
            entry = {
                'id': len(self.whitelist_data['networks']) + 1,
                'bssid': bssid,
                'ssid': ssid,
                'added_date': datetime.now().isoformat(),
                'enabled': kwargs.get('enabled', True),
                'use_wildcard': kwargs.get('use_wildcard', False),
                'use_regex': kwargs.get('use_regex', False),
                'regex_pattern': kwargs.get('regex_pattern'),
                'description': kwargs.get('description', ''),
                'tags': kwargs.get('tags', [])
            }
            
            self.whitelist_data['networks'].append(entry)
            self._save_whitelist()
            
            self._log_audit("Network added to whitelist", entry)
            logging.info(f"[whitelist] Added network: {ssid or bssid}")
            
            return True
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to add network: {e}")
            return False

    def remove_network(self, identifier: Union[str, int]) -> bool:
        """Remove a network from the whitelist by ID, BSSID, or SSID."""
        try:
            removed = False
            original_count = len(self.whitelist_data['networks'])
            
            if isinstance(identifier, int):
                # Remove by ID
                self.whitelist_data['networks'] = [
                    entry for entry in self.whitelist_data['networks'] 
                    if entry.get('id') != identifier
                ]
            else:
                # Remove by BSSID or SSID
                identifier = identifier.upper() if ':' in identifier else identifier
                self.whitelist_data['networks'] = [
                    entry for entry in self.whitelist_data['networks'] 
                    if not (entry.get('bssid', '').upper() == identifier or 
                           entry.get('ssid') == identifier)
                ]
                
            removed = len(self.whitelist_data['networks']) < original_count
            
            if removed:
                self._save_whitelist()
                self._log_audit("Network removed from whitelist", {"identifier": identifier})
                logging.info(f"[whitelist] Removed network: {identifier}")
                
            return removed
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to remove network: {e}")
            return False

    def get_whitelist(self) -> List[Dict]:
        """Get the current whitelist."""
        return self.whitelist_data.get('networks', [])

    def import_whitelist(self, data: Dict) -> bool:
        """Import whitelist data."""
        try:
            if 'networks' in data and isinstance(data['networks'], list):
                # Validate imported data
                valid_networks = []
                for entry in data['networks']:
                    if self._validate_entry(entry):
                        valid_networks.append(entry)
                        
                if valid_networks:
                    self.whitelist_data['networks'].extend(valid_networks)
                    self._save_whitelist()
                    
                    self._log_audit("Whitelist imported", {
                        "imported_count": len(valid_networks),
                        "total_count": len(self.whitelist_data['networks'])
                    })
                    
                    return True
                    
            return False
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to import whitelist: {e}")
            return False

    def export_whitelist(self) -> Dict:
        """Export whitelist data."""
        try:
            return {
                'networks': self.whitelist_data['networks'],
                'exported_date': datetime.now().isoformat(),
                'version': self.whitelist_data['version']
            }
        except Exception as e:
            logging.error(f"[whitelist] Failed to export whitelist: {e}")
            return {}

    def _validate_bssid(self, bssid: str) -> str:
        """Validate and normalize BSSID format."""
        if not bssid:
            raise ValueError("BSSID cannot be empty")
            
        # Remove common separators and normalize
        bssid = bssid.replace('-', ':').replace('.', ':').upper()
        
        # Validate MAC address format
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
            raise ValueError("Invalid BSSID format")
            
        return bssid

    def _validate_ssid(self, ssid: str) -> str:
        """Validate SSID."""
        if not ssid:
            raise ValueError("SSID cannot be empty")
            
        if len(ssid) > 32:
            raise ValueError("SSID cannot be longer than 32 characters")
            
        return ssid

    def _validate_entry(self, entry: Dict) -> bool:
        """Validate a whitelist entry."""
        try:
            if not isinstance(entry, dict):
                return False
                
            # Must have either BSSID or SSID
            if not entry.get('bssid') and not entry.get('ssid'):
                return False
                
            # Validate BSSID if present
            if entry.get('bssid'):
                self._validate_bssid(entry['bssid'])
                
            # Validate SSID if present
            if entry.get('ssid'):
                self._validate_ssid(entry['ssid'])
                
            return True
            
        except Exception:
            return False

    def _setup_logging(self):
        """Set up audit logging."""
        try:
            # Configure audit logger
            audit_logger = logging.getLogger('whitelist_audit')
            audit_logger.setLevel(logging.INFO)
            
            # Create file handler for audit log
            handler = logging.FileHandler(self.audit_log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            audit_logger.addHandler(handler)
            
        except Exception as e:
            logging.error(f"[whitelist] Failed to setup audit logging: {e}")

    def _log_audit(self, action: str, details: Dict):
        """Log audit events."""
        try:
            audit_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'details': details
            }
            
            # Log to audit logger
            audit_logger = logging.getLogger('whitelist_audit')
            audit_logger.info(json.dumps(audit_entry))
            
            # Keep in-memory audit log (limited size)
            self.audit_log.append(audit_entry)
            if len(self.audit_log) > 1000:  # Keep last 1000 entries
                self.audit_log = self.audit_log[-1000:]
                
        except Exception as e:
            logging.error(f"[whitelist] Failed to log audit event: {e}")

    def _create_backup(self):
        """Create a backup of the whitelist file."""
        try:
            if os.path.exists(self.whitelist_file):
                backup_file = f"{self.whitelist_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                import shutil
                shutil.copy2(self.whitelist_file, backup_file)
                
                logging.info(f"[whitelist] Backup created: {backup_file}")
                
                # Clean old backups (keep last 5)
                backup_dir = os.path.dirname(self.whitelist_file)
                backup_files = sorted([
                    f for f in os.listdir(backup_dir) 
                    if f.startswith(os.path.basename(self.whitelist_file) + '.backup.')
                ])
                
                if len(backup_files) > 5:
                    for old_backup in backup_files[:-5]:
                        os.remove(os.path.join(backup_dir, old_backup))
                        
        except Exception as e:
            logging.error(f"[whitelist] Failed to create backup: {e}")

    def get_stats(self) -> Dict:
        """Get plugin statistics."""
        try:
            return {
                'total_networks': len(self.whitelist_data['networks']),
                'enabled_networks': len([n for n in self.whitelist_data['networks'] if n.get('enabled', True)]),
                'bssid_entries': len([n for n in self.whitelist_data['networks'] if n.get('bssid')]),
                'ssid_entries': len([n for n in self.whitelist_data['networks'] if n.get('ssid')]),
                'wildcard_entries': len([n for n in self.whitelist_data['networks'] if n.get('use_wildcard', False)]),
                'regex_entries': len([n for n in self.whitelist_data['networks'] if n.get('use_regex', False)]),
                'last_updated': self.whitelist_data.get('last_updated'),
                'plugin_version': self.__version__,
                'ready': self.ready
            }
        except Exception:
            return {}

    def on_webhook(self, path, request):
        """Handle webhook requests for web interface integration."""
        if not self.ready:
            return "Plugin not ready", 503
            
        # Web interface routes
        if path == '' or path == '/':
            return render_template('whitelist.html')
            
        # API routes
        elif path == '/api/stats':
            return jsonify(self.get_stats())
            
        elif path == '/api/whitelist':
            if request.method == 'GET':
                return jsonify({
                    'networks': self.get_whitelist(),
                    'stats': self.get_stats()
                })
                
        elif path == '/api/whitelist/add':
            if request.method == 'POST':
                try:
                    data = request.get_json()
                    success = self.add_network(**data)
                    if success:
                        return jsonify({'status': 'success', 'message': 'Network added successfully'})
                    else:
                        return jsonify({'status': 'error', 'message': 'Failed to add network or network already exists'}), 400
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 400
                    
        elif path == '/api/whitelist/update':
            if request.method == 'PUT':
                try:
                    data = request.get_json()
                    network_id = data.get('id')
                    
                    # Remove old entry
                    if self.remove_network(network_id):
                        # Add updated entry
                        success = self.add_network(**{k: v for k, v in data.items() if k != 'id'})
                        if success:
                            return jsonify({'status': 'success', 'message': 'Network updated successfully'})
                    
                    return jsonify({'status': 'error', 'message': 'Failed to update network'}), 400
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 400
                    
        elif path == '/api/whitelist/delete':
            if request.method == 'DELETE':
                try:
                    data = request.get_json()
                    network_id = data.get('id')
                    success = self.remove_network(network_id)
                    if success:
                        return jsonify({'status': 'success', 'message': 'Network deleted successfully'})
                    else:
                        return jsonify({'status': 'error', 'message': 'Network not found'}), 404
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 400
                    
        elif path == '/api/whitelist/toggle':
            if request.method == 'PUT':
                try:
                    data = request.get_json()
                    network_id = data.get('id')
                    enabled = data.get('enabled', True)
                    
                    # Find and update the network
                    for network in self.whitelist_data['networks']:
                        if network.get('id') == network_id:
                            network['enabled'] = enabled
                            self._save_whitelist()
                            self._log_audit("Network toggled", {
                                "id": network_id,
                                "enabled": enabled
                            })
                            return jsonify({'status': 'success', 'message': f'Network {"enabled" if enabled else "disabled"}'})
                    
                    return jsonify({'status': 'error', 'message': 'Network not found'}), 404
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 400
                    
        elif path == '/api/whitelist/import':
            if request.method == 'POST':
                try:
                    data = request.get_json()
                    import_data = data.get('data', {})
                    create_backup = data.get('create_backup', True)
                    
                    if create_backup:
                        self._create_backup()
                        
                    success = self.import_whitelist(import_data)
                    if success:
                        return jsonify({'status': 'success', 'message': 'Whitelist imported successfully'})
                    else:
                        return jsonify({'status': 'error', 'message': 'Invalid import data'}), 400
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 400
                    
        elif path == '/api/whitelist/export':
            if request.method == 'GET':
                try:
                    export_data = self.export_whitelist()
                    return jsonify(export_data)
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 500
                    
        return "Not Found", 404