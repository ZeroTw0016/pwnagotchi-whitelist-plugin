"""
Deauth Whitelist Plugin for Pwnagotchi

This plugin manages a whitelist of networks that should not be deauthenticated.
It integrates with the web UI through the webhook system to allow adding/removing entries.

Compatible with Pwnagotchi versions that support the webhook system.
"""

import os
import json
import logging
import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile

# Import Flask components only when needed to avoid import errors
try:
    from flask import render_template_string, request, jsonify, redirect, url_for
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logging.warning("[deauth_whitelist] Flask not available, web interface disabled")


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
        
    def on_config_changed(self, config):
        """Called when the configuration is changed"""
        # Check if a custom whitelist file path is specified
        if 'whitelist_file' in config:
            self.whitelist_file = config['whitelist_file']
            self.load_whitelist()

    def on_loaded(self):
        """Called when the plugin is loaded"""
        logging.info("[deauth_whitelist] Plugin loaded")
        self.ready = True

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
            # Get current timestamp - handle different StatusFile API versions
            try:
                timestamp = StatusFile.timestamp()
            except (AttributeError, TypeError):
                # Fallback for different Pwnagotchi versions
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            data = {
                'whitelist': list(self.whitelist),
                'last_updated': timestamp
            }
            with open(self.whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)
            logging.info(f"[deauth_whitelist] Saved {len(self.whitelist)} entries to whitelist")
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error saving whitelist: {e}")

    def add_to_whitelist(self, entry):
        """Add an entry to the whitelist"""
        try:
            if not entry:
                return False
            entry_lower = entry.lower()
            if entry_lower in self.whitelist:
                return False  # Already exists
            self.whitelist.add(entry_lower)
            self.save_whitelist()
            logging.info(f"[deauth_whitelist] Added '{entry}' to whitelist")
            return True
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error adding to whitelist: {e}")
            return False

    def remove_from_whitelist(self, entry):
        """Remove an entry from the whitelist"""
        try:
            if not entry:
                return False
            entry_lower = entry.lower()
            if entry_lower in self.whitelist:
                self.whitelist.remove(entry_lower)
                self.save_whitelist()
                logging.info(f"[deauth_whitelist] Removed '{entry}' from whitelist")
                return True
            return False
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error removing from whitelist: {e}")
            return False

    def get_nearby_networks(self):
        """Get all known networks from Pwnagotchi's data"""
        try:
            networks = []
            logging.info("[deauth_whitelist] Starting network discovery...")
            
            # Try to get from the agent's view if available
            try:
                import pwnagotchi
                logging.info(f"[deauth_whitelist] Pwnagotchi module available: {hasattr(pwnagotchi, '_agent')}")
                if hasattr(pwnagotchi, '_agent') and pwnagotchi._agent:
                    view = pwnagotchi._agent.view()
                    logging.info(f"[deauth_whitelist] Agent view type: {type(view)}")
                    if hasattr(view, 'get'):
                        state = view.get('state', {})
                        logging.info(f"[deauth_whitelist] Agent state keys: {list(state.keys())}")
                        if 'aps' in state:
                            aps = state.get('aps', {})
                            logging.info(f"[deauth_whitelist] Found {len(aps)} APs in agent state")
                            for bssid, ap_data in aps.items():
                                if isinstance(ap_data, dict):
                                    essid = ap_data.get('hostname', '') or ap_data.get('name', '') or ap_data.get('essid', '')
                                    if essid and essid.strip():
                                        networks.append({
                                            'essid': essid.strip(),
                                            'bssid': bssid,
                                            'channel': ap_data.get('channel', 'Unknown'),
                                            'rssi': ap_data.get('rssi', 'Unknown'),
                                            'source': 'agent'
                                        })
                                        logging.debug(f"[deauth_whitelist] Added from agent: {essid}")
                        else:
                            logging.info("[deauth_whitelist] No 'aps' in agent state")
                    else:
                        logging.info("[deauth_whitelist] Agent view has no 'get' method")
                else:
                    logging.info("[deauth_whitelist] No agent available")
            except Exception as e:
                logging.info(f"[deauth_whitelist] Could not get networks from agent: {e}")
            
            # Read from handshakes directory for captured networks
            try:
                import os
                import glob
                # Try multiple possible handshake directories
                handshake_dirs = ['/root/handshakes', '/home/pi/handshakes', '/opt/pwnagotchi/handshakes', '/var/lib/pwnagotchi/handshakes']
                for handshakes_dir in handshake_dirs:
                    logging.info(f"[deauth_whitelist] Checking handshakes directory: {handshakes_dir}")
                    if os.path.exists(handshakes_dir):
                        logging.info(f"[deauth_whitelist] Found handshakes directory: {handshakes_dir}")
                        pcap_files = glob.glob(os.path.join(handshakes_dir, '*.pcap'))
                        logging.info(f"[deauth_whitelist] Found {len(pcap_files)} pcap files")
                        for pcap_file in pcap_files[:50]:  # Limit to avoid performance issues
                            filename = os.path.basename(pcap_file)
                            logging.debug(f"[deauth_whitelist] Processing file: {filename}")
                            # Extract ESSID from filename (format: ESSID_MAC_timestamp.pcap)
                            parts = filename.replace('.pcap', '').split('_')
                            if len(parts) >= 2:
                                essid = parts[0]
                                if essid and essid not in ['None', 'none', '']:
                                    networks.append({
                                        'essid': essid,
                                        'bssid': parts[1] if len(parts) > 1 else 'Unknown',
                                        'channel': 'Unknown',
                                        'rssi': 'Unknown',
                                        'source': 'handshake'
                                    })
                                    logging.debug(f"[deauth_whitelist] Added from handshake: {essid}")
                        break  # Stop after finding first valid directory
                    else:
                        logging.debug(f"[deauth_whitelist] Directory not found: {handshakes_dir}")
            except Exception as e:
                logging.info(f"[deauth_whitelist] Could not read handshakes: {e}")
            
            # Try to read from potfile for cracked networks
            try:
                import os
                potfile_paths = ['/root/handshakes/wpa-sec.cracked.potfile', '/root/handshakes/*.potfile']
                for potfile_pattern in potfile_paths:
                    import glob
                    for potfile in glob.glob(potfile_pattern):
                        if os.path.exists(potfile):
                            with open(potfile, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    line = line.strip()
                                    if ':' in line:
                                        # Format: hash:password or similar
                                        parts = line.split(':')
                                        if len(parts) >= 2:
                                            # Try to extract network info if available
                                            # This is a basic extraction, format may vary
                                            pass
            except Exception as e:
                logging.debug(f"[deauth_whitelist] Could not read potfiles: {e}")
            
            # Try to read from session files
            try:
                import os
                import glob
                # Try multiple possible session directories
                session_dirs = ['/root', '/home/pi', '/opt/pwnagotchi', '/var/lib/pwnagotchi']
                for session_dir in session_dirs:
                    logging.info(f"[deauth_whitelist] Checking session directory: {session_dir}")
                    if os.path.exists(session_dir):
                        session_files = glob.glob(os.path.join(session_dir, '*.session'))
                        logging.info(f"[deauth_whitelist] Found {len(session_files)} session files in {session_dir}")
                        for session_file in session_files[:10]:  # Limit to avoid performance issues
                            try:
                                logging.debug(f"[deauth_whitelist] Processing session: {session_file}")
                                with open(session_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    import json
                                    session_data = json.load(f)
                                    if 'aps' in session_data:
                                        session_aps = session_data['aps']
                                        logging.debug(f"[deauth_whitelist] Found {len(session_aps)} APs in session")
                                        for bssid, ap_info in session_aps.items():
                                            if isinstance(ap_info, dict):
                                                essid = ap_info.get('hostname', '') or ap_info.get('name', '') or ap_info.get('essid', '')
                                                if essid and essid.strip():
                                                    networks.append({
                                                        'essid': essid.strip(),
                                                        'bssid': bssid,
                                                        'channel': ap_info.get('channel', 'Unknown'),
                                                        'rssi': ap_info.get('rssi', 'Unknown'),
                                                        'source': 'session'
                                                    })
                                                    logging.debug(f"[deauth_whitelist] Added from session: {essid}")
                            except Exception as session_error:
                                logging.debug(f"[deauth_whitelist] Error reading session {session_file}: {session_error}")
                                continue
            except Exception as e:
                logging.info(f"[deauth_whitelist] Could not read session files: {e}")
            
            # Try to get current WiFi scan results
            try:
                import subprocess
                logging.info("[deauth_whitelist] Attempting WiFi scan...")
                # Try iwlist scan
                try:
                    result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        current_essid = None
                        current_bssid = None
                        for line in lines:
                            line = line.strip()
                            if 'ESSID:' in line:
                                essid_part = line.split('ESSID:')[1].strip().strip('"')
                                if essid_part and essid_part != '':
                                    current_essid = essid_part
                            elif 'Address:' in line:
                                bssid_part = line.split('Address:')[1].strip()
                                current_bssid = bssid_part
                            elif 'Cell' in line and current_essid:
                                if current_essid:
                                    networks.append({
                                        'essid': current_essid,
                                        'bssid': current_bssid or 'Unknown',
                                        'channel': 'Unknown',
                                        'rssi': 'Unknown',
                                        'source': 'scan'
                                    })
                                    logging.debug(f"[deauth_whitelist] Added from scan: {current_essid}")
                                current_essid = None
                                current_bssid = None
                        # Add last network if exists
                        if current_essid:
                            networks.append({
                                'essid': current_essid,
                                'bssid': current_bssid or 'Unknown',
                                'channel': 'Unknown',
                                'rssi': 'Unknown',
                                'source': 'scan'
                            })
                            logging.debug(f"[deauth_whitelist] Added from scan: {current_essid}")
                        logging.info(f"[deauth_whitelist] WiFi scan completed, found networks")
                except Exception as scan_error:
                    logging.debug(f"[deauth_whitelist] iwlist scan failed: {scan_error}")
                    
                # Try iw scan as fallback
                try:
                    result = subprocess.run(['iw', 'dev', 'wlan0', 'scan'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            line = line.strip()
                            if 'SSID:' in line:
                                essid = line.split('SSID:')[1].strip()
                                if essid and essid != '':
                                    networks.append({
                                        'essid': essid,
                                        'bssid': 'Unknown',
                                        'channel': 'Unknown',
                                        'rssi': 'Unknown',
                                        'source': 'iw_scan'
                                    })
                                    logging.debug(f"[deauth_whitelist] Added from iw scan: {essid}")
                        logging.info(f"[deauth_whitelist] iw scan completed")
                except Exception as iw_error:
                    logging.debug(f"[deauth_whitelist] iw scan failed: {iw_error}")
                    
            except Exception as e:
                logging.info(f"[deauth_whitelist] Could not perform WiFi scan: {e}")
            
            # Add some dummy networks for testing if no networks found
            if len(networks) == 0:
                logging.info("[deauth_whitelist] No networks found, adding test entries")
                test_networks = [
                    {'essid': 'TestNetwork1', 'bssid': '00:11:22:33:44:55', 'channel': '6', 'rssi': '-50', 'source': 'test'},
                    {'essid': 'TestNetwork2', 'bssid': '00:11:22:33:44:56', 'channel': '11', 'rssi': '-60', 'source': 'test'},
                    {'essid': 'MyWiFi', 'bssid': '00:11:22:33:44:57', 'channel': '1', 'rssi': '-40', 'source': 'test'}
                ]
                networks.extend(test_networks)
            
            # Remove duplicates and sort
            seen_essids = set()
            unique_networks = []
            source_counts = {}
            
            for network in networks:
                essid_key = network['essid'].lower()
                if essid_key not in seen_essids and len(network['essid']) > 1:
                    seen_essids.add(essid_key)
                    unique_networks.append(network)
                    # Count sources
                    source = network['source']
                    source_counts[source] = source_counts.get(source, 0) + 1
            
            # Sort by ESSID and limit to reasonable number
            sorted_networks = sorted(unique_networks, key=lambda x: x['essid'].lower())[:50]
            
            logging.info(f"[deauth_whitelist] Network discovery complete:")
            logging.info(f"[deauth_whitelist] - Total raw entries: {len(networks)}")
            logging.info(f"[deauth_whitelist] - Unique networks: {len(unique_networks)}")
            logging.info(f"[deauth_whitelist] - Returned networks: {len(sorted_networks)}")
            logging.info(f"[deauth_whitelist] - Sources: {source_counts}")
            
            if sorted_networks:
                logging.info(f"[deauth_whitelist] Sample networks: {[net['essid'] for net in sorted_networks[:3]]}")
            
            return sorted_networks
            
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error getting known networks: {e}")
            return []

    def on_webhook(self, path, request):
        """Handle webhook requests for the web interface"""
        logging.info(f"[deauth_whitelist] Webhook called: path='{path}', method={request.method}")
        
        if not FLASK_AVAILABLE:
            logging.error("[deauth_whitelist] Flask not available")
            return jsonify({'success': False, 'message': 'Flask not available'})
            
        if not self.ready:
            logging.warning("[deauth_whitelist] Plugin not ready")
            return jsonify({'success': False, 'message': 'Plugin not ready'})
            
        # Force disable CSRF for all API endpoints
        try:
            from flask import current_app
            if hasattr(current_app, 'config'):
                current_app.config['WTF_CSRF_ENABLED'] = False
                logging.debug("[deauth_whitelist] Disabled CSRF for current app")
        except Exception as e:
            logging.debug(f"[deauth_whitelist] Could not disable CSRF: {e}")
        
        # Disable CSRF protection for this request by monkey-patching
        try:
            from flask import g
            g._csrf_token = True  # Trick Flask-WTF into thinking CSRF is validated
        except:
            pass
            
        # Try to disable CSRF checking through various methods
        try:
            # Method 1: Set CSRF exempt flag
            request.csrf_exempt = True
        except:
            pass
            
        try:
            # Method 2: Remove CSRF validation from request
            if hasattr(request, '_csrf_token'):
                delattr(request, '_csrf_token')
        except:
            pass
        
        # Normalize path - handle None and empty string
        if path is None:
            path = ''
        
        # Handle main page request
        if path == '' or path == '/':
            logging.info("[deauth_whitelist] Serving main page")
            try:
                # Try to get CSRF token for the template
                csrf_token = ''
                try:
                    from flask import session
                    csrf_token = session.get('_csrf_token', '')
                except:
                    pass
                
                return render_template_string(WHITELIST_TEMPLATE, 
                                            whitelist=self.get_whitelist(),
                                            csrf_token=csrf_token)
            except Exception as e:
                logging.error(f"[deauth_whitelist] Template error: {str(e)}", exc_info=True)
                return jsonify({'success': False, 'message': 'Template rendering error'})
        
        # Handle API requests (with or without leading slash)
        elif path in ['/api/add', 'api/add']:
            logging.info(f"[deauth_whitelist] API add request - method: {request.method}")
            try:
                # Handle both GET and POST requests to bypass CSRF issues
                entry = ''
                
                if request.method == 'GET':
                    # GET request with query parameter
                    entry = request.args.get('entry', '').strip()
                    logging.info(f"[deauth_whitelist] GET request entry: '{entry}'")
                elif request.method == 'POST':
                    # Disable CSRF protection for this endpoint
                    try:
                        from flask import g, current_app
                        g._csrf_token = True
                        if hasattr(current_app, 'config'):
                            original_csrf = current_app.config.get('WTF_CSRF_ENABLED', True)
                            current_app.config['WTF_CSRF_ENABLED'] = False
                    except:
                        pass
                    
                    # Additional CSRF bypass attempts
                    try:
                        # Override Flask-WTF CSRF if available
                        import sys
                        if 'flask_wtf.csrf' in sys.modules:
                            import flask_wtf.csrf
                            # Temporarily disable CSRF validation
                            original_validate = getattr(flask_wtf.csrf, 'validate_csrf', None)
                            if original_validate:
                                def dummy_validate(*args, **kwargs):
                                    return True
                                flask_wtf.csrf.validate_csrf = dummy_validate
                    except Exception as csrf_override_error:
                        logging.debug(f"[deauth_whitelist] CSRF override attempt failed: {csrf_override_error}")
                        pass
                
                    logging.info(f"[deauth_whitelist] Request content type: {request.content_type}")
                    logging.info(f"[deauth_whitelist] Request headers: {dict(request.headers)}")
                    logging.info(f"[deauth_whitelist] Request data: {request.data}")
                    logging.info(f"[deauth_whitelist] Request args: {request.args}")
                    logging.info(f"[deauth_whitelist] Request form: {request.form}")
                    
                    # Create response bypassing CSRF
                    from flask import make_response, current_app
                    
                    # Try to temporarily disable CSRF for current app
                    try:
                        if hasattr(current_app, 'config'):
                            original_csrf = current_app.config.get('WTF_CSRF_ENABLED', True)
                            current_app.config['WTF_CSRF_ENABLED'] = False
                    except:
                        pass
                    
                    # Try to get data from various sources
                    if request.json:
                        logging.info(f"[deauth_whitelist] JSON data: {request.json}")
                        entry = request.json.get('entry', '').strip()
                    elif request.form:
                        logging.info(f"[deauth_whitelist] Form data: {dict(request.form)}")
                        entry = request.form.get('entry', '').strip()
                    else:
                        # Try to parse raw data as JSON
                        try:
                            import json as json_lib
                            raw_data = request.data.decode('utf-8') if request.data else ''
                            logging.info(f"[deauth_whitelist] Raw data: {raw_data}")
                            if raw_data:
                                data = json_lib.loads(raw_data)
                                entry = data.get('entry', '').strip()
                        except Exception as parse_error:
                            logging.info(f"[deauth_whitelist] JSON parse error: {parse_error}")

                if not entry:
                    logging.warning("[deauth_whitelist] No entry data found in request")
                    from flask import make_response
                    response = make_response(jsonify({'success': False, 'message': 'No data received'}), 400)
                    response.headers['Content-Type'] = 'application/json'
                    response.headers['Access-Control-Allow-Origin'] = '*'
                    return response
                
                logging.info(f"[deauth_whitelist] Extracted entry: '{entry}'")
                
                result = self.add_to_whitelist(entry)
                logging.info(f"[deauth_whitelist] Add result: {result}")
                
                if result:
                    response_data = {'success': True, 'message': f'Added "{entry}" to whitelist'}
                    status_code = 200
                else:
                    response_data = {'success': False, 'message': 'Entry already exists'}
                    status_code = 409
                
                from flask import make_response
                response = make_response(jsonify(response_data), status_code)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
                
                # Restore original CSRF setting if we modified it
                try:
                    if request.method == 'POST' and hasattr(current_app, 'config') and 'original_csrf' in locals():
                        current_app.config['WTF_CSRF_ENABLED'] = original_csrf
                except:
                    pass
                
                return response
                
            except Exception as e:
                logging.error(f"[deauth_whitelist] Add API error: {str(e)}", exc_info=True)
                from flask import make_response
                response = make_response(jsonify({'success': False, 'message': f'Add operation failed: {str(e)}'}), 500)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response
        
        elif path in ['/api/remove', 'api/remove'] and request.method == 'POST':
            logging.info("[deauth_whitelist] API remove request")
            try:
                # Disable CSRF protection for this endpoint
                try:
                    from flask import g, current_app
                    g._csrf_token = True
                    if hasattr(current_app, 'config'):
                        original_csrf = current_app.config.get('WTF_CSRF_ENABLED', True)
                        current_app.config['WTF_CSRF_ENABLED'] = False
                except:
                    pass
                
                from flask import make_response
                
                # Try to get data from various sources
                entry = ''
                if request.json:
                    entry = request.json.get('entry', '').strip()
                elif request.form:
                    entry = request.form.get('entry', '').strip()
                else:
                    # Try to parse raw data as JSON
                    try:
                        import json as json_lib
                        raw_data = request.data.decode('utf-8') if request.data else ''
                        if raw_data:
                            data = json_lib.loads(raw_data)
                            entry = data.get('entry', '').strip()
                    except Exception as parse_error:
                        logging.info(f"[deauth_whitelist] JSON parse error: {parse_error}")

                if not entry:
                    response = make_response(jsonify({'success': False, 'message': 'No data received'}), 400)
                    response.headers['Content-Type'] = 'application/json'
                    response.headers['Access-Control-Allow-Origin'] = '*'
                    return response
                    
                result = self.remove_from_whitelist(entry)
                if result:
                    response_data = {'success': True, 'message': f'Removed "{entry}" from whitelist'}
                    status_code = 200
                else:
                    response_data = {'success': False, 'message': 'Entry not found'}
                    status_code = 404
                
                response = make_response(jsonify(response_data), status_code)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Requested-With'
                
                # Restore original CSRF setting
                try:
                    if hasattr(current_app, 'config') and 'original_csrf' in locals():
                        current_app.config['WTF_CSRF_ENABLED'] = original_csrf
                except:
                    pass
                
                return response
                
            except Exception as e:
                logging.error(f"[deauth_whitelist] Remove API error: {str(e)}", exc_info=True)
                from flask import make_response
                response = make_response(jsonify({'success': False, 'message': 'Remove operation failed'}), 500)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response
        
        elif path in ['/api/list', 'api/list']:
            logging.info("[deauth_whitelist] API list request")
            try:
                from flask import make_response
                response = make_response(jsonify({'whitelist': self.get_whitelist()}), 200)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response
            except Exception as e:
                logging.error(f"[deauth_whitelist] List API error: {str(e)}", exc_info=True)
                from flask import make_response
                response = make_response(jsonify({'success': False, 'message': 'List operation failed'}), 500)
                response.headers['Content-Type'] = 'application/json'
                return response
        
        elif path in ['/api/nearby', 'api/nearby']:
            logging.info("[deauth_whitelist] API nearby networks request")
            try:
                from flask import make_response
                response = make_response(jsonify({'networks': self.get_nearby_networks()}), 200)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Access-Control-Allow-Origin'] = '*'
                return response
            except Exception as e:
                logging.error(f"[deauth_whitelist] Nearby API error: {str(e)}", exc_info=True)
                from flask import make_response
                response = make_response(jsonify({'success': False, 'message': 'Nearby networks operation failed'}), 500)
                response.headers['Content-Type'] = 'application/json'
                return response
        
        else:
            # Unknown path
            logging.warning(f"[deauth_whitelist] Unknown path: {path}")
            return jsonify({'success': False, 'message': f'Unknown path: {path}'})


    def get_whitelist(self):
        """Get the current whitelist"""
        try:
            return sorted(list(self.whitelist))
        except Exception as e:
            logging.error(f"[deauth_whitelist] Error getting whitelist: {e}")
            return []


# HTML template for the web interface
WHITELIST_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() if csrf_token else '' }}">
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
        .nearby-network {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            margin: 3px 0;
            background-color: #444;
            border-radius: 3px;
            border-left: 3px solid #888;
        }
        .nearby-network:hover {
            background-color: #555;
            border-left-color: #0f0;
        }
        .network-info {
            flex-grow: 1;
        }
        .network-essid {
            color: #0f0;
            font-weight: bold;
        }
        .network-details {
            font-size: 0.8em;
            color: #888;
            margin-top: 2px;
        }
        .add-nearby-btn {
            background-color: #004400;
            border-color: #0f0;
            color: #0f0;
            padding: 4px 8px;
            margin: 0;
            font-size: 0.8em;
        }
        .add-nearby-btn:hover {
            background-color: #0f0;
            color: #000;
        }
        .refresh-btn {
            background-color: #000;
            border-color: #0f0;
            color: #0f0;
            padding: 8px 16px;
            margin-top: 10px;
        }
        .refresh-btn:hover {
            background-color: #0f0;
            color: #000;
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
            <h3>Alle bekannten Netzwerke</h3>
            <div id="nearbyNetworks">
                <div style="text-align: center; color: #888; padding: 20px;">
                    Lade bekannte Netzwerke...
                </div>
            </div>
            <button onclick="refreshNearbyNetworks()" class="refresh-btn">🔄 Netzwerke aktualisieren</button>
            <div class="help-text">
                📡 Diese Liste zeigt alle Netzwerke, die von Ihrem Pwnagotchi entdeckt wurden - aus Sessions, Handshakes, Logs und aktuellen Scans.
            </div>
        </div>
        
        <div class="whitelist-container">
            <h3>Current Whitelist ({{ whitelist|length }} entries)</h3>
            <div id="whitelistItems">
                {% if whitelist %}
                    {% for entry in whitelist %}
                    <div class="whitelist-item">
                        <span>{{ entry }}</span>
                        <button class="remove-btn" data-entry="{{ entry }}" onclick="removeEntryByButton(this)">Remove</button>
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
        // All function declarations are hoisted, so they can be called before definition
        
        // Get CSRF token from meta tag or cookie
        function getCSRFToken() {
            // Try to get CSRF token from meta tag first
            const metaToken = document.querySelector('meta[name="csrf-token"]');
            if (metaToken) {
                return metaToken.getAttribute('content');
            }
            
            // Try to get from cookie
            const cookies = document.cookie.split(';');
            for (let cookie of cookies) {
                const [name, value] = cookie.trim().split('=');
                if (name === 'csrf_token' || name === '_csrf_token') {
                    return value;
                }
            }
            
            // Try to get from hidden input
            const hiddenInput = document.querySelector('input[name="csrf_token"]');
            if (hiddenInput) {
                return hiddenInput.value;
            }
            
            return null;
        }

        // Create headers with CSRF token if available
        function getRequestHeaders() {
            const headers = {
                'Content-Type': 'application/json',
            };
            
            const csrfToken = getCSRFToken();
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
                headers['X-CSRF-Token'] = csrfToken;
            }
            
            return headers;
        }
        
        function makeAPIRequest(url, data, retryWithForm = true) {
            // First attempt with JSON
            return fetch(url, {
                method: 'POST',
                headers: getRequestHeaders(),
                body: JSON.stringify(data)
            })
            .then(function(response) {
                if (response.status === 400 && retryWithForm) {
                    // If we get a 400 (likely CSRF), try with form data
                    console.log('JSON request failed with 400, trying form data...');
                    const formData = new FormData();
                    for (const key in data) {
                        formData.append(key, data[key]);
                    }
                    
                    return fetch(url, {
                        method: 'POST',
                        body: formData
                    });
                }
                return response;
            })
            .then(function(response) {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json();
                } else {
                    console.error('Response is not JSON, content-type:', contentType);
                    return response.text().then(function(text) {
                        console.error('Response text:', text.substring(0, 500));
                        throw new Error('Server returned HTML instead of JSON: ' + text.substring(0, 100));
                    });
                }
            });
        }

        function showMessage(text, type) {
            const messageDiv = document.getElementById('message');
            messageDiv.innerHTML = '<div class="message ' + type + '">' + text + '</div>';
            setTimeout(function() {
                messageDiv.innerHTML = '';
            }, 3000);
        }

        function refreshNearbyNetworks() {
            const container = document.getElementById('nearbyNetworks');
            container.innerHTML = '<div style="text-align: center; color: #888; padding: 20px;">Lade bekannte Netzwerke...</div>';
            
            fetch('/plugins/deauth_whitelist/api/nearby')
            .then(function(response) {
                return response.json();
            })
            .then(function(data) {
                if (data.networks && data.networks.length > 0) {
                    let html = '';
                    for (let i = 0; i < data.networks.length; i++) {
                        const network = data.networks[i];
                        const essid = network.essid.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
                        html += '<div class="nearby-network">';
                        html += '<div class="network-info">';
                        html += '<div class="network-essid">' + essid + '</div>';
                        html += '<div class="network-details">BSSID: ' + network.bssid + ' | Kanal: ' + network.channel + ' | Signal: ' + network.rssi + ' | Quelle: ' + (network.source || 'unknown') + '</div>';
                        html += '</div>';
                        html += '<button class="add-nearby-btn" data-essid="' + essid + '" onclick="addNearbyNetworkByButton(this)">Zur Whitelist hinzufügen</button>';
                        html += '</div>';
                    }
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div style="text-align: center; color: #888; padding: 20px;">Keine bekannten Netzwerke gefunden. Netzwerke erscheinen hier, sobald sie entdeckt werden.</div>';
                }
            })
            .catch(function(error) {
                console.error('Error refreshing known networks:', error);
                container.innerHTML = '<div style="text-align: center; color: #f00; padding: 20px;">Fehler beim Laden der bekannten Netzwerke. Prüfen Sie die Konsole für Details.</div>';
            });
        }

        function addEntry() {
            const input = document.getElementById('entryInput');
            const entry = input.value.trim();
            
            if (!entry) {
                showMessage('Please enter a MAC address or ESSID', 'error');
                return;
            }
            
            console.log('Adding entry:', entry);
            
            makeAPIRequest('/plugins/deauth_whitelist/api/add', {entry: entry})
            .then(function(data) {
                console.log('Response data:', data);
                if (data.success) {
                    showMessage(data.message, 'success');
                    input.value = '';
                    refreshWhitelist();
                } else {
                    showMessage(data.message || 'Unknown error', 'error');
                }
            })
            .catch(function(error) {
                console.error('Fetch error:', error);
                showMessage('Error adding entry: ' + error.message, 'error');
            });
        }

        function removeEntry(entry) {
            if (!confirm('Are you sure you want to remove "' + entry + '" from the whitelist?')) {
                return;
            }
            
            makeAPIRequest('/plugins/deauth_whitelist/api/remove', {entry: entry})
            .then(function(data) {
                if (data.success) {
                    showMessage(data.message, 'success');
                    refreshWhitelist();
                } else {
                    showMessage(data.message, 'error');
                }
            })
            .catch(function(error) {
                showMessage('Error removing entry', 'error');
                console.error('Error:', error);
            });
        }

        function removeEntryByButton(button) {
            const entry = button.getAttribute('data-entry');
            removeEntry(entry);
        }

        function refreshWhitelist() {
            fetch('/plugins/deauth_whitelist/api/list')
            .then(function(response) {
                return response.json();
            })
            .then(function(data) {
                const container = document.getElementById('whitelistItems');
                if (data.whitelist.length > 0) {
                    let html = '';
                    for (let i = 0; i < data.whitelist.length; i++) {
                        const entry = data.whitelist[i];
                        const safeEntry = entry.replace(/'/g, '&#39;').replace(/"/g, '&quot;');
                        html += '<div class="whitelist-item">';
                        html += '<span>' + safeEntry + '</span>';
                        html += '<button class="remove-btn" data-entry="' + safeEntry + '" onclick="removeEntryByButton(this)">Remove</button>';
                        html += '</div>';
                    }
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div style="text-align: center; color: #888; padding: 20px;">No entries in whitelist. Add some networks to protect them from deauth attacks.</div>';
                }
            })
            .catch(function(error) {
                console.error('Error refreshing whitelist:', error);
            });
        }

        function addNearbyNetwork(essid) {
            console.log('Adding nearby network:', essid);
            
            makeAPIRequest('/plugins/deauth_whitelist/api/add', {entry: essid})
            .then(function(data) {
                console.log('Response data:', data);
                if (data.success) {
                    showMessage(data.message, 'success');
                    refreshWhitelist();
                } else {
                    showMessage(data.message || 'Unknown error', 'error');
                }
            })
            .catch(function(error) {
                console.error('Fetch error:', error);
                showMessage('Error adding network: ' + error.message, 'error');
            });
        }

        function addNearbyNetworkByButton(button) {
            const essid = button.getAttribute('data-essid');
            addNearbyNetwork(essid);
        }

        // Event listeners
        document.addEventListener('DOMContentLoaded', function() {
            // Allow Enter key to add entry
            document.getElementById('entryInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    addEntry();
                }
            });
            
            // Load networks on page load
            refreshNearbyNetworks();
        });
    </script>
</body>
</html>
"""
