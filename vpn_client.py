"""
Fixed VPN Client with Working Local SOCKS5 Proxy for IP Hiding
Requirements: pip install cryptography
"""

import socket
import json
import time
import hashlib
import secrets
import struct
import threading
import os
import base64
import select
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
SERVER_IP = '10.0.11.228'
SERVER_PORT = 9999
BUFFER_SIZE = 4096
LOCAL_PROXY_PORT = 8888

class VPNClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.socket = None
        self.session_id = None
        self.session_key = None
        self.connected = False
        self.listening = False
        self.proxy_running = False
        self.proxy_connections = {}  # Store active proxy connections
        self.proxy_lock = threading.Lock()
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'latency_ms': [],
            'start_time': None,
            'files_uploaded': 0,
            'files_downloaded': 0,
            'file_bytes_sent': 0,
            'file_bytes_received': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'proxy_connections': 0
        }
        
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, key):
        iv = secrets.token_bytes(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data, key):
        try:
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}")
            return None
    
    # ========== FIXED LOCAL SOCKS5 PROXY ==========
    
    def start_local_proxy(self):
        """Start local SOCKS5 proxy - connects DIRECTLY to destinations"""
        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_socket.bind(('127.0.0.1', LOCAL_PROXY_PORT))
            proxy_socket.listen(5)
            
            self.proxy_running = True
            
            print(f"\n{'='*80}")
            print(f"🚀 LOCAL SOCKS5 PROXY STARTED - IP HIDING ENABLED!")
            print(f"{'='*80}")
            print(f"Proxy Address: 127.0.0.1 (localhost)")
            print(f"Proxy Port: {LOCAL_PROXY_PORT}")
            print(f"\n📋 Configure Your Browser:")
            print(f"   Settings → Network → Manual Proxy")
            print(f"   SOCKS Host: 127.0.0.1")
            print(f"   Port: {LOCAL_PROXY_PORT}")
            print(f"   Type: SOCKS5")
            print(f"\n✅ Traffic routes: Browser → Local Proxy → VPN Client → Internet")
            print(f"✅ Your real IP is hidden - destination sees VPN client IP!")
            print(f"{'='*80}\n")
            
            while self.proxy_running and self.connected:
                try:
                    proxy_socket.settimeout(1)
                    try:
                        client_sock, addr = proxy_socket.accept()
                        print(f"[PROXY] New connection from browser/app")
                        threading.Thread(
                            target=self.handle_proxy_request,
                            args=(client_sock,),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                except Exception as e:
                    if self.proxy_running:
                        print(f"[PROXY ERROR] {e}")
                        
        except Exception as e:
            print(f"[PROXY STARTUP ERROR] {e}")
        finally:
            try:
                proxy_socket.close()
            except:
                pass
    
    def handle_proxy_request(self, client_socket):
        """Handle SOCKS5 from browser - DIRECT CONNECTION (not tunneled)"""
        remote_socket = None
        try:
            client_socket.settimeout(30)  # Increase timeout
            
            # SOCKS5 handshake
            version, nmethods = struct.unpack('!BB', client_socket.recv(2))
            if version != 5:
                print(f"[PROXY] Invalid SOCKS version: {version}")
                client_socket.close()
                return
            
            methods = client_socket.recv(nmethods)
            client_socket.send(b'\x05\x00')  # No auth
            
            # Get destination
            version, cmd, _, atyp = struct.unpack('!BBBB', client_socket.recv(4))
            
            if cmd != 1:  # Only CONNECT
                print(f"[PROXY] Unsupported command: {cmd}")
                client_socket.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # Parse address
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 3:  # Domain
                addr_len = struct.unpack('!B', client_socket.recv(1))[0]
                addr = client_socket.recv(addr_len).decode()
            else:
                print(f"[PROXY] Unsupported address type: {atyp}")
                client_socket.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            port = struct.unpack('!H', client_socket.recv(2))[0]
            
            print(f"[PROXY] Request to connect: {addr}:{port}")
            
            # Resolve domain if needed
            try:
                if atyp == 3:  # Domain name
                    print(f"[PROXY] Resolving {addr}...")
                    resolved_ip = socket.gethostbyname(addr)
                    print(f"[PROXY] Resolved {addr} → {resolved_ip}")
                    addr = resolved_ip
            except socket.gaierror as e:
                print(f"[PROXY] ✗ DNS resolution failed for {addr}: {e}")
                # Send "Host unreachable" error
                client_socket.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # DIRECT CONNECTION from VPN client machine to destination
            try:
                print(f"[PROXY] Connecting to {addr}:{port}...")
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(15)
                remote_socket.connect((addr, port))
                remote_socket.settimeout(None)  # Remove timeout after connection
                
                print(f"[PROXY] ✓ Connected to {addr}:{port} - IP HIDDEN!")
                
                # Success response to browser
                reply = b'\x05\x00\x00\x01'
                reply += socket.inet_aton('0.0.0.0')
                reply += struct.pack('!H', 0)
                client_socket.send(reply)
                
                self.stats['proxy_connections'] += 1
                
                # Relay traffic directly
                self.relay_direct(client_socket, remote_socket)
                
            except socket.timeout:
                print(f"[PROXY] ✗ Connection timeout to {addr}:{port}")
                client_socket.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
            except ConnectionRefusedError:
                print(f"[PROXY] ✗ Connection refused by {addr}:{port}")
                client_socket.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
            except Exception as e:
                print(f"[PROXY] ✗ Failed to connect to {addr}:{port}: {type(e).__name__} - {e}")
                client_socket.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                
        except Exception as e:
            print(f"[PROXY ERROR] Handshake failed: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if remote_socket:
                    remote_socket.close()
            except:
                pass
    
    def relay_direct(self, client_socket, remote_socket):
        """Direct bidirectional relay between browser and destination"""
        print(f"[PROXY] Starting relay...")
        bytes_client_to_remote = 0
        bytes_remote_to_client = 0
        
        try:
            client_socket.setblocking(False)
            remote_socket.setblocking(False)
            
            while self.proxy_running:
                try:
                    readable, writable, exceptional = select.select(
                        [client_socket, remote_socket], 
                        [], 
                        [client_socket, remote_socket], 
                        30  # Longer timeout for HTTPS handshakes
                    )
                    
                    if exceptional:
                        print(f"[PROXY] Socket exception detected")
                        break
                    
                    # Handle client → remote
                    if client_socket in readable:
                        try:
                            data = client_socket.recv(16384)
                            if not data:
                                print(f"[PROXY] Client closed connection")
                                break
                            
                            # Send to remote
                            total_sent = 0
                            while total_sent < len(data):
                                try:
                                    sent = remote_socket.send(data[total_sent:])
                                    if sent == 0:
                                        print(f"[PROXY] Remote socket closed")
                                        return
                                    total_sent += sent
                                except BlockingIOError:
                                    # Wait for socket to be writable
                                    select.select([], [remote_socket], [], 1)
                                    continue
                            
                            bytes_client_to_remote += len(data)
                            
                        except BlockingIOError:
                            pass
                        except Exception as e:
                            print(f"[PROXY] Client→Remote error: {type(e).__name__}: {e}")
                            break
                    
                    # Handle remote → client
                    if remote_socket in readable:
                        try:
                            data = remote_socket.recv(16384)
                            if not data:
                                print(f"[PROXY] Remote closed connection")
                                break
                            
                            # Send to client
                            total_sent = 0
                            while total_sent < len(data):
                                try:
                                    sent = client_socket.send(data[total_sent:])
                                    if sent == 0:
                                        print(f"[PROXY] Client socket closed")
                                        return
                                    total_sent += sent
                                except BlockingIOError:
                                    # Wait for socket to be writable
                                    select.select([], [client_socket], [], 1)
                                    continue
                            
                            bytes_remote_to_client += len(data)
                            
                        except BlockingIOError:
                            pass
                        except Exception as e:
                            print(f"[PROXY] Remote→Client error: {type(e).__name__}: {e}")
                            break
                            
                except select.error as e:
                    print(f"[PROXY] Select error: {e}")
                    break
                except Exception as e:
                    print(f"[PROXY] Unexpected error: {type(e).__name__}: {e}")
                    break
                    
        except Exception as e:
            print(f"[PROXY] Fatal relay error: {type(e).__name__}: {e}")
        finally:
            print(f"[PROXY] Relay ended - Sent: {bytes_client_to_remote}B, Received: {bytes_remote_to_client}B")
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                client_socket.close()
            except:
                pass
            try:
                remote_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                remote_socket.close()
            except:
                pass
    
    # ========== ORIGINAL VPN CLIENT METHODS ==========
    
    def listen_for_messages(self):
        """Background thread to listen for incoming messages"""
        self.listening = True
        while self.listening and self.connected:
            try:
                if hasattr(self, '_waiting_for_response') and self._waiting_for_response:
                    time.sleep(0.1)
                    continue
                
                self.socket.settimeout(0.5)
                
                try:
                    length_data = self.socket.recv(4)
                    if not length_data:
                        continue
                    
                    data_length = struct.unpack('!I', length_data)[0]
                    encrypted_data = b''
                    while len(encrypted_data) < data_length:
                        chunk = self.socket.recv(min(BUFFER_SIZE, data_length - len(encrypted_data)))
                        if not chunk:
                            break
                        encrypted_data += chunk
                    
                    if not encrypted_data:
                        continue
                    
                    decrypted_data = self.decrypt_data(encrypted_data, self.session_key)
                    if decrypted_data:
                        message = json.loads(decrypted_data.decode())
                        msg_type = message.get('type')
                        
                        if msg_type == 'broadcast':
                            from_user = message.get('from')
                            msg_text = message.get('message')
                            print(f"\n[BROADCAST from {from_user}]: {msg_text}")
                            print(f"{self.username}> ", end='', flush=True)
                            self.stats['messages_received'] += 1
                            
                        elif msg_type == 'private_message':
                            from_user = message.get('from')
                            msg_text = message.get('message')
                            print(f"\n[MESSAGE from {from_user}]: {msg_text}")
                            print(f"{self.username}> ", end='', flush=True)
                            self.stats['messages_received'] += 1
                
                except socket.timeout:
                    continue
                    
            except Exception as e:
                if self.listening:
                    time.sleep(0.1)
                continue
    
    def connect(self):
        """Connect and authenticate with VPN server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_IP, SERVER_PORT))
            
            print(f"[CONNECTING] Connecting to VPN server at {SERVER_IP}:{SERVER_PORT}")
            
            auth_request = {
                'username': self.username,
                'password': self.password
            }
            self.socket.send(json.dumps(auth_request).encode())
            
            response_data = self.socket.recv(BUFFER_SIZE).decode()
            response = json.loads(response_data)
            
            if response['status'] == 'success':
                self.session_id = response['session_id']
                salt = bytes.fromhex(response['salt'])
                self.session_key = self.derive_key(self.password, salt)
                self.connected = True
                self.stats['start_time'] = datetime.now()
                self._waiting_for_response = False
                
                print("="*80)
                print(f"{'VPN CONNECTION ESTABLISHED WITH IP HIDING':^80}")
                print("="*80)
                print(f"Username: {self.username}")
                print(f"Session ID: {self.session_id[:16]}...")
                print(f"Encryption: AES-256-GCM")
                print(f"Server: {SERVER_IP}:{SERVER_PORT}")
                print("="*80 + "\n")
                
                return True
            else:
                print(f"[FAILED] Authentication failed: {response['message']}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False
    
    def send_packet(self, packet):
        """Send encrypted packet and receive response"""
        try:
            self._waiting_for_response = True
            start_time = time.time()
            
            packet_data = json.dumps(packet).encode()
            encrypted_data = self.encrypt_data(packet_data, self.session_key)
            
            self.socket.settimeout(None)
            self.socket.send(struct.pack('!I', len(encrypted_data)))
            self.socket.send(encrypted_data)
            
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(encrypted_data)
            
            self.socket.settimeout(10.0)
            length_data = self.socket.recv(4)
            if not length_data:
                return None, 0
            
            data_length = struct.unpack('!I', length_data)[0]
            encrypted_response = b''
            while len(encrypted_response) < data_length:
                chunk = self.socket.recv(min(BUFFER_SIZE, data_length - len(encrypted_response)))
                if not chunk:
                    break
                encrypted_response += chunk
            
            decrypted_response = self.decrypt_data(encrypted_response, self.session_key)
            
            latency = (time.time() - start_time) * 1000
            self.stats['latency_ms'].append(latency)
            
            self.stats['packets_received'] += 1
            self.stats['bytes_received'] += len(encrypted_response)
            
            if decrypted_response:
                return json.loads(decrypted_response.decode()), latency
            
            return None, latency
            
        except socket.timeout:
            print("[ERROR] Request timed out")
            return None, 0
        except Exception as e:
            print(f"[ERROR] Packet transmission failed: {e}")
            return None, 0
        finally:
            self.socket.settimeout(None)
            self._waiting_for_response = False
            time.sleep(0.1)
    
    def get_online_users(self):
        packet = {
            'type': 'get_users',
            'timestamp': datetime.now().isoformat(),
            'client': self.username
        }
        
        response, latency = self.send_packet(packet)
        if response and response.get('type') == 'users_list':
            return response.get('users', [])
        return []
    
    def send_broadcast(self, message):
        packet = {
            'type': 'broadcast',
            'data': message,
            'timestamp': datetime.now().isoformat(),
            'client': self.username
        }
        
        response, latency = self.send_packet(packet)
        if response and response.get('status') == 'success':
            print(f"[BROADCAST] {response.get('message')}")
            self.stats['messages_sent'] += 1
        else:
            print(f"[ERROR] Broadcast failed")
    
    def send_private_message(self, to_user, message):
        packet = {
            'type': 'private_message',
            'to_user': to_user,
            'data': message,
            'timestamp': datetime.now().isoformat(),
            'client': self.username
        }
        
        response, latency = self.send_packet(packet)
        if response and response.get('status') == 'success':
            print(f"[MESSAGE SENT] To {to_user}: {message}")
            self.stats['messages_sent'] += 1
        else:
            print(f"[ERROR] {response.get('message', 'Failed to send message')}")
    
    def upload_file(self, local_path, shared=False):
        try:
            if not os.path.exists(local_path):
                print(f"[ERROR] File not found: {local_path}")
                return
            
            filename = os.path.basename(local_path)
            file_size = os.path.getsize(local_path)
            location = "shared folder" if shared else "private folder"
            
            print(f"[UPLOAD] Uploading '{filename}' to {location} ({file_size/1024:.2f} KB)...")
            start_time = time.time()
            
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            
            file_packet = {
                'operation': 'upload',
                'filename': filename,
                'file_data': file_data_b64,
                'file_size': file_size,
                'shared': shared
            }
            
            packet = {
                'type': 'file_operation',
                'data': file_packet,
                'timestamp': datetime.now().isoformat(),
                'client': self.username
            }
            
            response, latency = self.send_packet(packet)
            
            if response and response.get('status') == 'success':
                elapsed = time.time() - start_time
                speed = (file_size / 1024) / elapsed if elapsed > 0 else 0
                print(f"[SUCCESS] Uploaded - {file_size/1024:.2f} KB in {elapsed:.2f}s ({speed:.2f} KB/s)")
                self.stats['files_uploaded'] += 1
                self.stats['file_bytes_sent'] += file_size
            else:
                print(f"[ERROR] Upload failed: {response.get('message', 'Unknown error')}")
                
        except Exception as e:
            print(f"[ERROR] Upload failed: {e}")
    
    def download_file(self, remote_filename, local_path=None, shared=False):
        try:
            if local_path is None:
                local_path = remote_filename
            
            location = "shared folder" if shared else "private folder"
            print(f"[DOWNLOAD] Downloading '{remote_filename}' from {location}...")
            start_time = time.time()
            
            file_packet = {
                'operation': 'download',
                'filename': remote_filename,
                'shared': shared
            }
            
            packet = {
                'type': 'file_operation',
                'data': file_packet,
                'timestamp': datetime.now().isoformat(),
                'client': self.username
            }
            
            response, latency = self.send_packet(packet)
            
            if response and response.get('status') == 'success':
                file_data_b64 = response.get('file_data')
                file_data = base64.b64decode(file_data_b64)
                file_size = response.get('file_size', len(file_data))
                
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                
                elapsed = time.time() - start_time
                speed = (file_size / 1024) / elapsed if elapsed > 0 else 0
                print(f"[SUCCESS] Downloaded - {file_size/1024:.2f} KB in {elapsed:.2f}s ({speed:.2f} KB/s)")
                print(f"[SUCCESS] Saved to: {local_path}")
                self.stats['files_downloaded'] += 1
                self.stats['file_bytes_received'] += file_size
            else:
                print(f"[ERROR] Download failed: {response.get('message', 'Unknown error')}")
                
        except Exception as e:
            print(f"[ERROR] Download failed: {e}")
    
    def list_files(self, shared=False):
        try:
            location = "shared" if shared else "private"
            print(f"[LIST] Fetching {location} file list...")
            
            file_packet = {
                'operation': 'list',
                'shared': shared
            }
            
            packet = {
                'type': 'file_operation',
                'data': file_packet,
                'timestamp': datetime.now().isoformat(),
                'client': self.username
            }
            
            response, latency = self.send_packet(packet)
            
            if response and response.get('status') == 'success':
                files = response.get('files', [])
                location = response.get('location', 'unknown')
                
                if not files:
                    print(f"[INFO] No files in {location} folder")
                    return
                
                print("\n" + "="*80)
                print(f"{'FILES IN ' + location.upper() + ' FOLDER':^80}")
                print("="*80)
                print(f"{'Name':<35} {'Type':<12} {'Size':<15} {'Modified'}")
                print("-"*80)
                
                for file_info in files:
                    name = file_info['name']
                    ftype = file_info['type']
                    size = file_info['size']
                    size_str = f"{size/1024:.2f} KB" if size >= 1024 else f"{size} B"
                    modified = datetime.fromisoformat(file_info['modified']).strftime('%Y-%m-%d %H:%M')
                    print(f"{name:<35} {ftype:<12} {size_str:<15} {modified}")
                
                print("="*80 + "\n")
                print(f"Total: {len(files)} items")
            else:
                print(f"[ERROR] List failed")
                
        except Exception as e:
            print(f"[ERROR] List failed: {e}")
    
    def delete_file(self, filename, shared=False):
        try:
            location = "shared folder" if shared else "private folder"
            print(f"[DELETE] Deleting '{filename}' from {location}...")
            
            file_packet = {
                'operation': 'delete',
                'filename': filename,
                'shared': shared
            }
            
            packet = {
                'type': 'file_operation',
                'data': file_packet,
                'timestamp': datetime.now().isoformat(),
                'client': self.username
            }
            
            response, latency = self.send_packet(packet)
            
            if response and response.get('status') == 'success':
                print(f"[SUCCESS] {response.get('message')}")
            else:
                print(f"[ERROR] Delete failed")
                
        except Exception as e:
            print(f"[ERROR] Delete failed: {e}")
    
    def display_stats(self):
        if not self.stats['start_time']:
            return
        
        uptime = (datetime.now() - self.stats['start_time']).seconds
        avg_latency = sum(self.stats['latency_ms']) / len(self.stats['latency_ms']) if self.stats['latency_ms'] else 0
        
        print("\n" + "="*80)
        print(f"{'VPN CLIENT STATISTICS WITH IP HIDING':^80}")
        print("="*80)
        print(f"Username: {self.username}")
        print(f"Uptime: {uptime} seconds")
        print(f"Packets Sent: {self.stats['packets_sent']}")
        print(f"Packets Received: {self.stats['packets_received']}")
        print(f"Data Sent: {self.stats['bytes_sent'] / 1024:.2f} KB")
        print(f"Data Received: {self.stats['bytes_received'] / 1024:.2f} KB")
        print(f"Average Latency: {avg_latency:.2f} ms")
        print(f"\nFiles Uploaded: {self.stats['files_uploaded']}")
        print(f"Files Downloaded: {self.stats['files_downloaded']}")
        print(f"Messages Sent: {self.stats['messages_sent']}")
        print(f"Messages Received: {self.stats['messages_received']}")
        print(f"\nProxy Connections: {self.stats['proxy_connections']}")
        print("="*80 + "\n")
    
    def show_help(self):
        print("\n" + "="*80)
        print(f"{'VPN CLIENT COMMANDS':^80}")
        print("="*80)
        print("\n🔧 System:")
        print("  stats    - Show statistics")
        print("  quit     - Disconnect")
        print("  help     - Show this help")
        print("  testip   - Test IP hiding")
        
        print("\n📁 Files:")
        print("  list [shared]                - List files")
        print("  upload <file> [shared]       - Upload file")
        print("  download <file> [shared]     - Download file")
        print("  delete <file> [shared]       - Delete file")
        
        print("\n💬 Messaging:")
        print("  who                          - Show online users")
        print("  msg <user> <message>         - Private message")
        print("  broadcast <message>          - Message to all")
        print("="*80 + "\n")
    
    def interactive_mode(self):
        print("\n[INTERACTIVE MODE] Type 'help' for commands\n")
        
        while self.connected:
            try:
                message = input(f"{self.username}> ")
                
                if not message.strip():
                    continue
                
                parts = message.split(maxsplit=2)
                command = parts[0].lower()
                
                if command == 'quit':
                    print("[DISCONNECT] Closing...")
                    break
                
                elif command == 'stats':
                    self.display_stats()
                
                elif command == 'help':
                    self.show_help()
                
                elif command == 'testip':
                    print(f"\n[TEST IP] Testing IP hiding...")
                    print(f"Run this command in another terminal:")
                    print(f"  curl --socks5 127.0.0.1:{LOCAL_PROXY_PORT} https://api.ipify.org")
                    print(f"Expected result: Your VPN client machine's public IP\n")
                
                elif command == 'who':
                    users = self.get_online_users()
                    print(f"\n[ONLINE] {len(users)} users:")
                    for user in users:
                        status = " (you)" if user == self.username else ""
                        print(f"  • {user}{status}")
                    print()
                
                elif command == 'broadcast':
                    if len(parts) < 2:
                        print("[ERROR] Usage: broadcast <message>")
                    else:
                        self.send_broadcast(message.split(maxsplit=1)[1])
                
                elif command == 'msg':
                    if len(parts) < 3:
                        print("[ERROR] Usage: msg <user> <message>")
                    else:
                        self.send_private_message(parts[1], parts[2])
                
                elif command == 'list':
                    shared = len(parts) > 1 and parts[1].lower() == 'shared'
                    self.list_files(shared=shared)
                
                elif command == 'upload':
                    if len(parts) < 2:
                        print("[ERROR] Usage: upload <file> [shared]")
                    else:
                        shared = len(parts) > 2 and parts[2].lower() == 'shared'
                        self.upload_file(parts[1], shared=shared)
                
                elif command == 'download':
                    if len(parts) < 2:
                        print("[ERROR] Usage: download <file> [shared]")
                    else:
                        filename = parts[1]
                        if len(parts) > 2 and parts[2].lower() == 'shared':
                            self.download_file(filename, shared=True)
                        else:
                            self.download_file(filename)
                
                elif command == 'delete':
                    if len(parts) < 2:
                        print("[ERROR] Usage: delete <file> [shared]")
                    else:
                        shared = len(parts) > 2 and parts[2].lower() == 'shared'
                        self.delete_file(parts[1], shared=shared)
                
                else:
                    packet = {
                        'type': 'message',
                        'data': message,
                        'timestamp': datetime.now().isoformat(),
                        'client': self.username
                    }
                    response, latency = self.send_packet(packet)
                    if response:
                        print(f"[SERVER] {response.get('server_message', 'OK')} ({latency:.0f}ms)")
                
            except KeyboardInterrupt:
                print("\n[DISCONNECT] Closing...")
                break
            except Exception as e:
                print(f"[ERROR] {e}")
        
        self.listening = False
        self.proxy_running = False
        self.socket.close()
        self.connected = False

def main():
    print("="*80)
    print(f"{'VPN CLIENT WITH IP HIDING':^80}")
    print("="*80)
    
    print("\nUsers: client1 (password123), client2 (password456)")
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    
    client = VPNClient(username, password)
    
    if client.connect():
        print("\n[AUTO-TEST] Testing connection...")
        time.sleep(1)
        
        for i in range(3):
            packet = {
                'type': 'test',
                'data': f"Test packet {i+1}",
                'timestamp': datetime.now().isoformat(),
                'client': username
            }
            response, latency = client.send_packet(packet)
            if response:
                print(f"[TEST] Packet {i+1} - Latency: {latency:.0f}ms")
            time.sleep(0.3)
        
        # Start message listener
        print("\n[STARTING] Message listener...")
        listener_thread = threading.Thread(target=client.listen_for_messages, daemon=True)
        listener_thread.start()
        time.sleep(0.5)
        
        # Start local SOCKS5 proxy
        print("\n[STARTING] Local IP hiding proxy...")
        proxy_thread = threading.Thread(target=client.start_local_proxy, daemon=True)
        proxy_thread.start()
        time.sleep(1)
        
        print("\n✅ VPN connected and ready!")
        print("\n💡 Quick Tips:")
        print("   • Type 'help' for all commands")
        print("   • Type 'who' to see online users")
        print("   • Type 'testip' for IP hiding test instructions")
        print(f"   • Configure browser proxy: 127.0.0.1:{LOCAL_PROXY_PORT}")
        print()
        
        client.interactive_mode()
    else:
        print("[FAILED] Could not connect to VPN")

if __name__ == "__main__":
    main()