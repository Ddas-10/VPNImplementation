"""
Fixed VPN Server with Working SOCKS5 Proxy
Requirements: pip install cryptography
"""

import socket
import threading
import json
import time
import hashlib
import secrets
import os
import base64
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct
import select

# Configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
PROXY_PORT = 10000  # SOCKS5 proxy port for IP hiding
BUFFER_SIZE = 4096
STORAGE_DIR = "vpn_storage"
SHARED_DIR = os.path.join(STORAGE_DIR, "shared")

# User database
USERS = {
    'client1': hashlib.sha256('password123'.encode()).hexdigest(),
    'client2': hashlib.sha256('password456'.encode()).hexdigest()
}

# Create storage directories
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(SHARED_DIR, exist_ok=True)

class VPNServer:
    def __init__(self):
        self.clients = {}
        self.server_socket = None
        self.proxy_socket = None
        self.running = False
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'packets_encrypted': 0,
            'packets_decrypted': 0,
            'files_uploaded': 0,
            'files_downloaded': 0,
            'total_file_bytes': 0,
            'messages_sent': 0,
            'broadcasts_sent': 0,
            'proxy_connections': 0,
            'proxy_bytes_relayed': 0
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
        self.stats['packets_encrypted'] += 1
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
            self.stats['packets_decrypted'] += 1
            return plaintext
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}")
            return None
    
    def authenticate_user(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return USERS.get(username) == password_hash
    
    def get_online_users(self):
        return [info['username'] for info in self.clients.values()]
    
    def send_to_client(self, session_id, message_data):
        try:
            client_info = self.clients.get(session_id)
            if not client_info:
                return False
            
            response_data = json.dumps(message_data).encode()
            encrypted_response = self.encrypt_data(response_data, client_info['key'])
            
            client_info['socket'].send(struct.pack('!I', len(encrypted_response)))
            client_info['socket'].send(encrypted_response)
            
            client_info['bytes_sent'] += len(encrypted_response)
            self.stats['total_bytes_sent'] += len(encrypted_response)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send to client: {e}")
            return False
    
    def broadcast_message(self, from_username, message, exclude_session=None):
        broadcast_data = {
            'type': 'broadcast',
            'from': from_username,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        count = 0
        for session_id, client_info in self.clients.items():
            if session_id != exclude_session:
                if self.send_to_client(session_id, broadcast_data):
                    count += 1
        
        self.stats['broadcasts_sent'] += 1
        return count
    
    def send_private_message(self, from_username, to_username, message):
        target_session = None
        for session_id, client_info in self.clients.items():
            if client_info['username'] == to_username:
                target_session = session_id
                break
        
        if not target_session:
            return False, f"User '{to_username}' is not online"
        
        message_data = {
            'type': 'private_message',
            'from': from_username,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        if self.send_to_client(target_session, message_data):
            self.stats['messages_sent'] += 1
            print(f"[MESSAGE] {from_username} → {to_username}: {message[:50]}...")
            return True, "Message sent"
        
        return False, "Failed to send message"
    
    def handle_file_operation(self, packet_info, session_id):
        client_info = self.clients[session_id]
        username = client_info['username']
        
        file_data = packet_info.get('data', {})
        operation = file_data.get('operation')
        is_shared = file_data.get('shared', False)
        
        try:
            if operation == 'upload':
                filename = file_data.get('filename')
                file_data_b64 = file_data.get('file_data')
                file_content = base64.b64decode(file_data_b64)
                
                if is_shared:
                    file_path = os.path.join(SHARED_DIR, filename)
                    location = "shared folder"
                else:
                    user_dir = os.path.join(STORAGE_DIR, username)
                    os.makedirs(user_dir, exist_ok=True)
                    file_path = os.path.join(user_dir, filename)
                    location = "private folder"
                
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                
                self.stats['files_uploaded'] += 1
                self.stats['total_file_bytes'] += len(file_content)
                
                print(f"[FILE] {username} uploaded '{filename}' to {location} ({len(file_content)/1024:.2f} KB)")
                
                return {
                    'status': 'success',
                    'operation': 'upload',
                    'message': f'File "{filename}" uploaded to {location}',
                    'size': len(file_content)
                }
                
            elif operation == 'download':
                filename = file_data.get('filename')
                
                if is_shared:
                    file_path = os.path.join(SHARED_DIR, filename)
                else:
                    user_dir = os.path.join(STORAGE_DIR, username)
                    file_path = os.path.join(user_dir, filename)
                
                if not os.path.exists(file_path):
                    return {
                        'status': 'error',
                        'operation': 'download',
                        'message': f'File "{filename}" not found'
                    }
                
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                file_data_b64 = base64.b64encode(file_content).decode('utf-8')
                self.stats['files_downloaded'] += 1
                self.stats['total_file_bytes'] += len(file_content)
                
                print(f"[FILE] {username} downloaded '{filename}' ({len(file_content)/1024:.2f} KB)")
                
                return {
                    'status': 'success',
                    'operation': 'download',
                    'filename': filename,
                    'file_data': file_data_b64,
                    'file_size': len(file_content)
                }
                
            elif operation == 'list':
                files_list = []
                
                if is_shared:
                    if os.path.exists(SHARED_DIR):
                        for item in os.listdir(SHARED_DIR):
                            item_path = os.path.join(SHARED_DIR, item)
                            if os.path.isfile(item_path):
                                size = os.path.getsize(item_path)
                                modified = datetime.fromtimestamp(os.path.getmtime(item_path))
                                files_list.append({
                                    'name': item,
                                    'size': size,
                                    'modified': modified.isoformat(),
                                    'type': 'file'
                                })
                else:
                    user_dir = os.path.join(STORAGE_DIR, username)
                    if os.path.exists(user_dir):
                        for item in os.listdir(user_dir):
                            item_path = os.path.join(user_dir, item)
                            if os.path.isfile(item_path):
                                size = os.path.getsize(item_path)
                                modified = datetime.fromtimestamp(os.path.getmtime(item_path))
                                files_list.append({
                                    'name': item,
                                    'size': size,
                                    'modified': modified.isoformat(),
                                    'type': 'file'
                                })
                
                location = "shared" if is_shared else "private"
                print(f"[FILE] {username} listed {location} files ({len(files_list)} items)")
                
                return {
                    'status': 'success',
                    'operation': 'list',
                    'files': files_list,
                    'location': location
                }
                
            elif operation == 'delete':
                filename = file_data.get('filename')
                
                if is_shared:
                    file_path = os.path.join(SHARED_DIR, filename)
                else:
                    user_dir = os.path.join(STORAGE_DIR, username)
                    file_path = os.path.join(user_dir, filename)
                
                if not os.path.exists(file_path):
                    return {
                        'status': 'error',
                        'operation': 'delete',
                        'message': f'File "{filename}" not found'
                    }
                
                os.remove(file_path)
                print(f"[FILE] {username} deleted '{filename}'")
                
                return {
                    'status': 'success',
                    'operation': 'delete',
                    'message': f'File "{filename}" deleted successfully'
                }
            
            else:
                return {
                    'status': 'error',
                    'message': f'Unknown operation: {operation}'
                }
                
        except Exception as e:
            print(f"[ERROR] File operation failed: {e}")
            return {
                'status': 'error',
                'operation': operation,
                'message': str(e)
            }
    
    # ========== FIXED SOCKS5 PROXY ==========
    
    def start_proxy_server(self):
        """Start SOCKS5 proxy server"""
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind((SERVER_HOST, PROXY_PORT))
            self.proxy_socket.listen(10)
            
            print(f"[PROXY] SOCKS5 Proxy started on port {PROXY_PORT}")
            print(f"[PROXY] Configure clients: SOCKS5 proxy at <server_ip>:{PROXY_PORT}")
            print(f"[PROXY] This HIDES client IP addresses!\n")
            
            while self.running:
                try:
                    self.proxy_socket.settimeout(1)
                    try:
                        client_sock, addr = self.proxy_socket.accept()
                        print(f"[PROXY] New connection from {addr[0]}:{addr[1]}")
                        threading.Thread(
                            target=self.handle_proxy_client,
                            args=(client_sock, addr),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                except Exception as e:
                    if self.running:
                        print(f"[PROXY ERROR] {e}")
        except Exception as e:
            print(f"[PROXY STARTUP ERROR] {e}")
    
    def handle_proxy_client(self, client_socket, client_addr):
        """Handle SOCKS5 proxy - IMPROVED VERSION"""
        remote_socket = None
        try:
            client_socket.settimeout(30)
            
            # SOCKS5 handshake
            version, nmethods = struct.unpack('!BB', client_socket.recv(2))
            if version != 5:
                print(f"[PROXY] Invalid SOCKS version from {client_addr[0]}")
                client_socket.close()
                return
            
            methods = client_socket.recv(nmethods)
            client_socket.send(b'\x05\x00')  # No auth
            
            # Connection request
            version, cmd, _, atyp = struct.unpack('!BBBB', client_socket.recv(4))
            
            if cmd != 1:
                print(f"[PROXY] Unsupported command {cmd} from {client_addr[0]}")
                client_socket.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # Parse destination
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 3:  # Domain
                addr_len = struct.unpack('!B', client_socket.recv(1))[0]
                addr = client_socket.recv(addr_len).decode()
            else:
                print(f"[PROXY] Unsupported address type {atyp}")
                client_socket.send(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            port = struct.unpack('!H', client_socket.recv(2))[0]
            
            print(f"[PROXY] {client_addr[0]} → {addr}:{port}")
            
            # Resolve domain if needed
            try:
                if atyp == 3:
                    resolved_ip = socket.gethostbyname(addr)
                    print(f"[PROXY] Resolved {addr} → {resolved_ip}")
                    addr = resolved_ip
            except socket.gaierror as e:
                print(f"[PROXY] DNS failed for {addr}: {e}")
                client_socket.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # Connect to destination
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(15)
                remote_socket.connect((addr, port))
                remote_socket.settimeout(None)
                
                # Success response
                reply = b'\x05\x00\x00\x01'
                reply += socket.inet_aton('0.0.0.0')
                reply += struct.pack('!H', 0)
                client_socket.send(reply)
                
                print(f"[PROXY] ✓ {client_addr[0]}'s IP HIDDEN - connected to {addr}:{port}")
                self.stats['proxy_connections'] += 1
                
                # Relay traffic
                self.relay_traffic_improved(client_socket, remote_socket, client_addr[0])
                
            except socket.timeout:
                print(f"[PROXY] ✗ Timeout connecting to {addr}:{port}")
                client_socket.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
            except ConnectionRefusedError:
                print(f"[PROXY] ✗ Connection refused: {addr}:{port}")
                client_socket.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
            except Exception as e:
                print(f"[PROXY] ✗ Failed to connect: {type(e).__name__}: {e}")
                client_socket.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                
        except Exception as e:
            print(f"[PROXY ERROR] {type(e).__name__}: {e}")
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
    
    def relay_traffic_improved(self, client_sock, remote_sock, client_ip):
        """Improved bidirectional relay"""
        bytes_sent = 0
        bytes_received = 0
        
        try:
            client_sock.setblocking(False)
            remote_sock.setblocking(False)
            
            while self.running:
                try:
                    readable, _, exceptional = select.select(
                        [client_sock, remote_sock],
                        [],
                        [client_sock, remote_sock],
                        30
                    )
                    
                    if exceptional:
                        break
                    
                    # Client → Remote
                    if client_sock in readable:
                        try:
                            data = client_sock.recv(16384)
                            if not data:
                                break
                            
                            total_sent = 0
                            while total_sent < len(data):
                                try:
                                    sent = remote_sock.send(data[total_sent:])
                                    if sent == 0:
                                        return
                                    total_sent += sent
                                except BlockingIOError:
                                    select.select([], [remote_sock], [], 1)
                                    continue
                            
                            bytes_sent += len(data)
                            self.stats['proxy_bytes_relayed'] += len(data)
                            
                        except BlockingIOError:
                            pass
                        except Exception as e:
                            break
                    
                    # Remote → Client
                    if remote_sock in readable:
                        try:
                            data = remote_sock.recv(16384)
                            if not data:
                                break
                            
                            total_sent = 0
                            while total_sent < len(data):
                                try:
                                    sent = client_sock.send(data[total_sent:])
                                    if sent == 0:
                                        return
                                    total_sent += sent
                                except BlockingIOError:
                                    select.select([], [client_sock], [], 1)
                                    continue
                            
                            bytes_received += len(data)
                            self.stats['proxy_bytes_relayed'] += len(data)
                            
                        except BlockingIOError:
                            pass
                        except Exception as e:
                            break
                            
                except select.error:
                    break
                    
        except Exception as e:
            pass
        finally:
            print(f"[PROXY] Session ended for {client_ip} - Sent: {bytes_sent}B, Recv: {bytes_received}B")
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                client_sock.close()
            except:
                pass
            try:
                remote_sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                remote_sock.close()
            except:
                pass
    
    # ========== VPN SERVER METHODS ==========
    
    def handle_client(self, client_socket, client_address):
        session_id = secrets.token_hex(16)
        session_key = None
        username = None
        
        try:
            # Authentication
            auth_data = client_socket.recv(BUFFER_SIZE).decode()
            auth_request = json.loads(auth_data)
            
            username = auth_request.get('username')
            password = auth_request.get('password')
            
            print(f"[AUTH] Authentication attempt from {client_address} - User: {username}")
            
            if self.authenticate_user(username, password):
                salt = secrets.token_bytes(16)
                session_key = self.derive_key(password, salt)
                
                response = {
                    'status': 'success',
                    'session_id': session_id,
                    'salt': salt.hex(),
                    'message': 'Authentication successful',
                    'proxy_port': PROXY_PORT
                }
                client_socket.send(json.dumps(response).encode())
                
                print(f"[SUCCESS] Client {username} authenticated - Session: {session_id[:8]}...")
                
                self.clients[session_id] = {
                    'socket': client_socket,
                    'username': username,
                    'ip': client_address[0],
                    'connected_time': datetime.now(),
                    'key': session_key,
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
                self.stats['total_connections'] += 1
                self.stats['active_connections'] += 1
                
                self.broadcast_message('SERVER', f'{username} has joined the VPN', exclude_session=session_id)
                
                self.handle_encrypted_traffic(session_id)
                
            else:
                response = {'status': 'failed', 'message': 'Invalid credentials'}
                client_socket.send(json.dumps(response).encode())
                print(f"[FAILED] Authentication failed for {username}")
                client_socket.close()
                
        except Exception as e:
            print(f"[ERROR] Client handler error: {e}")
        finally:
            if session_id in self.clients:
                leaving_user = self.clients[session_id]['username']
                del self.clients[session_id]
                self.stats['active_connections'] -= 1
                self.broadcast_message('SERVER', f'{leaving_user} has left the VPN')
            print(f"[DISCONNECT] Client {username or 'Unknown'} disconnected")
    
    def handle_encrypted_traffic(self, session_id):
        client_info = self.clients[session_id]
        client_socket = client_info['socket']
        session_key = client_info['key']
        
        try:
            while self.running:
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                
                data_length = struct.unpack('!I', length_data)[0]
                
                encrypted_data = b''
                while len(encrypted_data) < data_length:
                    chunk = client_socket.recv(min(BUFFER_SIZE, data_length - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if not encrypted_data:
                    break
                
                decrypted_data = self.decrypt_data(encrypted_data, session_key)
                if decrypted_data:
                    packet_info = json.loads(decrypted_data.decode())
                    
                    client_info['bytes_received'] += len(encrypted_data)
                    self.stats['total_bytes_received'] += len(encrypted_data)
                    
                    packet_type = packet_info['type']
                    
                    if packet_type == 'file_operation':
                        response = self.handle_file_operation(packet_info, session_id)
                        
                    elif packet_type == 'get_users':
                        online_users = self.get_online_users()
                        response = {
                            'type': 'users_list',
                            'users': online_users,
                            'count': len(online_users)
                        }
                        print(f"[INFO] {client_info['username']} requested user list")
                        
                    elif packet_type == 'broadcast':
                        message = packet_info.get('data', '')
                        count = self.broadcast_message(client_info['username'], message, exclude_session=session_id)
                        response = {
                            'type': 'broadcast_response',
                            'status': 'success',
                            'message': f'Broadcast sent to {count} client(s)'
                        }
                        print(f"[BROADCAST] {client_info['username']}: {message[:50]}...")
                        
                    elif packet_type == 'private_message':
                        to_user = packet_info.get('to_user')
                        message = packet_info.get('data', '')
                        success, msg = self.send_private_message(client_info['username'], to_user, message)
                        response = {
                            'type': 'message_response',
                            'status': 'success' if success else 'error',
                            'message': msg
                        }
                        
                    else:
                        print(f"[PACKET] From {client_info['username']}: {packet_type}")
                        response = {
                            'type': 'response',
                            'data': packet_info.get('data', ''),
                            'timestamp': datetime.now().isoformat(),
                            'server_message': 'Data received and processed'
                        }
                    
                    # Send response
                    response_data = json.dumps(response).encode()
                    encrypted_response = self.encrypt_data(response_data, session_key)
                    
                    client_socket.send(struct.pack('!I', len(encrypted_response)))
                    client_socket.send(encrypted_response)
                    
                    client_info['bytes_sent'] += len(encrypted_response)
                    self.stats['total_bytes_sent'] += len(encrypted_response)
                    
        except Exception as e:
            print(f"[ERROR] Traffic handling error: {e}")
    
    def display_stats(self):
        while self.running:
            time.sleep(10)
            print("\n" + "="*80)
            print(f"{'VPN SERVER STATISTICS':^80}")
            print("="*80)
            print(f"Active Connections: {self.stats['active_connections']}")
            print(f"Total Connections: {self.stats['total_connections']}")
            print(f"Data Sent: {self.stats['total_bytes_sent'] / 1024:.2f} KB")
            print(f"Data Received: {self.stats['total_bytes_received'] / 1024:.2f} KB")
            print(f"Packets Encrypted: {self.stats['packets_encrypted']}")
            print(f"Packets Decrypted: {self.stats['packets_decrypted']}")
            print(f"\nProxy Statistics:")
            print(f"Proxy Connections: {self.stats['proxy_connections']}")
            print(f"Proxy Data Relayed: {self.stats['proxy_bytes_relayed'] / 1024:.2f} KB")
            print(f"\nFile Transfer:")
            print(f"Files Uploaded: {self.stats['files_uploaded']}")
            print(f"Files Downloaded: {self.stats['files_downloaded']}")
            print(f"\nMessaging:")
            print(f"Private Messages: {self.stats['messages_sent']}")
            print(f"Broadcasts: {self.stats['broadcasts_sent']}")
            print("\nConnected Clients:")
            for sid, info in self.clients.items():
                uptime = (datetime.now() - info['connected_time']).seconds
                print(f"  - {info['username']} ({info['ip']}) - {uptime}s - "
                      f"Sent: {info['bytes_sent']/1024:.2f}KB, Recv: {info['bytes_received']/1024:.2f}KB")
            print("="*80 + "\n")
    
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(5)
        self.running = True
        
        print("="*80)
        print(f"{'VPN SERVER WITH IP HIDING':^80}")
        print("="*80)
        print(f"VPN Server: {SERVER_HOST}:{SERVER_PORT}")
        print(f"SOCKS5 Proxy: {SERVER_HOST}:{PROXY_PORT}")
        print(f"Storage: {os.path.abspath(STORAGE_DIR)}")
        print(f"Users: {', '.join(USERS.keys())}")
        print("="*80 + "\n")
        
        stats_thread = threading.Thread(target=self.display_stats, daemon=True)
        stats_thread.start()
        
        proxy_thread = threading.Thread(target=self.start_proxy_server, daemon=True)
        proxy_thread.start()
        
        print("Waiting for connections...\n")
        
        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                print(f"[NEW CONNECTION] From {client_address}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server shutting down...")
        finally:
            self.running = False
            if self.server_socket:
                self.server_socket.close()
            if self.proxy_socket:
                self.proxy_socket.close()

if __name__ == "__main__":
    print("\n🔒 Starting VPN Server with IP Hiding...")
    print("📋 Features:")
    print("   ✓ Encrypted VPN tunnel (AES-256-GCM)")
    print("   ✓ File sharing (private & shared)")
    print("   ✓ Messaging (broadcast & private)")
    print("   ✓ SOCKS5 proxy for IP hiding")
    print("\n💡 Usage:")
    print("   • VPN clients connect to port 9999")
    print("   • SOCKS5 proxy available on port 10000")
    print("   • Configure browser/apps: SOCKS5 <server_ip>:10000\n")
    
    server = VPNServer()
    server.start()