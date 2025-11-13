"""
VPN Server - Machine 1
Requirements: pip install cryptography scapy
Run as Administrator for packet capture
"""

import socket
import threading
import json
import time
import hashlib
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import struct

# Configuration
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
BUFFER_SIZE = 4096

# User database (username: password_hash)
USERS = {
    'client1': hashlib.sha256('password123'.encode()).hexdigest(),
    'client2': hashlib.sha256('password456'.encode()).hexdigest()
}

class VPNServer:
    def __init__(self):
        self.clients = {}  # {session_id: {socket, username, ip, connected_time, stats}}
        self.server_socket = None
        self.running = False
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'packets_encrypted': 0,
            'packets_decrypted': 0
        }
        
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, key):
        """AES-256 encryption in GCM mode"""
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        self.stats['packets_encrypted'] += 1
        # Return IV + Tag + Ciphertext
        return iv + encryptor.tag + ciphertext
    
    def decrypt_data(self, encrypted_data, key):
        """AES-256 decryption in GCM mode"""
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
        """Authenticate user credentials"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return USERS.get(username) == password_hash
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        session_id = secrets.token_hex(16)
        session_key = None
        username = None
        
        try:
            # Step 1: Authentication
            auth_data = client_socket.recv(BUFFER_SIZE).decode()
            auth_request = json.loads(auth_data)
            
            username = auth_request.get('username')
            password = auth_request.get('password')
            
            print(f"[AUTH] Authentication attempt from {client_address} - User: {username}")
            
            if self.authenticate_user(username, password):
                # Generate session key
                salt = secrets.token_bytes(16)
                session_key = self.derive_key(password, salt)
                
                # Send success response with salt
                response = {
                    'status': 'success',
                    'session_id': session_id,
                    'salt': salt.hex(),
                    'message': 'Authentication successful'
                }
                client_socket.send(json.dumps(response).encode())
                
                print(f"[SUCCESS] Client {username} authenticated - Session: {session_id[:8]}...")
                
                # Store client info
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
                
                # Start handling encrypted traffic
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
                del self.clients[session_id]
                self.stats['active_connections'] -= 1
            print(f"[DISCONNECT] Client {username or 'Unknown'} disconnected")
    
    def handle_encrypted_traffic(self, session_id):
        """Handle encrypted data transfer"""
        client_info = self.clients[session_id]
        client_socket = client_info['socket']
        session_key = client_info['key']
        
        try:
            while self.running:
                # Receive length prefix (4 bytes)
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                
                data_length = struct.unpack('!I', length_data)[0]
                
                # Receive encrypted data
                encrypted_data = b''
                while len(encrypted_data) < data_length:
                    chunk = client_socket.recv(min(BUFFER_SIZE, data_length - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if not encrypted_data:
                    break
                
                # Decrypt data
                decrypted_data = self.decrypt_data(encrypted_data, session_key)
                if decrypted_data:
                    packet_info = json.loads(decrypted_data.decode())
                    
                    # Update stats
                    client_info['bytes_received'] += len(encrypted_data)
                    self.stats['total_bytes_received'] += len(encrypted_data)
                    
                    # Process packet
                    print(f"[PACKET] From {client_info['username']}: {packet_info['type']} "
                          f"- {len(packet_info['data'])} bytes")
                    
                    # Echo back (simulating VPN tunnel)
                    response = {
                        'type': 'response',
                        'data': packet_info['data'],
                        'timestamp': datetime.now().isoformat(),
                        'server_message': 'Data received and processed'
                    }
                    
                    response_data = json.dumps(response).encode()
                    encrypted_response = self.encrypt_data(response_data, session_key)
                    
                    # Send length prefix + encrypted data
                    client_socket.send(struct.pack('!I', len(encrypted_response)))
                    client_socket.send(encrypted_response)
                    
                    # Update stats
                    client_info['bytes_sent'] += len(encrypted_response)
                    self.stats['total_bytes_sent'] += len(encrypted_response)
                    
        except Exception as e:
            print(f"[ERROR] Traffic handling error: {e}")
    
    def display_stats(self):
        """Display server statistics"""
        while self.running:
            time.sleep(5)
            print("\n" + "="*60)
            print(f"{'VPN SERVER STATISTICS':^60}")
            print("="*60)
            print(f"Active Connections: {self.stats['active_connections']}")
            print(f"Total Connections: {self.stats['total_connections']}")
            print(f"Total Data Sent: {self.stats['total_bytes_sent'] / 1024:.2f} KB")
            print(f"Total Data Received: {self.stats['total_bytes_received'] / 1024:.2f} KB")
            print(f"Packets Encrypted: {self.stats['packets_encrypted']}")
            print(f"Packets Decrypted: {self.stats['packets_decrypted']}")
            print("\nConnected Clients:")
            for sid, info in self.clients.items():
                uptime = (datetime.now() - info['connected_time']).seconds
                print(f"  - {info['username']} ({info['ip']}) - Uptime: {uptime}s - "
                      f"Sent: {info['bytes_sent']/1024:.2f}KB, Recv: {info['bytes_received']/1024:.2f}KB")
            print("="*60 + "\n")
    
    def start(self):
        """Start VPN server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(5)
        self.running = True
        
        print("="*60)
        print(f"{'VPN SERVER STARTED':^60}")
        print("="*60)
        print(f"Listening on {SERVER_HOST}:{SERVER_PORT}")
        print(f"Registered Users: {', '.join(USERS.keys())}")
        print("Waiting for client connections...")
        print("="*60 + "\n")
        
        # Start stats display thread
        stats_thread = threading.Thread(target=self.display_stats, daemon=True)
        stats_thread.start()
        
        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                print(f"\n[NEW CONNECTION] From {client_address}")
                
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
            self.server_socket.close()

if __name__ == "__main__":
    server = VPNServer()
    server.start()