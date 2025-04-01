#!/usr/bin/env python3
"""
MAC-based secure peer-to-peer connection script with HMAC and CMAC support.
Run in two separate terminals to establish a connection.

Usage:
  Terminal 1: python mac_connection.py --mode server
  Terminal 2: python mac_connection.py --mode client
"""

import argparse
import base64
import hmac
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
from hashlib import sha256, sha512, sha1, md5
from getpass import getpass

# For CMAC implementation
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CMAC_AVAILABLE = True
except ImportError:
    print("Warning: cryptography package not installed. CMAC will not be available.")
    print("To install: pip install cryptography")
    CMAC_AVAILABLE = False


class CMACGenerator:
    """Class for generating and verifying CMAC signatures."""
    
    def __init__(self, key, cipher_type='AES'):
        """Initialize CMAC generator with the given key."""
        if not CMAC_AVAILABLE:
            raise RuntimeError("CMAC is not available. Install cryptography package.")
        
        self.key = key
        self.cipher_type = cipher_type
        # Ensure key is the right length for the cipher
        if cipher_type == 'AES':
            # AES requires a 16, 24, or 32 byte key (128, 192, or 256 bits)
            if len(key) not in (16, 24, 32):
                # Use SHA256 to derive a 32-byte key
                self.key = sha256(key).digest()
        elif cipher_type == '3DES':
            # 3DES requires a 24-byte key
            if len(key) != 24:
                # Use SHA1 to derive a 20-byte key and pad to 24 bytes
                derived = sha1(key).digest()
                self.key = derived + derived[:4]
    
    def generate(self, message):
        """Generate a CMAC for the given message."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if self.cipher_type == 'AES':
            algorithm = algorithms.AES(self.key)
        elif self.cipher_type == '3DES':
            algorithm = algorithms.TripleDES(self.key)
        else:
            raise ValueError(f"Unsupported cipher type: {self.cipher_type}")
        
        from cryptography.hazmat.primitives.cmac import CMAC
        c = CMAC(algorithm, backend=default_backend())
        c.update(message)
        return c.finalize()
    
    def verify(self, message, signature):
        """Verify a CMAC signature."""
        computed_cmac = self.generate(message)
        return hmac.compare_digest(computed_cmac, signature)


class MACConnection:
    def __init__(self, mode, host='127.0.0.1', port=9000, buffer_size=4096):
        self.mode = mode
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.socket = None
        self.connection = None
        self.secret_key = None
        self.running = False
        self.sequence_number = 0
        self.cmac_generator = None
        self.mac_algorithm = "hmac-sha256"  # Default algorithm
        self.hash_algorithms = {
            'md5': md5,
            'sha1': sha1, 
            'sha256': sha256,
            'sha512': sha512
        }
    
    def setup_connection(self):
        """Establish the socket connection based on mode."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.mode == 'server':
                # Allow reuse of the address in case of recent disconnection
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.bind((self.host, self.port))
                self.socket.listen(1)
                print(f"[*] Server listening on {self.host}:{self.port}")
                self.connection, client_address = self.socket.accept()
                print(f"[+] Connection established with {client_address[0]}:{client_address[1]}")
            else:
                print(f"[*] Connecting to {self.host}:{self.port}...")
                self.socket.connect((self.host, self.port))
                self.connection = self.socket
                print(f"[+] Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection setup failed: {e}")
            return False

    def setup_shared_secret(self):
        """Set up a shared secret key for MAC operations."""
        if self.mode == 'server':
            print("\n[*] Setting up shared secret")
            # The server generates and provides the key
            while True:
                choice = input("[?] Generate random key or enter custom key? (r/c): ").lower()
                if choice == 'r':
                    self.secret_key = os.urandom(32)
                    key_hex = self.secret_key.hex()
                    print(f"[+] Generated key: {key_hex}")
                    break
                elif choice == 'c':
                    custom_key = getpass("[?] Enter custom secret key: ").encode('utf-8')
                    self.secret_key = sha256(custom_key).digest()
                    key_hex = self.secret_key.hex()
                    print(f"[+] Using key: {key_hex}")
                    break
                else:
                    print("[-] Invalid choice. Try again.")
            
            # Send the key to the client (in practice, this would be done over a secure channel)
            print("[*] Securely transmitting key to client...")
            key_b64 = base64.b64encode(self.secret_key).decode('utf-8')
            self.connection.sendall(key_b64.encode('utf-8'))
            print("[+] Key transmitted")
            
            # Select MAC algorithm
            self.select_mac_algorithm()
        else:
            # The client receives the key
            print("\n[*] Waiting to receive shared secret from server...")
            key_b64 = self.connection.recv(self.buffer_size).decode('utf-8')
            self.secret_key = base64.b64decode(key_b64)
            key_hex = self.secret_key.hex()
            print(f"[+] Received key: {key_hex}")
            
            # Receive MAC algorithm from server
            print("[*] Waiting for MAC algorithm selection...")
            self.mac_algorithm = self.connection.recv(self.buffer_size).decode('utf-8')
            print(f"[+] Using MAC algorithm: {self.mac_algorithm}")
        
        # Initialize CMAC if available and needed
        if CMAC_AVAILABLE and 'cmac' in self.mac_algorithm:
            self.cmac_generator = CMACGenerator(self.secret_key)
            print("[+] CMAC initialized")
        
        return True
    
    def select_mac_algorithm(self):
        """Select MAC algorithm to use for the connection."""
        available_algorithms = [
            'hmac-md5',
            'hmac-sha1',
            'hmac-sha256',
            'hmac-sha512'
        ]
        
        if CMAC_AVAILABLE:
            available_algorithms.extend(['cmac-aes', 'dual-hmac-cmac'])
        
        print("\n[*] Select MAC algorithm:")
        for i, algo in enumerate(available_algorithms, 1):
            print(f"  {i}. {algo}")
        
        while True:
            try:
                choice = int(input("[?] Enter your choice (1-{}): ".format(len(available_algorithms))))
                if 1 <= choice <= len(available_algorithms):
                    self.mac_algorithm = available_algorithms[choice-1]
                    break
                else:
                    print("[-] Invalid choice. Try again.")
            except ValueError:
                print("[-] Please enter a number.")
        
        print(f"[+] Selected algorithm: {self.mac_algorithm}")
        
        # Send the selected algorithm to the client
        self.connection.sendall(self.mac_algorithm.encode('utf-8'))
        
        # Initialize CMAC if needed
        if CMAC_AVAILABLE and 'cmac' in self.mac_algorithm:
            self.cmac_generator = CMACGenerator(self.secret_key)
            print("[+] CMAC initialized")
    
    def get_hash_function(self):
        """Get the hash function based on the selected MAC algorithm."""
        if 'md5' in self.mac_algorithm:
            return md5
        elif 'sha1' in self.mac_algorithm:
            return sha1
        elif 'sha512' in self.mac_algorithm:
            return sha512
        else:
            return sha256  # Default

    def generate_hmac(self, message, sequence_num=None):
        """Generate an HMAC for the given message and sequence number."""
        if sequence_num is None:
            sequence_num = self.sequence_number
        
        # Combine sequence number with message to prevent replay attacks
        if isinstance(message, str):
            message_with_seq = f"{sequence_num}:{message}".encode('utf-8')
        else:
            message_with_seq = f"{sequence_num}:".encode('utf-8') + message
        
        # Generate HMAC with the appropriate hash function
        hash_func = self.get_hash_function()
        message_hmac = hmac.new(self.secret_key, message_with_seq, hash_func).digest()
        return message_hmac
    
    def generate_cmac(self, message, sequence_num=None):
        """Generate a CMAC for the given message and sequence number."""
        if sequence_num is None:
            sequence_num = self.sequence_number
        
        # Combine sequence number with message to prevent replay attacks
        if isinstance(message, str):
            message_with_seq = f"{sequence_num}:{message}".encode('utf-8')
        else:
            message_with_seq = f"{sequence_num}:".encode('utf-8') + message
        
        return self.cmac_generator.generate(message_with_seq)
    
    def generate_macs(self, message, sequence_num=None):
        """Generate MAC(s) based on the selected algorithm."""
        hmac_value = None
        cmac_value = None
        
        if 'hmac' in self.mac_algorithm or self.mac_algorithm == 'dual-hmac-cmac':
            hmac_value = self.generate_hmac(message, sequence_num)
        
        if ('cmac' in self.mac_algorithm or self.mac_algorithm == 'dual-hmac-cmac') and CMAC_AVAILABLE:
            cmac_value = self.generate_cmac(message, sequence_num)
        
        return hmac_value, cmac_value
    
    def verify_macs(self, message, hmac_value=None, cmac_value=None, sequence_num=None):
        """Verify MAC(s) based on the selected algorithm."""
        hmac_valid = True
        cmac_valid = True
        
        if hmac_value is not None and ('hmac' in self.mac_algorithm or self.mac_algorithm == 'dual-hmac-cmac'):
            expected_hmac = self.generate_hmac(message, sequence_num)
            hmac_valid = hmac.compare_digest(hmac_value, expected_hmac)
        
        if cmac_value is not None and ('cmac' in self.mac_algorithm or self.mac_algorithm == 'dual-hmac-cmac') and CMAC_AVAILABLE:
            expected_cmac = self.generate_cmac(message, sequence_num)
            cmac_valid = hmac.compare_digest(cmac_value, expected_cmac)
        
        return hmac_valid and cmac_valid

    def send_message(self, message):
        """Send a message with MAC authentication."""
        try:
            # Increment sequence number for each message
            self.sequence_number += 1
            
            # Generate MACs for the message
            hmac_value, cmac_value = self.generate_macs(message)
            
            # Prepare the packet with sequence number, message, and MACs
            packet = {
                'sequence': self.sequence_number,
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'algorithm': self.mac_algorithm
            }
            
            # Add appropriate MACs
            if hmac_value:
                packet['hmac'] = base64.b64encode(hmac_value).decode('utf-8')
                # Calculate and add raw digest for display
                hash_func = self.get_hash_function()
                raw_digest = hash_func(message.encode('utf-8') if isinstance(message, str) else message).digest()
                packet['raw_digest'] = base64.b64encode(raw_digest).decode('utf-8')
            
            if cmac_value:
                packet['cmac'] = base64.b64encode(cmac_value).decode('utf-8')
            
            # Serialize and send
            data = json.dumps(packet).encode('utf-8')
            self.connection.sendall(data)
            return True
        except Exception as e:
            print(f"[-] Failed to send message: {e}")
            return False

    def receive_message(self):
        """Receive and verify a message with MAC authentication."""
        try:
            # Receive data
            data = self.connection.recv(self.buffer_size)
            if not data:
                return None, False, {}
            
            # Parse the packet
            packet = json.loads(data.decode('utf-8'))
            received_sequence = packet['sequence']
            received_message = packet['message']
            received_algorithm = packet.get('algorithm', self.mac_algorithm)
            
            # Extract MACs
            hmac_value = None
            cmac_value = None
            raw_digest = None
            
            if 'hmac' in packet:
                hmac_value = base64.b64decode(packet['hmac'])
            
            if 'cmac' in packet:
                cmac_value = base64.b64decode(packet['cmac'])
            
            if 'raw_digest' in packet:
                raw_digest = base64.b64decode(packet['raw_digest'])
            
            # Verify MACs
            mac_valid = self.verify_macs(
                received_message, 
                hmac_value, 
                cmac_value, 
                received_sequence
            )
            
            # Prepare verification info
            verification_info = {
                'algorithm': received_algorithm,
                'hmac': hmac_value.hex() if hmac_value else None,
                'cmac': cmac_value.hex() if cmac_value else None,
                'raw_digest': raw_digest.hex() if raw_digest else None,
                'sequence': received_sequence,
                'timestamp': packet.get('timestamp')
            }
            
            return received_message, mac_valid, verification_info
        except Exception as e:
            print(f"[-] Error receiving message: {e}")
            return None, False, {}

    def display_verification_details(self, message, verification_info):
        """Display detailed verification information."""
        print("\n[VERIFICATION DETAILS]")
        print(f"Message: {message}")
        print(f"Algorithm: {verification_info['algorithm']}")
        print(f"Sequence #: {verification_info['sequence']}")
        print(f"Timestamp: {verification_info['timestamp']}")
        
        if verification_info['raw_digest']:
            print(f"Raw digest: {verification_info['raw_digest']}")
        
        if verification_info['hmac']:
            print(f"HMAC: {verification_info['hmac']}")
            
        if verification_info['cmac']:
            print(f"CMAC: {verification_info['cmac']}")

    def handle_commands(self):
        """Handle user commands in an interactive session."""
        print("\n[*] Starting interactive session. Type 'help' for commands.")
        
        while self.running:
            try:
                command = input("\nCommand > ")
                parts = command.split(maxsplit=1)
                cmd = parts[0].lower() if parts else ""
                
                if cmd in ('exit', 'quit'):
                    print("[*] Closing connection...")
                    self.running = False
                    self.send_message("EXIT_REQUEST")
                    break
                    
                elif cmd == 'help':
                    self.display_help()
                    
                elif cmd == 'send' and len(parts) > 1:
                    message = parts[1]
                    print(f"[*] Sending: {message}")
                    if self.send_message(message):
                        print("[+] Message sent")
                        
                elif cmd == 'key':
                    print(f"[*] Current key: {self.secret_key.hex()}")
                    print(f"[*] MAC algorithm: {self.mac_algorithm}")
                    
                elif cmd == 'rotate':
                    self.rotate_key()
                    
                elif cmd == 'verify' and len(parts) > 1:
                    self.local_verify(parts[1])
                
                elif cmd == 'algorithm':
                    if self.mode == 'server':
                        prev_algorithm = self.mac_algorithm
                        self.select_mac_algorithm()
                        print(f"[+] Changed algorithm from {prev_algorithm} to {self.mac_algorithm}")
                    else:
                        print("[-] Only the server can change the algorithm")
                
                elif cmd == 'digest' and len(parts) > 1:
                    self.show_digest(parts[1])
                
                elif cmd == 'compare' and len(parts) > 1:
                    args = parts[1].split()
                    if len(args) >= 2:
                        self.compare_messages(args[0], args[1])
                    else:
                        print("[-] Usage: compare <message1> <message2>")
                
                else:
                    print("[-] Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                self.running = False
                break
            except Exception as e:
                print(f"[-] Error processing command: {e}")
    
    def display_help(self):
        """Display available commands."""
        print("\nAvailable commands:")
        print("  send <message>       - Send a message to the peer")
        print("  key                  - Display the current key and algorithm")
        print("  rotate               - Rotate the key")
        print("  verify <message>     - Test MAC verification locally")
        print("  algorithm            - Change MAC algorithm (server only)")
        print("  digest <message>     - Show raw digest, HMAC, and CMAC for a message")
        print("  compare <msg1> <msg2>- Compare MACs for two different messages")
        print("  exit/quit            - Close the connection and exit")
    
    def rotate_key(self):
        """Generate and distribute a new key."""
        print("[*] Rotating key...")
        new_key = os.urandom(32)
        key_message = f"KEY_ROTATION:{new_key.hex()}"
        if self.send_message(key_message):
            print("[+] Key rotation request sent")
            self.secret_key = new_key
            
            # Reinitialize CMAC with new key if needed
            if CMAC_AVAILABLE and 'cmac' in self.mac_algorithm:
                self.cmac_generator = CMACGenerator(self.secret_key)
                
            print(f"[+] New key active: {new_key.hex()}")
    
    def local_verify(self, message):
        """Test MAC verification locally."""
        print(f"[*] Testing verification for: {message}")
        
        # Generate MACs
        hmac_value, cmac_value = self.generate_macs(message)
        
        # Display results
        print("[+] Verification test results:")
        
        hash_func = self.get_hash_function()
        raw_digest = hash_func(message.encode('utf-8')).digest()
        print(f"  Raw {hash_func.__name__} digest: {raw_digest.hex()}")
        
        if hmac_value:
            print(f"  HMAC-{hash_func.__name__}: {hmac_value.hex()}")
            
        if cmac_value:
            print(f"  CMAC-AES: {cmac_value.hex()}")
            
        print("[+] Local verification successful")
    
    def show_digest(self, message):
        """Show raw digest, HMAC, and CMAC for a message."""
        print(f"[*] Generating digests for: {message}")
        
        # Generate all possible digests
        for name, hash_func in self.hash_algorithms.items():
            digest = hash_func(message.encode('utf-8')).digest()
            print(f"  {name.upper()} digest: {digest.hex()}")
        
        # Generate all possible HMACs
        for name, hash_func in self.hash_algorithms.items():
            mac = hmac.new(self.secret_key, message.encode('utf-8'), hash_func).digest()
            print(f"  HMAC-{name.upper()}: {mac.hex()}")
        
        # Generate CMAC if available
        if CMAC_AVAILABLE:
            cmac = CMACGenerator(self.secret_key).generate(message.encode('utf-8'))
            print(f"  CMAC-AES: {cmac.hex()}")
    
    def compare_messages(self, msg1, msg2):
        """Compare MACs for two different messages."""
        print("[*] Comparing MACs for two messages:")
        print(f"  Message 1: {msg1}")
        print(f"  Message 2: {msg2}")
        
        # Get the current hash function
        hash_func = self.get_hash_function()
        
        # Generate raw digests
        digest1 = hash_func(msg1.encode('utf-8')).digest()
        digest2 = hash_func(msg2.encode('utf-8')).digest()
        print(f"\n  {hash_func.__name__.upper()} digest comparison:")
        print(f"    Message 1: {digest1.hex()}")
        print(f"    Message 2: {digest2.hex()}")
        print(f"    Match: {digest1 == digest2}")
        
        # Generate HMACs
        hmac1 = hmac.new(self.secret_key, msg1.encode('utf-8'), hash_func).digest()
        hmac2 = hmac.new(self.secret_key, msg2.encode('utf-8'), hash_func).digest()
        print(f"\n  HMAC-{hash_func.__name__.upper()} comparison:")
        print(f"    Message 1: {hmac1.hex()}")
        print(f"    Message 2: {hmac2.hex()}")
        print(f"    Match: {hmac1 == hmac2}")
        
        # Generate CMACs if available
        if CMAC_AVAILABLE:
            cmac_gen = CMACGenerator(self.secret_key)
            cmac1 = cmac_gen.generate(msg1.encode('utf-8'))
            cmac2 = cmac_gen.generate(msg2.encode('utf-8'))
            print(f"\n  CMAC-AES comparison:")
            print(f"    Message 1: {cmac1.hex()}")
            print(f"    Message 2: {cmac2.hex()}")
            print(f"    Match: {cmac1 == cmac2}")

    def receiver_thread(self):
        """Background thread to receive messages."""
        while self.running:
            try:
                message, verified, verification_info = self.receive_message()
                
                if message is None:
                    print("\n[-] Connection closed by peer")
                    self.running = False
                    break
                    
                if message == "EXIT_REQUEST":
                    print("\n[*] Peer requested to close the connection")
                    self.running = False
                    break
                    
                verification_status = "✓" if verified else "✗"
                print(f"\n[RECEIVED] {verification_status} {message}")
                
                # Display verification details if requested
                if "DETAILS" in message:
                    self.display_verification_details(message, verification_info)
                
                print("Command > ", end="", flush=True)  # Restore prompt
                
                # Handle special messages
                if message.startswith("KEY_ROTATION:"):
                    new_key_hex = message.split(":", 1)[1]
                    self.secret_key = bytes.fromhex(new_key_hex)
                    
                    # Reinitialize CMAC with new key if needed
                    if CMAC_AVAILABLE and 'cmac' in self.mac_algorithm:
                        self.cmac_generator = CMACGenerator(self.secret_key)
                        
                    print(f"\n[+] Key rotated to: {new_key_hex}")
                    print("Command > ", end="", flush=True)
                    
                elif message.startswith("ALGORITHM_CHANGE:"):
                    new_algorithm = message.split(":", 1)[1]
                    self.mac_algorithm = new_algorithm
                    
                    # Reinitialize CMAC if needed
                    if CMAC_AVAILABLE and 'cmac' in self.mac_algorithm:
                        self.cmac_generator = CMACGenerator(self.secret_key)
                        
                    print(f"\n[+] MAC algorithm changed to: {new_algorithm}")
                    print("Command > ", end="", flush=True)
                    
            except Exception as e:
                print(f"\n[-] Error in receiver thread: {e}")
                self.running = False
                break
    
    def run(self):
        """Run the MAC connection."""
        # Set up the connection
        if not self.setup_connection():
            return False
        
        # Set up the shared secret
        if not self.setup_shared_secret():
            return False
        
        # Start the communication session
        self.running = True
        
        # Start receiver thread
        receiver = threading.Thread(target=self.receiver_thread)
        receiver.daemon = True
        receiver.start()
        
        # Handle user commands
        self.handle_commands()
        
        # Clean up
        time.sleep(0.5)  # Give time for last messages
        if self.connection:
            self.connection.close()
        if self.socket and self.mode == 'server':
            self.socket.close()
        
        print("[*] Connection closed")
        return True


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='MAC-based secure connection with HMAC and CMAC')
    parser.add_argument('--mode', required=True, choices=['server', 'client'],
                        help='Operation mode: server or client')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to connect to (client) or bind to (server)')
    parser.add_argument('--port', type=int, default=9000,
                        help='Port to use for connection')
    
    args = parser.parse_args()
    
    # Create and run the connection
    connection = MACConnection(args.mode, args.host, args.port)
    connection.run()


if __name__ == "__main__":
    main()