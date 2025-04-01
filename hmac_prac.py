#!/usr/bin/env python3
"""
HMAC-based secure peer-to-peer connection script.
Run in two separate terminals to establish a connection.

Usage:
  Terminal 1: python hmac_connection.py --mode server
  Terminal 2: python hmac_connection.py --mode client
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
from hashlib import sha256
from getpass import getpass


class HMACConnection:
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
        """Set up a shared secret key for HMAC operations."""
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
        else:
            # The client receives the key
            print("\n[*] Waiting to receive shared secret from server...")
            key_b64 = self.connection.recv(self.buffer_size).decode('utf-8')
            self.secret_key = base64.b64decode(key_b64)
            key_hex = self.secret_key.hex()
            print(f"[+] Received key: {key_hex}")
        return True

    def generate_hmac(self, message, sequence_num=None):
        """Generate an HMAC for the given message and sequence number."""
        if sequence_num is None:
            sequence_num = self.sequence_number
        
        # Combine sequence number with message to prevent replay attacks
        message_with_seq = f"{sequence_num}:{message}".encode('utf-8')
        
        # Generate HMAC
        message_hmac = hmac.new(self.secret_key, message_with_seq, sha256).digest()
        return message_hmac

    def send_message(self, message):
        """Send a message with HMAC authentication."""
        try:
            # Increment sequence number for each message
            self.sequence_number += 1
            
            # Generate HMAC for the message
            message_hmac = self.generate_hmac(message)
            
            # Prepare the packet with sequence number, message, and HMAC
            packet = {
                'sequence': self.sequence_number,
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'hmac': base64.b64encode(message_hmac).decode('utf-8')
            }
            
            # Serialize and send
            data = json.dumps(packet).encode('utf-8')
            self.connection.sendall(data)
            return True
        except Exception as e:
            print(f"[-] Failed to send message: {e}")
            return False

    def receive_message(self):
        """Receive and verify a message with HMAC authentication."""
        try:
            # Receive data
            data = self.connection.recv(self.buffer_size)
            if not data:
                return None, False
            
            # Parse the packet
            packet = json.loads(data.decode('utf-8'))
            received_sequence = packet['sequence']
            received_message = packet['message']
            received_hmac_b64 = packet['hmac']
            received_hmac = base64.b64decode(received_hmac_b64)
            
            # Generate expected HMAC for verification
            expected_hmac = self.generate_hmac(received_message, received_sequence)
            
            # Verify HMAC
            if hmac.compare_digest(received_hmac, expected_hmac):
                return received_message, True
            else:
                print(f"[-] HMAC verification failed for message: {received_message}")
                return received_message, False
        except Exception as e:
            print(f"[-] Error receiving message: {e}")
            return None, False

    def handle_commands(self):
        """Handle user commands in an interactive session."""
        print("\n[*] Starting interactive session. Type 'help' for commands.")
        
        while self.running:
            try:
                command = input("\nCommand > ")
                
                if command.lower() == 'exit' or command.lower() == 'quit':
                    print("[*] Closing connection...")
                    self.running = False
                    self.send_message("EXIT_REQUEST")
                    break
                    
                elif command.lower() == 'help':
                    print("\nAvailable commands:")
                    print("  send <message> - Send a message to the peer")
                    print("  key              - Display the current HMAC key")
                    print("  rotate           - Rotate the HMAC key")
                    print("  verify <message> - Test HMAC verification locally")
                    print("  exit/quit        - Close the connection and exit")
                    
                elif command.lower().startswith('send '):
                    message = command[5:]
                    print(f"[*] Sending: {message}")
                    if self.send_message(message):
                        print("[+] Message sent")
                        
                elif command.lower() == 'key':
                    print(f"[*] Current HMAC key: {self.secret_key.hex()}")
                    
                elif command.lower() == 'rotate':
                    print("[*] Rotating HMAC key...")
                    new_key = os.urandom(32)
                    key_message = f"KEY_ROTATION:{new_key.hex()}"
                    if self.send_message(key_message):
                        print("[+] Key rotation request sent")
                        self.secret_key = new_key
                        print(f"[+] New key active: {new_key.hex()}")
                        
                elif command.lower().startswith('verify '):
                    test_message = command[7:]
                    test_hmac = self.generate_hmac(test_message)
                    print(f"[*] Message: {test_message}")
                    print(f"[*] HMAC: {test_hmac.hex()}")
                    print("[+] Local verification successful")
                    
                else:
                    print("[-] Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                self.running = False
                break
            except Exception as e:
                print(f"[-] Error processing command: {e}")

    def receiver_thread(self):
        """Background thread to receive messages."""
        while self.running:
            try:
                message, verified = self.receive_message()
                
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
                print("Command > ", end="", flush=True)  # Restore prompt
                
                # Handle special messages
                if message.startswith("KEY_ROTATION:"):
                    new_key_hex = message.split(":", 1)[1]
                    self.secret_key = bytes.fromhex(new_key_hex)
                    print(f"\n[+] Key rotated to: {new_key_hex}")
                    print("Command > ", end="", flush=True)
                    
            except Exception as e:
                print(f"\n[-] Error in receiver thread: {e}")
                self.running = False
                break
    
    def run(self):
        """Run the HMAC connection."""
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
    parser = argparse.ArgumentParser(description='HMAC-based secure connection')
    parser.add_argument('--mode', required=True, choices=['server', 'client'],
                        help='Operation mode: server or client')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to connect to (client) or bind to (server)')
    parser.add_argument('--port', type=int, default=9000,
                        help='Port to use for connection')
    
    args = parser.parse_args()
    
    # Create and run the connection
    connection = HMACConnection(args.mode, args.host, args.port)
    connection.run()


if __name__ == "__main__":
    main()