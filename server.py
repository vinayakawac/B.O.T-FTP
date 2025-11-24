import os
import socket
import threading
import base64
import hashlib
import json
import logging
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet

class FileTransferServer:
    def __init__(self, config_path='config.json'):
        # Load configuration
        self.load_config(config_path)
        
        # Setup logging
        self.setup_logging()
        
        # File save path
        os.makedirs(self.save_path, exist_ok=True)
        
        # Generate secure encryption key
        self.key = base64.urlsafe_b64encode(self.encryption_key.encode()[:32])
        self.cipher = Fernet(self.key)
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("File Transfer Server")
        self.root.geometry("600x500")
        
        # Setup GUI and start server
        self.setup_gui()
        self.start_server()

    def load_config(self, config_path):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.host = config['server']['host']
            self.port = config['server']['port']
            self.buffer_size = config['server']['buffer_size']
            self.save_path = config['server']['save_path']
            self.max_connections = config['server']['max_connections']
            self.encryption_key = config['security']['encryption_key']
            self.log_level = config['logging']['level']
            self.log_file = config['logging']['file']
            self.log_format = config['logging']['format']
        except FileNotFoundError:
            # Use default values if config file not found
            self.host = '0.0.0.0'
            self.port = 5000
            self.buffer_size = 4096
            self.save_path = 'received_files'
            self.max_connections = 5
            self.encryption_key = 'SecureFileTransfer2024_LongKey32Bytes!'
            self.log_level = 'INFO'
            self.log_file = 'file_transfer.log'
            self.log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    def setup_logging(self):
        """Configure logging for the server"""
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            format=self.log_format,
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('FileTransferServer')

    def setup_gui(self):
        # Server status label
        tk.Label(self.root, text="Server Status:").pack(pady=(10, 0))
        
        # Scrolled text area for logs
        self.status_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=70, height=20)
        self.status_area.pack(padx=10, pady=10)

    def update_status(self, message):
        self.status_area.insert(tk.END, message + "\n")
        self.status_area.see(tk.END)
        self.logger.info(message)

    def handle_client(self, client_socket, client_address):
        try:
            # Receive filename length
            filename_length_bytes = client_socket.recv(4)
            filename_length = int.from_bytes(filename_length_bytes, byteorder='big')
            
            # Receive filename
            filename = client_socket.recv(filename_length).decode()
            
            # Receive file size
            file_size_bytes = client_socket.recv(8)
            file_size = int.from_bytes(file_size_bytes, byteorder='big')
            
            # Receive checksum length
            checksum_length_bytes = client_socket.recv(4)
            checksum_length = int.from_bytes(checksum_length_bytes, byteorder='big')
            
            # Receive original checksum
            original_checksum = client_socket.recv(checksum_length).decode()
            
            # Receive encrypted file data
            encrypted_data = b''
            while len(encrypted_data) < file_size:
                chunk = client_socket.recv(self.buffer_size)
                if not chunk:
                    break
                encrypted_data += chunk
            
            # Decrypt file
            try:
                decrypted_data = self.cipher.decrypt(encrypted_data)
            except Exception as decrypt_error:
                self.logger.error(f"Decryption error from {client_address}: {decrypt_error}")
                self.update_status(f"Decryption error from {client_address}: {decrypt_error}")
                client_socket.send(b"FAILED")
                return

            # Verify file integrity with SHA-256 checksum
            calculated_checksum = hashlib.sha256(decrypted_data).hexdigest()
            if calculated_checksum != original_checksum:
                self.logger.error(f"Checksum mismatch for {filename} from {client_address}")
                self.update_status(f"Checksum verification failed for {filename}")
                client_socket.send(b"FAILED")
                return
            
            self.logger.info(f"Checksum verified for {filename}")

            # Save decrypted file
            save_path = os.path.join(self.save_path, filename)
            with open(save_path, 'wb') as file:
                file.write(decrypted_data)
            
            # Send success response
            client_socket.send(b"SUCCESS")
            
            # Update status
            self.logger.info(f"Successfully received {filename} from {client_address}")
            self.update_status(f"Received file from {client_address}: {filename}")

        except Exception as e:
            self.logger.error(f"Error receiving file from {client_address}: {e}")
            self.update_status(f"Error receiving file from {client_address}: {e}")
            client_socket.send(b"FAILED")
        finally:
            client_socket.close()

    def start_server(self):
        def run_server():
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                # Bind and listen
                server_socket.bind((self.host, self.port))
                server_socket.listen(self.max_connections)
                
                self.logger.info(f"Server started on {self.host}:{self.port}")
                self.update_status(f"Server listening on {self.host}:{self.port}")
                
                while True:
                    # Accept client connections
                    client_socket, client_address = server_socket.accept()
                    self.logger.info(f"New connection from {client_address}")
                    self.update_status(f"Connection from {client_address}")
                    
                    # Handle each client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, client_address)
                    )
                    client_thread.start()
            
            except Exception as e:
                self.logger.error(f"Server error: {e}")
                self.update_status(f"Server error: {e}")
            finally:
                server_socket.close()

        # Start server in a separate thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    server = FileTransferServer()
    server.run()
