import os
import socket
import threading
import base64
import hashlib
import json
import logging
import zlib
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler
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
            self.max_file_size_mb = config['server']['max_file_size_mb']
            self.chunk_size = config['server']['chunk_size']
            self.enable_compression = config['transfer']['enable_compression']
            self.encryption_key = config['security']['encryption_key']
            self.log_level = config['logging']['level']
            self.log_file = config['logging']['file']
            self.log_format = config['logging']['format']
            self.log_max_bytes = config['logging'].get('max_bytes', 10485760)
            self.log_backup_count = config['logging'].get('backup_count', 5)
        except FileNotFoundError:
            # Use default values if config file not found
            self.host = '0.0.0.0'
            self.port = 5000
            self.buffer_size = 65536
            self.save_path = 'received_files'
            self.max_connections = 10
            self.max_file_size_mb = 500
            self.chunk_size = 8192
            self.enable_compression = True
            self.encryption_key = 'SecureFileTransfer2024_LongKey32Bytes!'
            self.log_level = 'INFO'
            self.log_file = 'file_transfer.log'
            self.log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            self.log_max_bytes = 10485760
            self.log_backup_count = 5

    def setup_logging(self):
        """Configure logging for the server with rotation"""
        self.logger = logging.getLogger('FileTransferServer')
        self.logger.setLevel(getattr(logging, self.log_level))
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Rotating file handler
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=self.log_max_bytes,
            backupCount=self.log_backup_count
        )
        file_handler.setFormatter(logging.Formatter(self.log_format))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(self.log_format))
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def sanitize_filename(self, filename):
        """Sanitize filename to prevent directory traversal attacks"""
        # Get basename to remove any path components
        safe_name = os.path.basename(filename)
        
        # Remove any remaining path separators
        safe_name = safe_name.replace('..', '').replace('/', '').replace('\\', '')
        
        # If filename is empty after sanitization, use a default
        if not safe_name or safe_name.startswith('.'):
            safe_name = f'file_{int(time.time())}'
        
        return safe_name
    
    def check_disk_space(self, required_bytes):
        """Check if there's enough disk space available"""
        try:
            stat = os.statvfs(self.save_path)
            available_bytes = stat.f_bavail * stat.f_frsize
            return available_bytes > required_bytes * 1.1  # 10% buffer
        except Exception as e:
            self.logger.warning(f"Could not check disk space: {e}")
            return True  # Proceed if check fails

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
        filename = "unknown"
        start_time = time.time()
        
        try:
            client_socket.settimeout(60)  # 60 second timeout for operations
            
            # Receive filename length
            filename_length_bytes = self._recv_exact(client_socket, 4)
            if not filename_length_bytes:
                raise ConnectionError("Client disconnected before sending filename length")
            filename_length = int.from_bytes(filename_length_bytes, byteorder='big')
            
            if filename_length > 255:
                raise ValueError(f"Filename too long: {filename_length} bytes")
            
            # Receive filename
            filename_bytes = self._recv_exact(client_socket, filename_length)
            if not filename_bytes:
                raise ConnectionError("Client disconnected while sending filename")
            filename = filename_bytes.decode('utf-8')
            
            # Sanitize filename for security
            filename = self.sanitize_filename(filename)
            self.logger.info(f"Receiving file: {filename} from {client_address}")
            
            # Receive file size
            file_size_bytes = self._recv_exact(client_socket, 8)
            if not file_size_bytes:
                raise ConnectionError("Client disconnected while sending file size")
            file_size = int.from_bytes(file_size_bytes, byteorder='big')
            
            # Validate file size
            max_bytes = self.max_file_size_mb * 1024 * 1024
            if file_size > max_bytes:
                raise ValueError(f"File too large: {file_size / 1024 / 1024:.2f} MB (max: {self.max_file_size_mb} MB)")
            
            if file_size == 0:
                raise ValueError("File size is zero")
            
            # Check disk space
            if not self.check_disk_space(file_size):
                raise IOError("Insufficient disk space")
            
            # Receive compression flag
            compression_flag = self._recv_exact(client_socket, 1)
            if not compression_flag:
                raise ConnectionError("Client disconnected while sending compression flag")
            is_compressed = compression_flag[0] == 1
            
            # Receive checksum length
            checksum_length_bytes = self._recv_exact(client_socket, 4)
            if not checksum_length_bytes:
                raise ConnectionError("Client disconnected while sending checksum length")
            checksum_length = int.from_bytes(checksum_length_bytes, byteorder='big')
            
            if checksum_length != 64:  # SHA-256 hex length
                raise ValueError(f"Invalid checksum length: {checksum_length}")
            
            # Receive original checksum
            checksum_bytes = self._recv_exact(client_socket, checksum_length)
            if not checksum_bytes:
                raise ConnectionError("Client disconnected while sending checksum")
            original_checksum = checksum_bytes.decode('utf-8')
            
            # Receive encrypted file data in chunks
            self.update_status(f"Receiving {filename} ({file_size / 1024 / 1024:.2f} MB)...")
            encrypted_data = b''
            bytes_received = 0
            
            while bytes_received < file_size:
                remaining = file_size - bytes_received
                chunk_size = min(self.buffer_size, remaining)
                chunk = client_socket.recv(chunk_size)
                
                if not chunk:
                    raise ConnectionError(f"Connection lost after {bytes_received}/{file_size} bytes")
                
                encrypted_data += chunk
                bytes_received += len(chunk)
            
            self.logger.info(f"Received {bytes_received} bytes, decrypting...")
            
            # Decrypt file
            try:
                decrypted_data = self.cipher.decrypt(encrypted_data)
            except Exception as decrypt_error:
                self.logger.error(f"Decryption failed for {filename}: {decrypt_error}")
                raise ValueError(f"Decryption failed: Invalid encryption key or corrupted data")
            
            # Decompress if compressed
            if is_compressed:
                try:
                    self.logger.info(f"Decompressing {filename}...")
                    decrypted_data = zlib.decompress(decrypted_data)
                except zlib.error as ze:
                    self.logger.error(f"Decompression failed for {filename}: {ze}")
                    raise ValueError(f"Decompression failed: {ze}")

            # Verify file integrity with SHA-256 checksum
            calculated_checksum = hashlib.sha256(decrypted_data).hexdigest()
            if calculated_checksum != original_checksum:
                self.logger.error(f"Checksum mismatch for {filename}: expected {original_checksum}, got {calculated_checksum}")
                raise ValueError("File integrity check failed: checksum mismatch")
            
            self.logger.info(f"Checksum verified for {filename}")

            # Save decrypted file
            save_path = os.path.join(self.save_path, filename)
            
            # Handle duplicate filenames
            if os.path.exists(save_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(save_path):
                    filename = f"{base}_{counter}{ext}"
                    save_path = os.path.join(self.save_path, filename)
                    counter += 1
                self.logger.info(f"Renamed to {filename} to avoid overwrite")
            
            with open(save_path, 'wb') as file:
                file.write(decrypted_data)
            
            # Calculate transfer statistics
            elapsed_time = time.time() - start_time
            speed_mbps = (file_size / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
            
            # Send success response
            client_socket.send(b"SUCCESS")
            
            # Update status
            self.logger.info(f"Successfully received {filename} from {client_address} ({speed_mbps:.2f} MB/s)")
            self.update_status(f"Received {filename} ({file_size / 1024 / 1024:.2f} MB) at {speed_mbps:.2f} MB/s")

        except ConnectionError as ce:
            self.logger.error(f"Connection error with {client_address}: {ce}")
            self.update_status(f"Connection error: {ce}")
            try:
                client_socket.send(b"FAILED")
            except:
                pass
        except ValueError as ve:
            self.logger.error(f"Validation error for {filename}: {ve}")
            self.update_status(f"Validation error: {ve}")
            try:
                client_socket.send(b"FAILED")
            except:
                pass
        except IOError as ioe:
            self.logger.error(f"I/O error for {filename}: {ioe}")
            self.update_status(f"I/O error: {ioe}")
            try:
                client_socket.send(b"FAILED")
            except:
                pass
        except Exception as e:
            self.logger.error(f"Unexpected error receiving {filename} from {client_address}: {e}", exc_info=True)
            self.update_status(f"Error: {e}")
            try:
                client_socket.send(b"FAILED")
            except:
                pass
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _recv_exact(self, sock, num_bytes):
        """Receive exactly num_bytes from socket"""
        data = b''
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data

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
