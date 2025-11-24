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
from tkinter import filedialog, messagebox, scrolledtext, ttk
from cryptography.fernet import Fernet

class FileTransferClient:
    def __init__(self, config_path='config.json'):
        # Load configuration
        self.load_config(config_path)
        
        # Setup logging
        self.setup_logging()
        
        # Network configuration
        self.server_ip = None
        
        # Generate secure encryption key (must match server)
        self.key = base64.urlsafe_b64encode(self.encryption_key.encode()[:32])
        self.cipher = Fernet(self.key)
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("File Transfer Client")
        self.root.geometry("600x500")
        
        # Setup GUI and discover server
        self.setup_gui()
        self.discover_server()

    def load_config(self, config_path):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.port = config['client']['port']
            self.buffer_size = config['client']['buffer_size']
            self.connection_timeout = config['client']['connection_timeout']
            self.scan_timeout = config['client']['scan_timeout']
            self.max_retries = config['client']['max_retries']
            self.retry_delay = config['client']['retry_delay']
            self.chunk_size = config['client']['chunk_size']
            self.enable_compression = config['transfer']['enable_compression']
            self.compression_level = config['transfer']['compression_level']
            self.show_progress = config['transfer']['show_progress']
            self.encryption_key = config['security']['encryption_key']
            self.log_level = config['logging']['level']
            self.log_file = config['logging']['file']
            self.log_format = config['logging']['format']
            self.log_max_bytes = config['logging'].get('max_bytes', 10485760)
            self.log_backup_count = config['logging'].get('backup_count', 5)
        except FileNotFoundError:
            # Use default values if config file not found
            self.port = 5000
            self.buffer_size = 65536
            self.connection_timeout = 30
            self.scan_timeout = 0.1
            self.max_retries = 3
            self.retry_delay = 2
            self.chunk_size = 8192
            self.enable_compression = True
            self.compression_level = 6
            self.show_progress = True
            self.encryption_key = 'SecureFileTransfer2024_LongKey32Bytes!'
            self.log_level = 'INFO'
            self.log_file = 'file_transfer.log'
            self.log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            self.log_max_bytes = 10485760
            self.log_backup_count = 5

    def setup_logging(self):
        """Configure logging for the client with rotation"""
        self.logger = logging.getLogger('FileTransferClient')
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

    def setup_gui(self):
        # Server Host Label and Entry
        tk.Label(self.root, text="Server Host:").pack(pady=(10, 0))
        self.host_entry = tk.Entry(self.root, width=30)
        self.host_entry.pack()
        self.host_entry.insert(0, "Discovering...")

        # File Send Button
        tk.Button(self.root, text="Select File to Send", command=self.select_file, 
                 font=("Arial", 10, "bold")).pack(pady=10)

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, 
                                           maximum=100, length=600)
        self.progress_bar.pack(pady=5)
        
        # Progress Label
        self.progress_label = tk.Label(self.root, text="")
        self.progress_label.pack()

        # Status Area
        tk.Label(self.root, text="Transfer Status:").pack()
        self.status_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=70, height=15)
        self.status_area.pack(padx=10, pady=10)

    def get_local_ip(self):
        try:
            # Create a socket to connect to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def discover_server(self):
        def scan_network():
            local_ip = self.get_local_ip()
            subnet = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            for i in range(1, 255):
                test_ip = f"{subnet}{i}"
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(self.scan_timeout)
                        result = sock.connect_ex((test_ip, self.port))
                        if result == 0:
                            self.server_ip = test_ip
                            self.root.after(0, self.update_server_ip)
                            return
                except Exception:
                    pass
            
            self.logger.warning("Server discovery failed")
            self.update_status("No server found. Enter IP manually.")

        threading.Thread(target=scan_network, daemon=True).start()

    def update_server_ip(self):
        if self.server_ip:
            self.host_entry.delete(0, tk.END)
            self.host_entry.insert(0, self.server_ip)
            self.logger.info(f"Server discovered at {self.server_ip}")
            self.update_status(f"Server discovered at {self.server_ip}")

    def update_status(self, message):
        self.status_area.insert(tk.END, message + "\n")
        self.status_area.see(tk.END)
        self.logger.info(message)

    def calculate_checksum(self, data):
        """Calculate SHA-256 checksum of data"""
        return hashlib.sha256(data).hexdigest()

    def compress_data(self, data):
        """Compress data using zlib"""
        if not self.enable_compression:
            return data, False
        
        try:
            compressed = zlib.compress(data, level=self.compression_level)
            # Only use compression if it actually reduces size
            if len(compressed) < len(data):
                self.logger.info(f"Compression: {len(data)} -> {len(compressed)} bytes ({100 * (1 - len(compressed)/len(data)):.1f}% reduction)")
                return compressed, True
            else:
                self.logger.info("Compression skipped: no size reduction")
                return data, False
        except Exception as e:
            self.logger.warning(f"Compression failed: {e}, sending uncompressed")
            return data, False

    def encrypt_file(self, file_path):
        """Read, compress, and encrypt file"""
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            
            original_data = data
            
            # Compress if enabled
            data, is_compressed = self.compress_data(data)
            
            # Encrypt
            encrypted_data = self.cipher.encrypt(data)
            
            return encrypted_data, original_data, is_compressed
            
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            raise
        except PermissionError:
            self.logger.error(f"Permission denied: {file_path}")
            raise
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise

    def send_file(self, file_path):
        """Send file with retry logic and progress tracking"""
        for attempt in range(self.max_retries):
            try:
                return self._send_file_attempt(file_path, attempt + 1)
            except (ConnectionError, socket.timeout, socket.error) as e:
                self.logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed: {e}")
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    self.update_status(f"Connection failed. Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    self.logger.error(f"All {self.max_retries} attempts failed")
                    messagebox.showerror("Transfer Failed", 
                                       f"Failed after {self.max_retries} attempts.\n{str(e)}")
                    return False
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}", exc_info=True)
                messagebox.showerror("Error", str(e))
                return False
        
        return False
    
    def _send_file_attempt(self, file_path, attempt_num):
        """Single attempt to send a file"""
        start_time = time.time()
        
        try:
            # Validate file
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                raise ValueError("Cannot send empty file")
            
            self.update_status(f"[Attempt {attempt_num}] Preparing {os.path.basename(file_path)} ({file_size / 1024 / 1024:.2f} MB)...")
            self.update_progress(0, "Reading file...")

            # Encrypt file and get original data
            encrypted_data, original_data, is_compressed = self.encrypt_file(file_path)
            
            # Calculate checksum of original data
            checksum = self.calculate_checksum(original_data)
            self.logger.info(f"File checksum: {checksum}")

            self.update_progress(20, "Encrypted")
            
            # Create socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                # Get server host from entry
                server_host = self.host_entry.get().strip()
                if not server_host or server_host == "Discovering...":
                    raise ValueError("Please specify a server host")

                # Connect to server
                self.update_progress(30, "Connecting...")
                client_socket.settimeout(self.connection_timeout)
                client_socket.connect((server_host, self.port))
                self.logger.info(f"Connected to server at {server_host}:{self.port}")

                # Prepare filename
                filename = os.path.basename(file_path)
                filename_bytes = filename.encode('utf-8')

                # Send filename length
                client_socket.send(len(filename_bytes).to_bytes(4, byteorder='big'))
                
                # Send filename
                client_socket.send(filename_bytes)

                # Send file size
                client_socket.send(len(encrypted_data).to_bytes(8, byteorder='big'))
                
                # Send compression flag
                client_socket.send(bytes([1 if is_compressed else 0]))
                
                # Send checksum length
                checksum_bytes = checksum.encode('utf-8')
                client_socket.send(len(checksum_bytes).to_bytes(4, byteorder='big'))
                
                # Send checksum
                client_socket.send(checksum_bytes)

                # Send encrypted file data in chunks with progress
                self.update_progress(40, "Sending...")
                bytes_sent = 0
                total_bytes = len(encrypted_data)
                
                while bytes_sent < total_bytes:
                    chunk_end = min(bytes_sent + self.buffer_size, total_bytes)
                    chunk = encrypted_data[bytes_sent:chunk_end]
                    client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                    
                    # Update progress
                    progress = 40 + int(50 * bytes_sent / total_bytes)
                    self.update_progress(progress, f"Sending {bytes_sent / 1024 / 1024:.1f}/{total_bytes / 1024 / 1024:.1f} MB")

                self.update_progress(90, "Waiting for confirmation...")

                # Receive server response
                client_socket.settimeout(30)
                response = client_socket.recv(7)
                
                if response == b"SUCCESS":
                    elapsed_time = time.time() - start_time
                    speed_mbps = (file_size / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
                    
                    self.update_progress(100, "Complete!")
                    self.logger.info(f"File {filename} sent successfully in {elapsed_time:.2f}s ({speed_mbps:.2f} MB/s)")
                    self.update_status(f"SUCCESS: {filename} ({file_size / 1024 / 1024:.2f} MB) sent at {speed_mbps:.2f} MB/s")
                    messagebox.showinfo("Success", f"File sent successfully!\n\nFile: {filename}\nSize: {file_size / 1024 / 1024:.2f} MB\nSpeed: {speed_mbps:.2f} MB/s\nTime: {elapsed_time:.2f}s")
                    return True
                else:
                    raise ValueError("Server rejected the file")

        except FileNotFoundError as fnf:
            self.logger.error(f"File not found: {fnf}")
            raise
        except ValueError as ve:
            self.logger.error(f"Validation error: {ve}")
            raise
        except socket.timeout:
            self.logger.error("Connection timeout")
            raise ConnectionError("Connection timeout - server not responding")
        except socket.error as se:
            self.logger.error(f"Socket error: {se}")
            raise ConnectionError(f"Network error: {se}")
        except Exception as e:
            self.logger.error(f"Send file error: {e}", exc_info=True)
            raise
        finally:
            self.update_progress(0, "")
    
    def update_progress(self, value, text=""):
        """Update progress bar and label"""
        self.progress_var.set(value)
        self.progress_label.config(text=text)
        self.root.update_idletasks()

    def select_file(self):
        """Open file dialog and send selected file in background thread"""
        file_path = filedialog.askopenfilename(
            title="Select File to Send",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("Images", "*.png *.jpg *.jpeg *.gif"),
                ("Documents", "*.pdf *.doc *.docx"),
            ]
        )
        if file_path:
            # Run transfer in background thread to keep GUI responsive
            transfer_thread = threading.Thread(
                target=self.send_file,
                args=(file_path,),
                daemon=True
            )
            transfer_thread.start()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    client = FileTransferClient()
    client.run()