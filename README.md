# B.O.T-FTP

A secure file transfer application with encrypted transmission and integrity verification.

## Features

- Encrypted File Transfer: All files are encrypted using Fernet symmetric encryption before transmission
- Data Compression: Automatic compression before encryption for faster transfers
- Integrity Verification: SHA-256 checksums ensure files are received without corruption
- Automatic Retry: Failed transfers automatically retry with exponential backoff
- Progress Tracking: Real-time progress bar showing transfer status and speed
- Filename Sanitization: Protection against directory traversal attacks
- File Size Limits: Configurable maximum file size to prevent disk filling
- Disk Space Checking: Verifies available space before accepting files
- Automatic Server Discovery: Client automatically scans the local network to find the server
- GUI Interface: User-friendly graphical interfaces with responsive design
- Comprehensive Logging: Rotating log files with detailed operation tracking
- Multi-threaded Server: Handle multiple client connections simultaneously
- Error Handling: Specific error messages with detailed troubleshooting information
- Duplicate Handling: Automatic file renaming to prevent overwrites
- Configurable Settings: JSON configuration file for easy customization
- Cross-platform: Works on Windows, macOS, and Linux

## Installation

1. Clone the repository:
```bash
git clone https://github.com/vinayakawac/B.O.T-FTP.git
cd B.O.T-FTP
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The application uses a `config.json` file for configuration. Default settings:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 5000,
    "buffer_size": 65536,
    "save_path": "received_files",
    "max_connections": 10,
    "max_file_size_mb": 500,
    "chunk_size": 8192
  },
  "client": {
    "port": 5000,
    "buffer_size": 65536,
    "connection_timeout": 30,
    "scan_timeout": 0.1,
    "max_retries": 3,
    "retry_delay": 2,
    "chunk_size": 8192
  },
  "transfer": {
    "enable_compression": true,
    "compression_level": 6,
    "show_progress": true
  },
  "security": {
    "encryption_key": "SecureFileTransfer2024_LongKey32Bytes!"
  },
  "logging": {
    "level": "INFO",
    "file": "file_transfer.log",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "max_bytes": 10485760,
    "backup_count": 5
  }
}
```

Configuration Options:
- `buffer_size`: Network buffer size in bytes (larger = faster for big files)
- `max_file_size_mb`: Maximum file size accepted by server in megabytes
- `max_connections`: Maximum simultaneous client connections
- `connection_timeout`: Socket timeout in seconds
- `max_retries`: Number of retry attempts for failed transfers
- `retry_delay`: Initial delay between retries (uses exponential backoff)
- `enable_compression`: Compress files before encryption for speed
- `compression_level`: Compression level 1-9 (higher = better compression, slower)
- `max_bytes`: Maximum log file size before rotation
- `backup_count`: Number of backup log files to keep

Important: Change the encryption key in production environments for security. Both client and server must use the same encryption key to communicate.

## Usage

### Using the Main Launcher

Run the main application to choose between client and server:

```bash
python main.py
```

This will open a GUI with buttons to start either the client or server.

### Running Server Directly

Start the server to receive files:

```bash
python server.py
```

The server will:
- Listen on the configured port (default: 5000)
- Display connection status and file transfer progress
- Save received files to the `received_files` directory
- Verify file integrity using SHA-256 checksums
- Log all operations to `file_transfer.log`

### Running Client Directly

Start the client to send files:

```bash
python client.py
```

The client will:
- Automatically discover servers on the local network
- Allow manual server IP entry if discovery fails
- Compress files for faster transfer (if beneficial)
- Encrypt files before transmission
- Calculate and send SHA-256 checksums
- Show real-time progress bar with transfer speed
- Automatically retry failed transfers up to 3 times
- Display detailed transfer statistics

## Security Features

1. **Encryption**: Files are encrypted using Fernet (AES-128 in CBC mode) before transmission
2. **Integrity Checking**: SHA-256 checksums verify that files haven't been corrupted or tampered with
3. **Secure Key Exchange**: Both client and server use the same encryption key (configure securely)

## File Structure

```
B.O.T-FTP/
├── main.py              # Main launcher GUI
├── server.py            # File transfer server
├── client.py            # File transfer client
├── config.json          # Configuration file
├── requirements.txt     # Python dependencies
├── README.md           # Documentation
├── LICENSE             # License file
└── received_files/     # Directory for received files
```

## Logging

All operations are logged to `file_transfer.log` with automatic rotation (max 10 MB per file, 5 backups). Logs include:
- Server start/stop events
- Client connections and disconnections
- File transfer progress with speed metrics
- Compression ratios and statistics
- Encryption/decryption operations
- Checksum verification results
- Retry attempts and outcomes
- Detailed error messages with stack traces
- Security events (sanitization, file size validation)

## Troubleshooting

Server not discovered automatically:
- Ensure both client and server are on the same network
- Manually enter the server IP address in the client GUI
- Check firewall settings allow connections on the configured port (default: 5000)
- Verify no other service is using the same port

File transfer fails:
- Verify encryption keys match exactly on client and server in config.json
- Check network connectivity between client and server
- Review logs in file_transfer.log for detailed error messages
- Ensure server is running before starting the client

Checksum verification errors:
- This indicates data corruption during transfer or encryption/decryption mismatch
- Verify both client and server are using the same encryption key
- Check network stability
- Try disabling compression in config.json

Permission errors:
- Ensure the server has write permissions to the received_files directory
- Check that the client has read permissions for files being sent
- On Linux/macOS, verify directory permissions with: ls -la

File too large error:
- Check max_file_size_mb in server configuration
- Increase the limit if you need to transfer larger files
- Default limit is 500 MB

Transfer keeps retrying:
- Check network connectivity
- Verify server is running and accessible
- Look at file_transfer.log for specific error messages
- Increase connection_timeout if network is slow

Compression errors:
- Some files may not compress well (already compressed formats)
- Set enable_compression to false in config.json to disable
- Check compression_level (1-9) if compression is too slow

GUI does not appear:
- This application requires a graphical environment
- For headless servers, the GUI cannot be displayed
- Use X11 forwarding if connecting via SSH: ssh -X user@host

Disk space errors:
- Server checks available space before accepting files
- Free up space in the received_files directory
- Or change save_path in configuration to a drive with more space

## License

This project is licensed under the terms specified in the LICENSE file.