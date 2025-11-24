# B.O.T-FTP

A secure file transfer application with encrypted transmission and integrity verification.

## Features

- Encrypted File Transfer: All files are encrypted using Fernet symmetric encryption before transmission
- Integrity Verification: SHA-256 checksums ensure files are received without corruption
- Automatic Server Discovery: Client automatically scans the local network to find the server
- GUI Interface: User-friendly graphical interfaces for both client and server
- Comprehensive Logging: Detailed logging of all file transfer operations to both file and console
- Multi-threaded Server: Handle multiple client connections simultaneously
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
    "buffer_size": 4096,
    "save_path": "received_files",
    "max_connections": 5
  },
  "client": {
    "port": 5000,
    "buffer_size": 4096,
    "connection_timeout": 10,
    "scan_timeout": 0.1
  },
  "security": {
    "encryption_key": "SecureFileTransfer2024_LongKey32Bytes!"
  },
  "logging": {
    "level": "INFO",
    "file": "file_transfer.log",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  }
}
```

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
- Encrypt files before transmission
- Calculate and send SHA-256 checksums
- Display transfer status and confirmation

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

All operations are logged to `file_transfer.log` with configurable log levels. Logs include:
- Server start/stop events
- Client connections and disconnections
- File transfer progress
- Encryption/decryption operations
- Checksum verification results
- Errors and warnings

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

Permission errors:
- Ensure the server has write permissions to the received_files directory
- Check that the client has read permissions for files being sent
- On Linux/macOS, verify directory permissions with: ls -la

GUI does not appear:
- This application requires a graphical environment
- For headless servers, the GUI cannot be displayed
- Use X11 forwarding if connecting via SSH: ssh -X user@host

## License

This project is licensed under the terms specified in the LICENSE file.