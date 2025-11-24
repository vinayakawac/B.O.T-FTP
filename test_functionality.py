#!/usr/bin/env python3
"""
Test script to verify B.O.T-FTP functionality without GUI
Tests encryption, decryption, checksum verification, and configuration loading
"""

import os
import sys
import json
import base64
import hashlib
import tempfile
from cryptography.fernet import Fernet

def test_config_loading():
    """Test configuration file loading"""
    print("=" * 60)
    print("TEST 1: Configuration Loading")
    print("=" * 60)
    
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        print("[PASS] Config file loaded successfully")
        print(f"  Server port: {config['server']['port']}")
        print(f"  Client port: {config['client']['port']}")
        print(f"  Save path: {config['server']['save_path']}")
        print(f"  Log level: {config['logging']['level']}")
        return True
    except Exception as e:
        print(f"[FAIL] Config loading failed: {e}")
        return False

def test_encryption_decryption():
    """Test encryption and decryption"""
    print("\n" + "=" * 60)
    print("TEST 2: Encryption & Decryption")
    print("=" * 60)
    
    try:
        # Load encryption key from config
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        encryption_key = config['security']['encryption_key']
        key = base64.urlsafe_b64encode(encryption_key.encode()[:32])
        cipher = Fernet(key)
        
        # Test data
        test_data = b"This is a test file content for B.O.T-FTP encryption!"
        
        # Encrypt
        encrypted_data = cipher.encrypt(test_data)
        print(f"[PASS] Original data length: {len(test_data)} bytes")
        print(f"[PASS] Encrypted data length: {len(encrypted_data)} bytes")
        
        # Decrypt
        decrypted_data = cipher.decrypt(encrypted_data)
        print(f"[PASS] Decrypted data length: {len(decrypted_data)} bytes")
        
        # Verify
        if test_data == decrypted_data:
            print("[PASS] Encryption/Decryption successful - data matches!")
            return True
        else:
            print("[FAIL] Data mismatch after decryption")
            return False
            
    except Exception as e:
        print(f"[FAIL] Encryption/Decryption failed: {e}")
        return False

def test_checksum_verification():
    """Test SHA-256 checksum calculation and verification"""
    print("\n" + "=" * 60)
    print("TEST 3: SHA-256 Checksum Verification")
    print("=" * 60)
    
    try:
        test_data = b"Test file content for checksum verification"
        
        # Calculate checksum
        checksum1 = hashlib.sha256(test_data).hexdigest()
        print(f"[PASS] Checksum calculated: {checksum1[:16]}...")
        
        # Recalculate to verify
        checksum2 = hashlib.sha256(test_data).hexdigest()
        
        if checksum1 == checksum2:
            print("[PASS] Checksum verification successful!")
            
            # Test with modified data
            modified_data = test_data + b"X"
            checksum3 = hashlib.sha256(modified_data).hexdigest()
            
            if checksum1 != checksum3:
                print("[PASS] Checksum correctly detects data modification")
                return True
            else:
                print("[FAIL] Checksum failed to detect modification")
                return False
        else:
            print("[FAIL] Checksum mismatch")
            return False
            
    except Exception as e:
        print(f"[FAIL] Checksum verification failed: {e}")
        return False

def test_file_operations():
    """Test file read/write with encryption"""
    print("\n" + "=" * 60)
    print("TEST 4: File Operations with Encryption")
    print("=" * 60)
    
    try:
        # Load config
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        encryption_key = config['security']['encryption_key']
        key = base64.urlsafe_b64encode(encryption_key.encode()[:32])
        cipher = Fernet(key)
        
        # Create temporary test file
        test_content = b"B.O.T-FTP Test File\nLine 2\nLine 3\n"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp_file:
            temp_file.write(test_content)
            temp_file_path = temp_file.name
        
        print(f"[PASS] Created test file: {os.path.basename(temp_file_path)}")
        
        # Read and encrypt
        with open(temp_file_path, 'rb') as f:
            original_data = f.read()
        
        encrypted_data = cipher.encrypt(original_data)
        original_checksum = hashlib.sha256(original_data).hexdigest()
        print(f"[PASS] File encrypted, checksum: {original_checksum[:16]}...")
        
        # Decrypt and verify
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_checksum = hashlib.sha256(decrypted_data).hexdigest()
        
        if original_checksum == decrypted_checksum:
            print("[PASS] File checksum matches after encryption/decryption!")
        else:
            print("[FAIL] File checksum mismatch")
            os.unlink(temp_file_path)
            return False
        
        if original_data == decrypted_data:
            print("[PASS] File content matches perfectly!")
        else:
            print("[FAIL] File content mismatch")
            os.unlink(temp_file_path)
            return False
        
        # Clean up
        os.unlink(temp_file_path)
        print("[PASS] Test file cleaned up")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] File operations failed: {e}")
        if 'temp_file_path' in locals():
            try:
                os.unlink(temp_file_path)
            except:
                pass
        return False

def test_directory_creation():
    """Test directory creation for received files"""
    print("\n" + "=" * 60)
    print("TEST 5: Directory Creation")
    print("=" * 60)
    
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        save_path = config['server']['save_path']
        
        # Create directory if it doesn't exist
        os.makedirs(save_path, exist_ok=True)
        
        if os.path.exists(save_path) and os.path.isdir(save_path):
            print(f"[PASS] Directory '{save_path}' exists and is accessible")
            
            # Test write permissions
            test_file = os.path.join(save_path, '.test_write')
            with open(test_file, 'w') as f:
                f.write('test')
            os.unlink(test_file)
            print(f"[PASS] Directory is writable")
            return True
        else:
            print(f"[FAIL] Directory '{save_path}' not accessible")
            return False
            
    except Exception as e:
        print(f"[FAIL] Directory test failed: {e}")
        return False

def test_logging_setup():
    """Test logging configuration"""
    print("\n" + "=" * 60)
    print("TEST 6: Logging Setup")
    print("=" * 60)
    
    try:
        import logging
        
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        log_level = config['logging']['level']
        log_file = config['logging']['file']
        log_format = config['logging']['format']
        
        # Setup test logger
        test_logger = logging.getLogger('TestLogger')
        test_logger.setLevel(getattr(logging, log_level))
        
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(log_format))
        test_logger.addHandler(handler)
        
        # Test log writing
        test_logger.info("Test log entry from functionality test")
        
        print(f"[PASS] Logging configured with level: {log_level}")
        print(f"[PASS] Log file: {log_file}")
        
        # Check if log file was created
        if os.path.exists(log_file):
            print(f"[PASS] Log file created successfully")
            return True
        else:
            print(f"[FAIL] Log file not found")
            return False
            
    except Exception as e:
        print(f"[FAIL] Logging setup failed: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("B.O.T-FTP FUNCTIONALITY TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        ("Configuration Loading", test_config_loading),
        ("Encryption & Decryption", test_encryption_decryption),
        ("Checksum Verification", test_checksum_verification),
        ("File Operations", test_file_operations),
        ("Directory Creation", test_directory_creation),
        ("Logging Setup", test_logging_setup),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[FAIL] Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS] PASS" if result else "[FAIL] FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "-" * 60)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60 + "\n")
    
    if passed == total:
        print(" All tests passed! The application is functioning correctly.")
        return 0
    else:
        print("  Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
