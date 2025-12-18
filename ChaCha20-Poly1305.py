import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import getpass


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from a password using PBKDF2
    
    Args:
        password: User-provided password
        salt: Random salt for key derivation
    
    Returns:
        32-byte key suitable for ChaCha20-Poly1305
    """
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


def encrypt_message(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a message using ChaCha20-Poly1305
    
    Args:
        plaintext: The message to encrypt
        key: 32-byte encryption key
    
    Returns:
        Tuple of (nonce, ciphertext) where ciphertext includes the authentication tag
    """
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)  # ChaCha20-Poly1305 uses 96-bit nonces
    ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt a message using ChaCha20-Poly1305
    
    Args:
        nonce: The nonce used during encryption
        ciphertext: The encrypted message with authentication tag
        key: 32-byte decryption key
    
    Returns:
        The decrypted plaintext message
    
    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def encode_for_storage(salt: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """
    Encode encrypted data for easy storage/transmission
    
    Format: base64(salt) + ':' + base64(nonce) + ':' + base64(ciphertext)
    """
    salt_b64 = base64.b64encode(salt).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return f"{salt_b64}:{nonce_b64}:{ciphertext_b64}"


def decode_from_storage(encoded: str) -> tuple[bytes, bytes, bytes]:
    """
    Decode encrypted data from storage format
    
    Returns:
        Tuple of (salt, nonce, ciphertext)
    """
    parts = encoded.split(':')
    if len(parts) != 3:
        raise ValueError("Invalid encrypted data format")
    
    salt = base64.b64decode(parts[0])
    nonce = base64.b64decode(parts[1])
    ciphertext = base64.b64decode(parts[2])
    return salt, nonce, ciphertext


def main():
    """Main interactive loop"""
    print("=" * 60)
    print("ChaCha20-Poly1305 Encryption/Decryption Tool")
    print("=" * 60)
    print()
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            # Encryption mode
            print("\n--- ENCRYPTION MODE ---")
            plaintext = input("Enter the message to encrypt: ")
            
            print("\nKey Options:")
            print("1. Use a password (recommended)")
            print("2. Provide a hex key directly (32 bytes / 64 hex characters)")
            key_choice = input("Choose key option (1-2): ").strip()
            
            if key_choice == "1":
                password = getpass.getpass("Enter password: ")
                salt = os.urandom(16)
                key = derive_key_from_password(password, salt)
            elif key_choice == "2":
                hex_key = input("Enter 64-character hex key: ").strip()
                if len(hex_key) != 64:
                    print("Error: Key must be exactly 64 hex characters (32 bytes)")
                    continue
                try:
                    key = bytes.fromhex(hex_key)
                    salt = b'\x00' * 16  # Dummy salt when using direct key
                except ValueError:
                    print("Error: Invalid hex key")
                    continue
            else:
                print("Invalid choice")
                continue
            
            try:
                nonce, ciphertext = encrypt_message(plaintext, key)
                encoded = encode_for_storage(salt, nonce, ciphertext)
                
                print("\n✓ Encryption successful!")
                print("\nEncrypted data (save this):")
                print("-" * 60)
                print(encoded)
                print("-" * 60)
                
            except Exception as e:
                print(f"\n✗ Encryption failed: {e}")
        
        elif choice == "2":
            # Decryption mode
            print("\n--- DECRYPTION MODE ---")
            encoded = input("Enter the encrypted data: ").strip()
            
            try:
                salt, nonce, ciphertext = decode_from_storage(encoded)
                
                # Check if a real salt was used
                if salt == b'\x00' * 16:
                    hex_key = input("Enter 64-character hex key: ").strip()
                    if len(hex_key) != 64:
                        print("Error: Key must be exactly 64 hex characters")
                        continue
                    key = bytes.fromhex(hex_key)
                else:
                    password = getpass.getpass("Enter password: ")
                    key = derive_key_from_password(password, salt)
                
                plaintext = decrypt_message(nonce, ciphertext, key)
                
                print("\n✓ Decryption successful!")
                print("\nDecrypted message:")
                print("-" * 60)
                print(plaintext)
                print("-" * 60)
                
            except ValueError as e:
                print(f"\n✗ Invalid encrypted data format: {e}")
            except Exception as e:
                print(f"\n✗ Decryption failed: {e}")
                print("This could mean:")
                print("  - Wrong password/key")
                print("  - Corrupted encrypted data")
                print("  - Data has been tampered with")
        
        elif choice == "3":
            print("\nGoodbye!")
            break
        
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
