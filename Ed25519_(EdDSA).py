import os
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import json


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Generate a new Ed25519 key pair
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key: Ed25519PrivateKey, filename: str, password: str = None):
    """
    Save private key to a file
    
    Args:
        private_key: The Ed25519 private key
        filename: File path to save to
        password: Optional password to encrypt the key
    """
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key(filename: str, password: str = None) -> Ed25519PrivateKey:
    """
    Load private key from a file
    
    Args:
        filename: File path to load from
        password: Password if the key is encrypted
    
    Returns:
        Ed25519PrivateKey object
    """
    with open(filename, 'rb') as f:
        pem = f.read()
    
    pwd = password.encode() if password else None
    return serialization.load_pem_private_key(pem, password=pwd)


def save_public_key(public_key: Ed25519PublicKey, filename: str):
    """
    Save public key to a file
    
    Args:
        public_key: The Ed25519 public key
        filename: File path to save to
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)


def load_public_key(filename: str) -> Ed25519PublicKey:
    """
    Load public key from a file
    
    Args:
        filename: File path to load from
    
    Returns:
        Ed25519PublicKey object
    """
    with open(filename, 'rb') as f:
        pem = f.read()
    
    return serialization.load_pem_public_key(pem)


def sign_message(message: str, private_key: Ed25519PrivateKey) -> bytes:
    """
    Sign a message using Ed25519 private key
    
    Args:
        message: The message to sign
        private_key: Ed25519 private key
    
    Returns:
        Signature bytes (64 bytes for Ed25519)
    """
    return private_key.sign(message.encode())


def verify_signature(message: str, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """
    Verify a signature using Ed25519 public key
    
    Args:
        message: The original message
        signature: The signature to verify
        public_key: Ed25519 public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(signature, message.encode())
        return True
    except InvalidSignature:
        return False


def export_keys_as_base64(private_key: Ed25519PrivateKey) -> dict:
    """
    Export keys as base64 strings for display
    
    Returns:
        Dictionary with base64-encoded private and public keys
    """
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return {
        'private_key': base64.b64encode(private_bytes).decode(),
        'public_key': base64.b64encode(public_bytes).decode()
    }


def import_private_key_from_base64(private_key_b64: str) -> Ed25519PrivateKey:
    """
    Import private key from base64 string
    """
    private_bytes = base64.b64decode(private_key_b64)
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def import_public_key_from_base64(public_key_b64: str) -> Ed25519PublicKey:
    """
    Import public key from base64 string
    """
    public_bytes = base64.b64decode(public_key_b64)
    return Ed25519PublicKey.from_public_bytes(public_bytes)


def create_signed_message(message: str, signature: bytes) -> str:
    """
    Create a JSON structure containing message and signature
    """
    data = {
        'message': message,
        'signature': base64.b64encode(signature).decode()
    }
    return json.dumps(data, indent=2)


def parse_signed_message(signed_data: str) -> tuple[str, bytes]:
    """
    Parse JSON structure to extract message and signature
    """
    data = json.loads(signed_data)
    message = data['message']
    signature = base64.b64decode(data['signature'])
    return message, signature


def main():
    """Main interactive loop"""
    print("=" * 70)
    print("Ed25519 (EdDSA) Digital Signature Tool")
    print("=" * 70)
    print("\nEd25519 is an asymmetric (public-key) cryptography algorithm.")
    print("• Private key: Used to SIGN messages (keep secret!)")
    print("• Public key: Used to VERIFY signatures (share freely)")
    print()
    
    current_private_key = None
    current_public_key = None
    
    while True:
        print("\n" + "=" * 70)
        print("Main Menu")
        print("=" * 70)
        print("\nKey Management:")
        print("1. Generate new key pair")
        print("2. Save current keys to files")
        print("3. Load private key from file")
        print("4. Load public key from file")
        print("5. Display current keys (base64)")
        print("6. Import private key from base64")
        print("7. Import public key from base64")
        
        print("\nSigning Operations:")
        print("8. Sign a message")
        print("9. Verify a signature")
        
        print("\nOther:")
        print("10. Exit")
        
        choice = input("\nEnter your choice (1-10): ").strip()
        
        if choice == "1":
            print("\n--- GENERATE NEW KEY PAIR ---")
            current_private_key, current_public_key = generate_keypair()
            print("✓ New Ed25519 key pair generated successfully!")
            print(f"  Private key: 32 bytes (keep this SECRET!)")
            print(f"  Public key: 32 bytes (safe to share)")
        
        elif choice == "2":
            if not current_private_key:
                print("\n✗ No key pair loaded. Generate or load keys first.")
                continue
            
            print("\n--- SAVE KEYS TO FILES ---")
            private_file = input("Enter filename for private key (e.g., private.pem): ").strip()
            public_file = input("Enter filename for public key (e.g., public.pem): ").strip()
            
            use_password = input("Encrypt private key with password? (y/n): ").strip().lower()
            password = None
            if use_password == 'y':
                import getpass
                password = getpass.getpass("Enter password: ")
            
            try:
                save_private_key(current_private_key, private_file, password)
                save_public_key(current_public_key, public_file)
                print(f"\n✓ Keys saved successfully!")
                print(f"  Private key: {private_file}")
                print(f"  Public key: {public_file}")
            except Exception as e:
                print(f"\n✗ Error saving keys: {e}")
        
        elif choice == "3":
            print("\n--- LOAD PRIVATE KEY ---")
            filename = input("Enter private key filename: ").strip()
            
            try:
                has_password = input("Is the key encrypted? (y/n): ").strip().lower()
                password = None
                if has_password == 'y':
                    import getpass
                    password = getpass.getpass("Enter password: ")
                
                current_private_key = load_private_key(filename, password)
                current_public_key = current_private_key.public_key()
                print("✓ Private key loaded successfully!")
            except Exception as e:
                print(f"✗ Error loading private key: {e}")
        
        elif choice == "4":
            print("\n--- LOAD PUBLIC KEY ---")
            filename = input("Enter public key filename: ").strip()
            
            try:
                current_public_key = load_public_key(filename)
                print("✓ Public key loaded successfully!")
                print("  (Note: You can only verify signatures with just the public key)")
            except Exception as e:
                print(f"✗ Error loading public key: {e}")
        
        elif choice == "5":
            print("\n--- DISPLAY KEYS ---")
            if current_private_key:
                keys = export_keys_as_base64(current_private_key)
                print("\nPrivate Key (base64) - KEEP SECRET:")
                print("-" * 70)
                print(keys['private_key'])
                print("-" * 70)
                print("\nPublic Key (base64) - Safe to share:")
                print("-" * 70)
                print(keys['public_key'])
                print("-" * 70)
            elif current_public_key:
                public_bytes = current_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                print("\nPublic Key (base64):")
                print("-" * 70)
                print(base64.b64encode(public_bytes).decode())
                print("-" * 70)
            else:
                print("✗ No keys loaded.")
        
        elif choice == "6":
            print("\n--- IMPORT PRIVATE KEY FROM BASE64 ---")
            private_key_b64 = input("Enter base64-encoded private key: ").strip()
            
            try:
                current_private_key = import_private_key_from_base64(private_key_b64)
                current_public_key = current_private_key.public_key()
                print("✓ Private key imported successfully!")
            except Exception as e:
                print(f"✗ Error importing private key: {e}")
        
        elif choice == "7":
            print("\n--- IMPORT PUBLIC KEY FROM BASE64 ---")
            public_key_b64 = input("Enter base64-encoded public key: ").strip()
            
            try:
                current_public_key = import_public_key_from_base64(public_key_b64)
                print("✓ Public key imported successfully!")
            except Exception as e:
                print(f"✗ Error importing public key: {e}")
        
        elif choice == "8":
            if not current_private_key:
                print("\n✗ No private key loaded. Generate or load a private key first.")
                continue
            
            print("\n--- SIGN A MESSAGE ---")
            message = input("Enter the message to sign: ")
            
            try:
                signature = sign_message(message, current_private_key)
                signed_data = create_signed_message(message, signature)
                
                print("\n✓ Message signed successfully!")
                print("\nSigned Message (JSON format - copy everything below):")
                print("=" * 70)
                print(signed_data)
                print("=" * 70)
                print("\nSignature (base64):")
                print(base64.b64encode(signature).decode())
            except Exception as e:
                print(f"✗ Error signing message: {e}")
        
        elif choice == "9":
            if not current_public_key:
                print("\n✗ No public key loaded. Generate, load, or import a public key first.")
                continue
            
            print("\n--- VERIFY A SIGNATURE ---")
            print("\nInput format:")
            print("1. Paste signed JSON message (from signing operation)")
            print("2. Enter message and signature separately")
            
            format_choice = input("\nChoose input format (1-2): ").strip()
            
            try:
                if format_choice == "1":
                    print("\nPaste the signed JSON message (press Enter twice when done):")
                    lines = []
                    while True:
                        line = input()
                        if line == "" and lines:
                            break
                        lines.append(line)
                    signed_data = '\n'.join(lines)
                    message, signature = parse_signed_message(signed_data)
                
                elif format_choice == "2":
                    message = input("Enter the original message: ")
                    sig_b64 = input("Enter the signature (base64): ").strip()
                    signature = base64.b64decode(sig_b64)
                
                else:
                    print("Invalid choice")
                    continue
                
                is_valid = verify_signature(message, signature, current_public_key)
                
                if is_valid:
                    print("\n" + "=" * 70)
                    print("✓ SIGNATURE VALID")
                    print("=" * 70)
                    print("The signature is authentic and the message has not been altered.")
                else:
                    print("\n" + "=" * 70)
                    print("✗ SIGNATURE INVALID")
                    print("=" * 70)
                    print("The signature is NOT valid. The message may have been:")
                    print("  • Altered/tampered with")
                    print("  • Signed with a different key")
                    print("  • Corrupted during transmission")
            
            except Exception as e:
                print(f"✗ Error verifying signature: {e}")
        
        elif choice == "10":
            print("\nGoodbye!")
            break
        
        else:
            print("\n✗ Invalid choice. Please enter 1-10.")


if __name__ == "__main__":
    main()
