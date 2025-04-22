from cryptography.fernet import Fernet

def generate_key():
    """
    Generate a secure random encryption key for Fernet symmetric encryption
    
    Returns:
        bytes: Generated encryption key
    """
    return Fernet.generate_key()

def encrypt_message(message: str, key: bytes) -> str:
    """
    Encrypt a message using Fernet symmetric encryption
    
    Args:
        message (str): Message to encrypt
        key (bytes): Encryption key generated with generate_key()
        
    Returns:
        str: Encrypted message as a base64-encoded string
    """
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(token: str, key: bytes) -> str:
    """
    Decrypt a message using Fernet symmetric encryption
    
    Args:
        token (str): Encrypted message as a base64-encoded string
        key (bytes): Encryption key used for encryption
        
    Returns:
        str: Decrypted message
        
    Raises:
        cryptography.fernet.InvalidToken: If the token is invalid or key is incorrect
    """
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()
