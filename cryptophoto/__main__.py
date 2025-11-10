from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

class AESFileCrypt:
    def __init__(self, key=None, password=None):
        """
        Initializes the encryptor with AES-256 key.
        
        Args:
            key (bytes, optional): 32-byte key. If None, generates a new one.
            password (str, optional): Password to derive key from
        """
        if password is not None:
            # Deriva uma chave de 32 bytes da senha usando PBKDF2
            salt = b'fixed_salt_1234'  # Em produção, use um salt aleatório
            self.key = PBKDF2(password, salt, dkLen=32)
        elif key is None:
            self.key = get_random_bytes(32)
        elif len(key) == 32:
            self.key = key
        else:
            raise ValueError("Key must be 32 bytes for AES-256")
    
    def encrypt(self, input_path, output_path):
        """
        Encrypts a file using AES-256 CBC.
        
        Args:
            input_path (str): Path to the original file
            output_path (str): Path to save the encrypted file
        
        Returns:
            bytes: IV used for encryption
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        # Read file data
        with open(input_path, 'rb') as f:
            file_data = f.read()
        
        # Generate IV and create cipher
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Encrypt with padding
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        
        # Save IV + encrypted data
        with open(output_path, 'wb') as f:
            f.write(iv + encrypted_data)
        
        return iv
    
    def decrypt(self, input_path, output_path):
        """
        Decrypts an encrypted file.
        
        Args:
            input_path (str): Path to the encrypted file
            output_path (str): Path to save the decrypted file
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        # Read encrypted file
        with open(input_path, 'rb') as f:
            data = f.read()
        
        # Extract IV (16 bytes) and encrypted data
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
    
    def get_key(self):
        """
        Returns the encryption key.
        
        Returns:
            bytes: AES-256 key
        """
        return self.key
    
    def save_key(self, key_path):
        """
        Saves the key to a file.
        
        Args:
            key_path (str): Path to save the key
        """
        with open(key_path, 'wb') as f:
            f.write(self.key)
    
    @classmethod
    def load_from_keyfile(cls, key_path):
        """
        Creates instance by loading key from file.
        
        Args:
            key_path (str): Path to the key file
        
        Returns:
            AESFileCrypt: Instance with loaded key
        """
        with open(key_path, 'rb') as f:
            key = f.read()
        return cls(key=key)

    @classmethod
    def create_with_password(cls, password):
        """
        Creates a new instance with a password-derived key.
        
        Args:
            password (str): Password to derive key from
        
        Returns:
            AESFileCrypt: New instance with password-derived key
        """
        return cls(password=password)

    @classmethod
    def create_with_new_key(cls):
        """
        Creates a new instance with a randomly generated key.
        
        Returns:
            AESFileCrypt: New instance with random key
        """
        return cls()