from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os


class AES256:
    """
    AES-256 encryption/decryption handler supporting both random keys and
    password-derived keys using PBKDF2.

    Args:
        key (bytes, optional): 32-byte AES key. Must be exactly 32 bytes.
        password (str, optional): Password for deriving the key using PBKDF2.
        salt (bytes, optional): Optional salt for PBKDF2. If omitted, a random
            16-byte salt will be generated.

    Raises:
        ValueError: If key length is invalid.
    """
    def __init__(self, key=None, password=None, salt=None):
        if password is not None:
            # Store password for later use in decryption
            self.password = password
            # Use provided salt or generate a random one
            if salt is None:
                salt = get_random_bytes(16)
            self.salt = salt
            # Derive 32-byte key from password using PBKDF2
            self.key = PBKDF2(password, salt, dkLen=32, count=100000)
            
        elif key is None:
            self.key = get_random_bytes(32)
            self.salt = None
            self.password = None
        elif len(key) == 32:
            self.key = key
            self.salt = None
            self.password = None
        else:
            raise ValueError("Key must be 32 bytes for AES-256")
    
    def encrypt_file(self, input_path, output_path=None):
        """
        Encrypts a single file using AES-256 CBC mode.

        Args:
            input_path (str): Path to the file to encrypt.
            output_path (str, optional): Output encrypted file path. If None,
                appends '.enc' to the original filename.

        Returns:
            dict: Metadata about the encryption, including:
                - iv (bytes): Initialization vector used.
                - salt (bytes or None): Salt used (if password-based).
                - input_file (str): Original file path.
                - output_file (str): Encrypted file path.

        Raises:
            FileNotFoundError: If the input file does not exist.
        """

        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        if output_path is None:
            output_path = input_path + '.enc'
        
        # Read file data
        with open(input_path, 'rb') as f:
            file_data = f.read()
        
        # Generate IV and create cipher
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Encrypt with padding
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        
        # Save salt (if password-based) + IV + encrypted data
        with open(output_path, 'wb') as f:
            if self.salt is not None:
                f.write(len(self.salt).to_bytes(4, 'big'))  # Salt length
                f.write(self.salt)                          # Salt
            f.write(iv)                                     # IV
            f.write(encrypted_data)                         # Encrypted data
        
        return {
            'iv': iv,
            'salt': self.salt,
            'input_file': input_path,
            'output_file': output_path
        }
    
    def decrypt_file(self, input_path, output_path=None):
        """
        Decrypts a previously encrypted file using AES-256 CBC mode.

        Args:
            input_path (str): Path to encrypted file.
            output_path (str, optional): Output decrypted file path. If None:
                - removes '.enc' if present
                - otherwise adds '.dec'

        Returns:
            str: Path to decrypted file.

        Raises:
            FileNotFoundError: If the encrypted file does not exist.
            ValueError: If padding or decryption fails.
        """

        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        # Read encrypted file
        with open(input_path, 'rb') as f:
            data = f.read()
        
        # Check if file has salt (password-based encryption)
        pointer = 0
        salt = None
        
        # Read salt length and salt if present
        if len(data) >= 4:
            salt_length = int.from_bytes(data[:4], 'big')
            pointer += 4
            
            if salt_length > 0 and len(data) >= pointer + salt_length:
                salt = data[pointer:pointer + salt_length]
                pointer += salt_length
        
        # Extract IV (16 bytes) and encrypted data
        iv = data[pointer:pointer + 16]
        encrypted_data = data[pointer + 16:]
        
        # 🔥 CORREÇÃO CRÍTICA: Se o arquivo tem salt, mas nossa instância não tem password,
        # ou se o salt é diferente, precisamos derivar a chave corretamente
        if salt is not None and self.password is not None:
            # Se temos uma password e o arquivo tem salt, derivar a chave com o salt do arquivo
            key_to_use = PBKDF2(self.password, salt, dkLen=32, count=100000)
        else:
            # Caso contrário, usar a chave existente
            key_to_use = self.key
        
        # Create cipher and decrypt
        cipher = AES.new(key_to_use, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # Determine output path
        if output_path is None:
            if input_path.endswith('.enc'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + '.dec'
        
        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def encrypt_directory(self, directory_path, output_dir=None, extensions=None):
        """
        Encrypts all files in a directory.

        Args:
            directory_path (str): Path to the directory containing files.
            output_dir (str, optional): Output directory for encrypted files.
            extensions (list[str], optional): List of allowed extensions to encrypt.
                If None, encrypts all files.

        Returns:
            list[str]: List of encrypted file paths.

        Raises:
            FileNotFoundError: If directory does not exist.
        """

        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if output_dir is None:
            output_dir = directory_path + '_encrypted'
        
        os.makedirs(output_dir, exist_ok=True)
        
        encrypted_files = []
        
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            
            if os.path.isfile(file_path):
                # Check extensions if specified
                if extensions:
                    file_ext = os.path.splitext(filename)[1].lower()
                    if file_ext not in extensions:
                        continue
                
                output_path = os.path.join(output_dir, filename + '.enc')
                self.encrypt_file(file_path, output_path)
                encrypted_files.append(output_path)
        
        return encrypted_files
    
    def decrypt_directory(self, directory_path, output_dir=None):
        """
        Decrypts all encrypted files (.enc) in a directory.

        Args:
            directory_path (str): Directory containing encrypted files.
            output_dir (str, optional): Directory to save decrypted files.

        Returns:
            list[str]: List of decrypted file paths.

        Raises:
            FileNotFoundError: If directory does not exist.
        """

        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if output_dir is None:
            output_dir = directory_path + '_decrypted'
        
        os.makedirs(output_dir, exist_ok=True)
        
        decrypted_files = []
        
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            
            if os.path.isfile(file_path) and filename.endswith('.enc'):
                output_filename = filename[:-4]  # Remove .enc extension
                output_path = os.path.join(output_dir, output_filename)
                self.decrypt_file(file_path, output_path)
                decrypted_files.append(output_path)
        
        return decrypted_files
    
    def get_key_info(self):
        """
        Returns information about the current AES key and salt.

        Returns:
            dict: Contains:
                - key (bytes)
                - key_hex (str)
                - salt (bytes or None)
                - salt_hex (str or None)
                - key_type (str): 'password-derived' or 'random-binary'
        """

        return {
            'key': self.key,
            'key_hex': self.key.hex(),
            'salt': self.salt,
            'salt_hex': self.salt.hex() if self.salt else None,
            'key_type': 'password-derived' if self.salt else 'random-binary'
        }
    
    def save_key(self, key_path):
        """
        Saves the binary key to a file.

        Note:
            This is only valid when using binary keys (not password-derived keys).

        Args:
            key_path (str): File path to save the key.

        Raises:
            ValueError: If key is derived from a password.
        """

        if self.salt is not None:
            raise ValueError("Cannot save password-derived key. Save the password and salt instead.")
        
        with open(key_path, 'wb') as f:
            f.write(self.key)
    
    @classmethod
    def load_from_keyfile(cls, key_path):
        """
        Creates an AES256 instance by loading a 32-byte key from a file.

        Args:
            key_path (str): Path to binary key file.

        Returns:
            AES256: Instance initialized with the loaded key.
        """
        
        with open(key_path, 'rb') as f:
            key = f.read()
        return cls(key=key)

# Utility functions for easy use
def encrypt_file_with_password(input_path, password, output_path=None):
    """Utility function to encrypt a file with password in one line."""
    crypt = AES256(password=password)
    return crypt.encrypt_file(input_path, output_path)

def decrypt_file_with_password(input_path, password, output_path=None):
    """Utility function to decrypt a file with password in one line."""
    crypt = AES256(password=password)
    return crypt.decrypt_file(input_path, output_path)