from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
import base64


class AES256:
    """
    AES-256 encryption/decryption handler supporting both random keys and
    password-derived keys using PBKDF2, with encrypted filename support.
    """

    # ---------------------------------------------------------
    # INIT
    # ---------------------------------------------------------
    def __init__(self, key=None, password=None, salt=None):
        if password is not None:
            self.password = password
            if salt is None:
                salt = get_random_bytes(16)
            self.salt = salt
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
        
    def encrypt_filename(self, filename: str) -> str:
        raw = filename.encode("utf-8")
        iv = get_random_bytes(16)

        # we also save salt specific to filename!
        salt = self.salt if self.salt is not None else get_random_bytes(16)

        key = PBKDF2(self.password, salt, dkLen=32, count=100000)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(raw, AES.block_size))

        # final format: base64( salt + iv + encrypted )
        packed = salt + iv + encrypted
        return base64.urlsafe_b64encode(packed).decode("utf-8")


    def decrypt_filename(self, encrypted_name: str) -> str:
        data = base64.urlsafe_b64decode(encrypted_name.encode("utf-8"))

        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]

        key = PBKDF2(self.password, salt, dkLen=32, count=100000)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

        return decrypted.decode("utf-8")


    
    # ---------------------------------------------------------
    # ENCRYPT FILE
    # ---------------------------------------------------------
    def encrypt_file(self, input_path, output_path=None, encrypt_filename=False):

        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        directory = os.path.dirname(input_path)

        # encrypted filename
        if encrypt_filename:
            base = os.path.basename(input_path)
            enc_name = self.encrypt_filename(base)
            if output_path is None:
                output_path = os.path.join(directory, enc_name + ".enc")
            else:
                output_path = os.path.join(os.path.dirname(output_path), enc_name + ".enc")

        # normal filename
        else:
            if output_path is None:
                output_path = input_path + ".enc"

        # read file
        with open(input_path, "rb") as f:
            file_data = f.read()

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        # write output
        with open(output_path, "wb") as f:
            if self.salt is not None:
                f.write(len(self.salt).to_bytes(4, "big"))
                f.write(self.salt)
            f.write(iv)
            f.write(encrypted_data)

        return output_path

    # ---------------------------------------------------------
    # DECRYPT FILE
    # ---------------------------------------------------------
    def decrypt_file(self, input_path, output_path=None, decrypt_filename=False):

        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        with open(input_path, "rb") as f:
            data = f.read()

        pointer = 0
        salt = None

        # read salt
        if len(data) >= 4:
            salt_length = int.from_bytes(data[:4], "big")
            pointer += 4

            if salt_length > 0 and len(data) >= pointer + salt_length:
                salt = data[pointer:pointer + salt_length]
                pointer += salt_length

        iv = data[pointer:pointer + 16]
        encrypted_data = data[pointer + 16:]

        if salt is not None and self.password is not None:
            key = PBKDF2(self.password, salt, dkLen=32, count=100000)
        else:
            key = self.key

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # ---------------------------------------------------------
        # SAFE FILENAME DECRYPT LOGIC
        # ---------------------------------------------------------
        if decrypt_filename:
            encrypted_name = os.path.basename(input_path)[:-4]
            real_name = self.decrypt_filename(encrypted_name)

            # fallback when not encrypted
            if real_name is None:
                real_name = encrypted_name

            directory = os.path.dirname(output_path) if output_path else os.path.dirname(input_path)
            output_path = os.path.join(directory, real_name)

        # normal output
        else:
            if output_path is None:
                if input_path.endswith(".enc"):
                    output_path = input_path[:-4]
                else:
                    output_path = input_path + ".dec"

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        return output_path

    # ---------------------------------------------------------
    # DIRECTORY ENCRYPT
    # ---------------------------------------------------------
    def encrypt_directory(self, directory_path, output_dir=None, extensions=None, encrypt_filenames=False):
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        if output_dir is None:
            output_dir = directory_path + "_encrypted"

        os.makedirs(output_dir, exist_ok=True)
        encrypted_files = []

        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)

            if os.path.isfile(file_path):
                if extensions:
                    file_ext = os.path.splitext(filename)[1].lower()
                    if file_ext not in extensions:
                        continue

                self.encrypt_file(
                    file_path,
                    os.path.join(output_dir, filename + ".enc"),
                    encrypt_filename=encrypt_filenames
                )
                encrypted_files.append(file_path)

        return encrypted_files

    # ---------------------------------------------------------
    # DIRECTORY DECRYPT
    # ---------------------------------------------------------
    def decrypt_directory(self, directory_path, output_dir=None, decrypt_filenames=False):
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        if output_dir is None:
            output_dir = directory_path + "_decrypted"

        os.makedirs(output_dir, exist_ok=True)
        decrypted_files = []

        for filename in os.listdir(directory_path):
            if not filename.endswith(".enc"):
                continue

            file_path = os.path.join(directory_path, filename)
            self.decrypt_file(
                file_path,
                os.path.join(output_dir, filename[:-4]),
                decrypt_filename=decrypt_filenames
            )
            decrypted_files.append(file_path)

        return decrypted_files


# Utility
def encrypt_file_with_password(input_path, password, output_path=None, encrypt_filename=False):
    crypt = AES256(password=password)
    return crypt.encrypt_file(input_path, output_path, encrypt_filename=encrypt_filename)

def decrypt_file_with_password(input_path, password, output_path=None, decrypt_filename=False):
    crypt = AES256(password=password)
    return crypt.decrypt_file(input_path, output_path, decrypt_filename=decrypt_filename)
