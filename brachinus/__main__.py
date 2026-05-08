    
"""
Copyright (C) 2025-2026 - JuanBindez <juanbindez780@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""


import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


class AES256:
    """
    AES-256 encryption/decryption handler supporting random keys and
    password-derived keys using PBKDF2, with support for encrypted filenames and directory names.
    """

    def __init__(self, key=None, password=None, salt=None):
        """
        Initialize an AES256 encryption instance.

        Parameters
        ----------
        key : bytes, optional
            A 32-byte AES key. If provided, no password is required.
        password : str, optional
            A password used to derive the AES key via PBKDF2.
        salt : bytes, optional
            Optional salt to use with PBKDF2. If omitted, a new random salt is generated.

        Raises
        ------
        ValueError
            If the provided key is not exactly 32 bytes.
        """
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
        
    def encrypt_name(self, name: str) -> str:
        """
        Encrypt a name (filename or directory name) using AES-256.
        Returns a URL-safe Base64 encoded string.

        Parameters
        ----------
        name : str
            The original name to encrypt.

        Returns
        -------
        str
            Encrypted name encoded as URL-safe Base64.
        """
        raw = name.encode("utf-8")
        iv = get_random_bytes(16)
        salt = self.salt if self.salt is not None else get_random_bytes(16)
        key = PBKDF2(self.password, salt, dkLen=32, count=100000)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(raw, AES.block_size))
        packed = salt + iv + encrypted
        return base64.urlsafe_b64encode(packed).decode("utf-8").replace('/', '_')

    def decrypt_name(self, encrypted_name: str) -> str:
        """
        Decrypt a name that was encrypted using encrypt_name().

        Parameters
        ----------
        encrypted_name : str
            The encrypted name.

        Returns
        -------
        str
            The decrypted original name.

        Raises
        ------
        ValueError
            If decryption fails due to invalid password or corrupted data.
        """
        try:
            encrypted_name = encrypted_name.replace('_', '/')
            data = base64.urlsafe_b64decode(encrypted_name.encode("utf-8"))
            salt = data[:16]
            iv = data[16:32]
            encrypted = data[32:]

            key = PBKDF2(self.password, salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decrypt name. Invalid password or corrupted data: {str(e)}")

    def encrypt_file(self, file_path, output_path=None, encrypt_filename=False):
        """
        Encrypt a single file using AES-256 (CBC + PKCS7 padding).

        Parameters
        ----------
        file_path : str
            Path to the file to encrypt.
        output_path : str, optional
            Destination path for encrypted output. If omitted, ".enc" is appended.
        encrypt_filename : bool
            If True, the final filename is encrypted using encrypt_name().

        Returns
        -------
        str
            The path of the encrypted output file.

        Raises
        ------
        FileNotFoundError
            If the input file does not exist.
        Exception
            If encryption fails.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        directory = os.path.dirname(file_path)

        if encrypt_filename:
            base = os.path.basename(file_path)
            enc_name = self.encrypt_name(base)
            if output_path is None:
                output_path = os.path.join(directory, enc_name + ".enc")
            else:
                output_path = os.path.join(os.path.dirname(output_path), enc_name + ".enc")
        else:
            if output_path is None:
                output_path = file_path + ".enc"

        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            raise Exception(f"Failed to read input file {file_path}: {str(e)}")

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        try:
            with open(output_path, "wb") as f:
                if self.salt is not None:
                    f.write(len(self.salt).to_bytes(4, "big"))
                    f.write(self.salt)
                f.write(iv)
                f.write(encrypted_data)
        except Exception as e:
            raise Exception(f"Failed to write encrypted file {output_path}: {str(e)}")

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise Exception(f"Failed to create encrypted file: {output_path}")
            
        return output_path

    def decrypt_file(self, file_path, output_path=None, decrypt_filename=False):
        """
        Decrypt a file encrypted with encrypt_file().

        Parameters
        ----------
        file_path : str
            Path to the encrypted .enc file.
        output_path : str, optional
            Where the decrypted file should be saved.
        decrypt_filename : bool
            If True, decrypts embedded encrypted filename and restores original.

        Returns
        -------
        str
            Path to the decrypted output file.

        Raises
        ------
        FileNotFoundError
            If the input file does not exist.
        ValueError
            If decryption fails due to invalid password or corrupted data.
        Exception
            If file operations fail.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            raise Exception(f"Failed to read encrypted file {file_path}: {str(e)}")

        pointer = 0
        salt = None

        if len(data) >= 4:
            salt_length = int.from_bytes(data[:4], "big")
            pointer += 4
            if salt_length > 0 and len(data) >= pointer + salt_length:
                salt = data[pointer:pointer + salt_length]
                pointer += salt_length

        if len(data) < pointer + 16:
            raise ValueError(f"Invalid encrypted file format: {file_path}")

        iv = data[pointer:pointer + 16]
        encrypted_data = data[pointer + 16:]

        if salt is not None and self.password is not None:
            try:
                key = PBKDF2(self.password, salt, dkLen=32, count=100000)
            except Exception as e:
                raise ValueError(f"Failed to derive key from password: {str(e)}")
        else:
            key = self.key

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except Exception as e:
            raise ValueError(f"Decryption failed. Invalid password or corrupted data: {str(e)}")

        if decrypt_filename:
            try:
                encrypted_name = os.path.basename(file_path)[:-4]
                real_name = self.decrypt_name(encrypted_name)
                directory = os.path.dirname(output_path) if output_path else os.path.dirname(file_path)
                output_path = os.path.join(directory, real_name)
            except Exception as e:
                raise ValueError(f"Failed to decrypt filename: {str(e)}")
        else:
            if output_path is None:
                output_path = file_path[:-4] if file_path.endswith(".enc") else file_path + ".dec"

        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        try:
            with open(output_path, "wb") as f:
                f.write(decrypted_data)
        except Exception as e:
            raise Exception(f"Failed to write decrypted file {output_path}: {str(e)}")

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise Exception(f"Failed to create decrypted file: {output_path}")

        return output_path

    def encrypt_directory(self, directory_path, output_dir=None, extensions=None, encrypt_filenames=False, encrypt_dirnames=False, recursive=False, backup=False):
        """
        Encrypt all files in a directory.

        Parameters
        ----------
        directory_path : str
            Path to the source directory.
        output_dir : str, optional
            Output directory for encrypted files (mirrors structure).
        extensions : list[str], optional
            Only encrypt files with these extensions.
        encrypt_filenames : bool
            Encrypt filenames using encrypt_name().
        encrypt_dirnames : bool
            Encrypt directory names using encrypt_name().
        recursive : bool
            If True, process subdirectories recursively.
        backup : bool
            If True, creates a new directory for encrypted files.
            If False, encrypts files in place (overwrites original files with encrypted ones).

        Returns
        -------
        list
            List of all encrypted file paths.

        Raises
        ------
        FileNotFoundError
            If the directory does not exist.
        Exception
            If encryption fails.
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        if not backup:
            encrypted_files = []
            files_to_encrypt = []
            dirs_to_process = []
            
            try:
                items = os.listdir(directory_path)
            except Exception as e:
                raise Exception(f"Failed to list directory {directory_path}: {str(e)}")
            
            for item in items:
                full_path = os.path.join(directory_path, item)
                
                if os.path.isdir(full_path) and recursive:
                    dirs_to_process.append(full_path)
                elif os.path.isfile(full_path):
                    if item.endswith(".enc"):
                        continue
                    if extensions:
                        ext = os.path.splitext(item)[1].lower()
                        if ext not in extensions:
                            continue
                    files_to_encrypt.append(full_path)
            
            for subdir in dirs_to_process:
                sub_encrypted = self.encrypt_directory(
                    subdir,
                    output_dir=None,
                    extensions=extensions,
                    encrypt_filenames=encrypt_filenames,
                    encrypt_dirnames=encrypt_dirnames,
                    recursive=True,
                    backup=False
                )
                encrypted_files.extend(sub_encrypted)
                
                if encrypt_dirnames:
                    parent_dir = os.path.dirname(subdir)
                    old_name = os.path.basename(subdir)
                    try:
                        new_name = self.encrypt_name(old_name)
                        new_path = os.path.join(parent_dir, new_name)
                        
                        if os.path.exists(subdir) and not os.path.exists(new_path):
                            os.rename(subdir, new_path)
                    except Exception as e:
                        raise Exception(f"Failed to rename directory {old_name}: {str(e)}")
            
            for full_path in files_to_encrypt:
                base_name = os.path.basename(full_path)
                
                if encrypt_filenames:
                    try:
                        enc_name = self.encrypt_name(base_name)
                        encrypted_path = os.path.join(directory_path, enc_name + ".enc")
                        result_path = self.encrypt_file(full_path, encrypted_path, encrypt_filename=encrypt_filenames)
                        
                        if os.path.exists(result_path) and os.path.getsize(result_path) > 0:
                            os.unlink(full_path)
                            encrypted_files.append(result_path)
                        else:
                            raise Exception(f"Encryption produced empty file for {base_name}")
                    except Exception as e:
                        raise Exception(f"Failed to encrypt file {base_name}: {str(e)}")
                else:
                    try:
                        encrypted_path = full_path + ".enc"
                        result_path = self.encrypt_file(full_path, encrypted_path, encrypt_filename=encrypt_filenames)
                        
                        if os.path.exists(result_path) and os.path.getsize(result_path) > 0:
                            os.unlink(full_path)
                            encrypted_files.append(result_path)
                        else:
                            raise Exception(f"Encryption produced empty file for {base_name}")
                    except Exception as e:
                        raise Exception(f"Failed to encrypt file {base_name}: {str(e)}")
            
            return encrypted_files
        
        else:
            if output_dir is None:
                if encrypt_dirnames:
                    try:
                        dir_name = os.path.basename(directory_path)
                        enc_dir_name = self.encrypt_name(dir_name)
                        output_dir = os.path.join(os.path.dirname(directory_path), enc_dir_name + "_encrypted")
                    except Exception as e:
                        raise Exception(f"Failed to encrypt directory name: {str(e)}")
                else:
                    output_dir = directory_path + "_encrypted"
            
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                raise Exception(f"Failed to create output directory {output_dir}: {str(e)}")
            
            encrypted_files = []
            
            try:
                items = os.listdir(directory_path)
            except Exception as e:
                raise Exception(f"Failed to list directory {directory_path}: {str(e)}")
            
            for item in items:
                full_path = os.path.join(directory_path, item)
                
                if os.path.isdir(full_path) and recursive:
                    if encrypt_dirnames:
                        try:
                            enc_subdir_name = self.encrypt_name(item)
                            new_out = os.path.join(output_dir, enc_subdir_name)
                        except Exception as e:
                            raise Exception(f"Failed to encrypt subdirectory name {item}: {str(e)}")
                    else:
                        new_out = os.path.join(output_dir, item)
                    
                    try:
                        os.makedirs(new_out, exist_ok=True)
                    except Exception as e:
                        raise Exception(f"Failed to create output subdirectory {new_out}: {str(e)}")
                    
                    encrypted_files.extend(
                        self.encrypt_directory(
                            full_path,
                            new_out,
                            extensions=extensions,
                            encrypt_filenames=encrypt_filenames,
                            encrypt_dirnames=encrypt_dirnames,
                            recursive=True,
                            backup=True
                        )
                    )
                    continue
                
                if os.path.isfile(full_path):
                    if item.endswith(".enc"):
                        continue
                    if extensions:
                        ext = os.path.splitext(item)[1].lower()
                        if ext not in extensions:
                            continue
                    
                    if encrypt_filenames:
                        try:
                            enc_filename = self.encrypt_name(item)
                            output_path = os.path.join(output_dir, enc_filename + ".enc")
                        except Exception as e:
                            raise Exception(f"Failed to encrypt filename {item}: {str(e)}")
                    else:
                        output_path = os.path.join(output_dir, item + ".enc")
                    
                    self.encrypt_file(full_path, output_path, encrypt_filename=encrypt_filenames)
                    encrypted_files.append(output_path)
            
            return encrypted_files

    def decrypt_directory(self, directory_path, output_dir=None, decrypt_filenames=False, decrypt_dirnames=False, recursive=False, backup=False):
        """
        Decrypt all .enc files inside a directory.

        Parameters
        ----------
        directory_path : str
            Path to the encrypted directory.
        output_dir : str, optional
            Destination directory for decrypted files.
        decrypt_filenames : bool
            Restore original filenames if encrypted.
        decrypt_dirnames : bool
            Restore original directory names if encrypted.
        recursive : bool
            Process subdirectories recursively.
        backup : bool
            If True, creates a new directory for decrypted files.
            If False, decrypts files in place (overwrites encrypted files with decrypted ones).

        Returns
        -------
        list
            List of decrypted file paths.

        Raises
        ------
        FileNotFoundError
            If the directory does not exist.
        ValueError
            If decryption fails due to invalid password or corrupted data.
        Exception
            If file operations fail.
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not backup:
            decrypted_files = []
            enc_files = []
            dirs_to_process = []
            
            try:
                items = os.listdir(directory_path)
            except Exception as e:
                raise Exception(f"Failed to list directory {directory_path}: {str(e)}")
            
            for item in items:
                full_path = os.path.join(directory_path, item)
                
                if os.path.isdir(full_path) and recursive:
                    dirs_to_process.append(full_path)
                elif os.path.isfile(full_path) and item.endswith(".enc"):
                    enc_files.append(full_path)
            
            for subdir in dirs_to_process:
                sub_decrypted = self.decrypt_directory(
                    subdir,
                    output_dir=None,
                    decrypt_filenames=decrypt_filenames,
                    decrypt_dirnames=decrypt_dirnames,
                    recursive=True,
                    backup=False
                )
                decrypted_files.extend(sub_decrypted)
            
            for full_path in enc_files:
                item = os.path.basename(full_path)
                
                if decrypt_filenames:
                    try:
                        encrypted_name = item[:-4]
                        original_name = self.decrypt_name(encrypted_name)
                        original_path = os.path.join(directory_path, original_name)
                        result_path = self.decrypt_file(full_path, original_path, decrypt_filename=decrypt_filenames)
                        
                        if os.path.exists(result_path) and os.path.getsize(result_path) > 0:
                            os.unlink(full_path)
                            decrypted_files.append(result_path)
                        else:
                            raise ValueError(f"Decryption produced empty file for {item}")
                    except Exception as e:
                        raise ValueError(f"Failed to decrypt file {item}: {str(e)}")
                else:
                    try:
                        output_path = full_path[:-4]
                        result_path = self.decrypt_file(full_path, output_path, decrypt_filename=False)
                        
                        if os.path.exists(result_path) and os.path.getsize(result_path) > 0:
                            os.unlink(full_path)
                            decrypted_files.append(result_path)
                        else:
                            raise ValueError(f"Decryption produced empty file for {item}")
                    except Exception as e:
                        raise ValueError(f"Failed to decrypt file {item}: {str(e)}")
            
            if decrypt_dirnames:
                parent_dir = os.path.dirname(directory_path)
                current_name = os.path.basename(directory_path)
                try:
                    original_name = self.decrypt_name(current_name)
                    original_path = os.path.join(parent_dir, original_name)
                    
                    if original_name != current_name and not os.path.exists(original_path):
                        os.rename(directory_path, original_path)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt directory name {current_name}: {str(e)}")
            
            return decrypted_files
        
        else:
            if output_dir is None:
                if decrypt_dirnames:
                    try:
                        original_name = self.decrypt_name(os.path.basename(directory_path))
                        output_dir = os.path.join(os.path.dirname(directory_path), original_name + "_decrypted")
                    except Exception as e:
                        raise ValueError(f"Failed to decrypt output directory name: {str(e)}")
                else:
                    output_dir = directory_path + "_decrypted"
            
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                raise Exception(f"Failed to create output directory {output_dir}: {str(e)}")
            
            decrypted_files = []
            
            try:
                items = os.listdir(directory_path)
            except Exception as e:
                raise Exception(f"Failed to list directory {directory_path}: {str(e)}")
            
            for item in items:
                full_path = os.path.join(directory_path, item)
                
                if os.path.isdir(full_path) and recursive:
                    if decrypt_dirnames:
                        try:
                            original_name = self.decrypt_name(item)
                            new_out = os.path.join(output_dir, original_name)
                        except Exception as e:
                            raise ValueError(f"Failed to decrypt subdirectory name {item}: {str(e)}")
                    else:
                        new_out = os.path.join(output_dir, item)
                    
                    try:
                        os.makedirs(new_out, exist_ok=True)
                    except Exception as e:
                        raise Exception(f"Failed to create output subdirectory {new_out}: {str(e)}")
                    
                    decrypted_files.extend(
                        self.decrypt_directory(
                            full_path,
                            new_out,
                            decrypt_filenames=decrypt_filenames,
                            decrypt_dirnames=decrypt_dirnames,
                            recursive=True,
                            backup=True
                        )
                    )
                    continue
                
                if os.path.isfile(full_path) and item.endswith(".enc"):
                    if decrypt_filenames:
                        enc_name = item[:-4]
                        try:
                            original_name = self.decrypt_name(enc_name)
                            output_path = os.path.join(output_dir, original_name)
                        except Exception as e:
                            raise ValueError(f"Failed to decrypt filename {enc_name}: {str(e)}")
                    else:
                        output_path = os.path.join(output_dir, item[:-4])
                    
                    self.decrypt_file(full_path, output_path, decrypt_filename=decrypt_filenames)
                    decrypted_files.append(output_path)
            
            return decrypted_files


def encrypt_file_with_password(file_path, password, output_path=None, encrypt_filename=False):
    """
    Quickly encrypt a file using a password-derived AES key.

    Parameters
    ----------
    file_path : str
        File to encrypt.
    password : str
        Password used to derive AES key.
    output_path : str, optional
        Destination output path.
    encrypt_filename : bool
        Encrypt the final filename.

    Returns
    -------
    str
        Output encrypted file path.

    Raises
    ------
    Exception
        If encryption fails.
    """
    crypt = AES256(password=password)
    return crypt.encrypt_file(file_path, output_path, encrypt_filename=encrypt_filename)


def decrypt_file_with_password(file_path, password, output_path=None, decrypt_filename=False):
    """
    Quickly decrypt a file using a password-derived AES key.

    Parameters
    ----------
    file_path : str
        File to decrypt.
    password : str
        Password used to derive the AES key.
    output_path : str, optional
        Destination path.
    decrypt_filename : bool
        Restore original filename if encrypted.

    Returns
    -------
    str
        Output decrypted file path.

    Raises
    ------
    ValueError
        If decryption fails due to invalid password or corrupted data.
    Exception
        If file operations fail.
    """
    crypt = AES256(password=password)
    return crypt.decrypt_file(file_path, output_path, decrypt_filename=decrypt_filename)