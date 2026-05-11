    
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
        """
        if password is not None:
            self.password = password

            if salt is None:
                salt = get_random_bytes(16)

            self.salt = salt

            self.key = PBKDF2(
                password,
                salt,
                dkLen=32,
                count=100000
            )

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
        Encrypt a filename or directory name using AES-256
        and return a shortened URL-safe Base64 string.
        """
        raw = name.encode("utf-8")

        iv = get_random_bytes(16)

        salt = self.salt if self.salt is not None else get_random_bytes(16)

        key = PBKDF2(self.password, salt, dkLen=32, count=100000)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        encrypted = cipher.encrypt(pad(raw, AES.block_size))

        packed = salt + iv + encrypted

        encoded = base64.urlsafe_b64encode(packed).decode("utf-8")

        encoded = encoded.rstrip("=")

        return encoded

    def decrypt_name(self, encrypted_name: str) -> str:
        """
        Decrypt a filename or directory name encrypted with encrypt_name().
        """
        try:
            padding = 4 - (len(encrypted_name) % 4)

            if padding != 4:
                encrypted_name += "=" * padding

            data = base64.urlsafe_b64decode(encrypted_name.encode("utf-8"))

            salt = data[:16]

            iv = data[16:32]

            encrypted = data[32:]

            key = PBKDF2(self.password, salt, dkLen=32, count=100000)

            cipher = AES.new(key, AES.MODE_CBC, iv)

            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

            return decrypted.decode("utf-8")

        except Exception as e:
            raise ValueError(
                f"Failed to decrypt name. Invalid password or corrupted data: {str(e)}"
            )

    def encrypt_file(
        self,
        file_path,
        output_path=None,
        encrypt_filename=False,
        backup=False
    ):
        """
        Encrypt a single file.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        directory = os.path.dirname(file_path)

        if encrypt_filename:
            base = os.path.basename(file_path)

            enc_name = self.encrypt_name(base)

            if output_path is None:
                output_path = os.path.join(
                    directory,
                    enc_name + ".enc"
                )

            else:
                output_path = os.path.join(
                    os.path.dirname(output_path),
                    enc_name + ".enc"
                )

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
            raise Exception(
                f"Failed to read input file {file_path}: {str(e)}"
            )

        iv = get_random_bytes(16)

        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        encrypted_data = cipher.encrypt(
            pad(file_data, AES.block_size)
        )

        try:
            with open(output_path, "wb") as f:

                if self.salt is not None:
                    f.write(len(self.salt).to_bytes(4, "big"))
                    f.write(self.salt)

                f.write(iv)
                f.write(encrypted_data)

        except Exception as e:
            raise Exception(
                f"Failed to write encrypted file {output_path}: {str(e)}"
            )

        if not os.path.exists(output_path):
            raise Exception(
                f"Failed to create encrypted file: {output_path}"
            )

        if os.path.getsize(output_path) == 0:
            raise Exception(
                f"Failed to create encrypted file: {output_path}"
            )

        if not backup:
            try:
                os.unlink(file_path)

            except Exception as e:
                raise Exception(
                    f"Failed to remove original file {file_path}: {str(e)}"
                )

        return output_path

    def decrypt_file(
        self,
        file_path,
        output_path=None,
        decrypt_filename=False,
        backup=False
    ):
        """
        Decrypt a single encrypted file.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        try:
            with open(file_path, "rb") as f:
                data = f.read()

        except Exception as e:
            raise Exception(
                f"Failed to read encrypted file {file_path}: {str(e)}"
            )

        pointer = 0
        salt = None

        if len(data) >= 4:
            salt_length = int.from_bytes(
                data[:4],
                "big"
            )

            pointer += 4

            if salt_length > 0 and len(data) >= pointer + salt_length:
                salt = data[pointer:pointer + salt_length]
                pointer += salt_length

        if len(data) < pointer + 16:
            raise ValueError(
                f"Invalid encrypted file format: {file_path}"
            )

        iv = data[pointer:pointer + 16]

        encrypted_data = data[pointer + 16:]

        if salt is not None and self.password is not None:

            try:
                key = PBKDF2(
                    self.password,
                    salt,
                    dkLen=32,
                    count=100000
                )

            except Exception as e:
                raise ValueError(
                    f"Failed to derive key from password: {str(e)}"
                )

        else:
            key = self.key

        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)

            decrypted_data = unpad(
                cipher.decrypt(encrypted_data),
                AES.block_size
            )

        except Exception as e:
            raise ValueError(
                f"Decryption failed: {str(e)}"
            )

        if decrypt_filename:

            try:
                encrypted_name = os.path.basename(file_path)[:-4]

                real_name = self.decrypt_name(encrypted_name)

                directory = (
                    os.path.dirname(output_path)
                    if output_path
                    else os.path.dirname(file_path)
                )

                output_path = os.path.join(
                    directory,
                    real_name
                )

            except Exception as e:
                raise ValueError(
                    f"Failed to decrypt filename: {str(e)}"
                )

        else:
            if output_path is None:

                if file_path.endswith(".enc"):
                    output_path = file_path[:-4]

                else:
                    output_path = file_path + ".dec"

        output_dir = os.path.dirname(output_path)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        try:
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

        except Exception as e:
            raise Exception(
                f"Failed to write decrypted file {output_path}: {str(e)}"
            )

        if not os.path.exists(output_path):
            raise Exception(
                f"Failed to create decrypted file: {output_path}"
            )

        if os.path.getsize(output_path) == 0:
            raise Exception(
                f"Failed to create decrypted file: {output_path}"
            )

        if not backup:
            try:
                os.unlink(file_path)

            except Exception as e:
                raise Exception(
                    f"Failed to remove encrypted file {file_path}: {str(e)}"
                )

        return output_path

    def encrypt_directory(
        self,
        directory_path,
        output_dir=None,
        extensions=None,
        encrypt_filenames=False,
        encrypt_dirnames=False,
        recursive=False,
        backup=False
    ):
        """
        Encrypt all files in a directory.
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(
                f"Directory not found: {directory_path}"
            )

        encrypted_files = []

        if backup:

            if output_dir is None:

                if encrypt_dirnames:
                    enc_dir = self.encrypt_name(
                        os.path.basename(directory_path)
                    )

                    output_dir = os.path.join(
                        os.path.dirname(directory_path),
                        enc_dir
                    )

                else:
                    output_dir = directory_path

            os.makedirs(output_dir, exist_ok=True)

        for item in os.listdir(directory_path):

            full_path = os.path.join(
                directory_path,
                item
            )

            if os.path.isdir(full_path):

                if recursive:

                    if backup:

                        if encrypt_dirnames:
                            subdir_name = self.encrypt_name(item)

                        else:
                            subdir_name = item

                        new_output = os.path.join(
                            output_dir,
                            subdir_name
                        )

                    else:
                        new_output = None

                    encrypted_files.extend(
                        self.encrypt_directory(
                            full_path,
                            output_dir=new_output,
                            extensions=extensions,
                            encrypt_filenames=encrypt_filenames,
                            encrypt_dirnames=encrypt_dirnames,
                            recursive=True,
                            backup=backup
                        )
                    )

                    if not backup and encrypt_dirnames:

                        parent = os.path.dirname(full_path)

                        new_name = self.encrypt_name(item)

                        os.rename(
                            full_path,
                            os.path.join(parent, new_name)
                        )

                continue

            if not os.path.isfile(full_path):
                continue

            if item.endswith(".enc"):
                continue

            if extensions:
                ext = os.path.splitext(item)[1].lower()

                if ext not in extensions:
                    continue

            if backup:

                if encrypt_filenames:
                    filename = self.encrypt_name(item) + ".enc"

                else:
                    filename = item + ".enc"

                output_path = os.path.join(
                    output_dir,
                    filename
                )

            else:

                if encrypt_filenames:
                    filename = self.encrypt_name(item) + ".enc"

                    output_path = os.path.join(
                        directory_path,
                        filename
                    )

                else:
                    output_path = full_path + ".enc"

            result = self.encrypt_file(
                full_path,
                output_path=output_path,
                encrypt_filename=False,
                backup=backup
            )

            encrypted_files.append(result)

        return encrypted_files

    def decrypt_directory(
        self,
        directory_path,
        output_dir=None,
        decrypt_filenames=False,
        decrypt_dirnames=False,
        recursive=False,
        backup=False
    ):
        """
        Decrypt all encrypted files in a directory.
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(
                f"Directory not found: {directory_path}"
            )

        decrypted_files = []

        if backup:

            if output_dir is None:

                if decrypt_dirnames:

                    original = self.decrypt_name(
                        os.path.basename(directory_path)
                    )

                    output_dir = os.path.join(
                        os.path.dirname(directory_path),
                        original
                    )

                else:
                    output_dir = directory_path

            os.makedirs(output_dir, exist_ok=True)

        for item in os.listdir(directory_path):

            full_path = os.path.join(
                directory_path,
                item
            )

            if os.path.isdir(full_path):

                if recursive:

                    if backup:

                        if decrypt_dirnames:
                            subdir_name = self.decrypt_name(item)

                        else:
                            subdir_name = item

                        new_output = os.path.join(
                            output_dir,
                            subdir_name
                        )

                    else:
                        new_output = None

                    decrypted_files.extend(
                        self.decrypt_directory(
                            full_path,
                            output_dir=new_output,
                            decrypt_filenames=decrypt_filenames,
                            decrypt_dirnames=decrypt_dirnames,
                            recursive=True,
                            backup=backup
                        )
                    )

                    if not backup and decrypt_dirnames:

                        parent = os.path.dirname(full_path)

                        original_name = self.decrypt_name(item)

                        os.rename(
                            full_path,
                            os.path.join(parent, original_name)
                        )

                continue

            if not os.path.isfile(full_path):
                continue

            if not item.endswith(".enc"):
                continue

            if decrypt_filenames:

                try:
                    original_name = self.decrypt_name(
                        item[:-4]
                    )

                except Exception as e:
                    raise ValueError(
                        f"Failed to decrypt filename: {str(e)}"
                    )

            else:
                original_name = item[:-4]

            if backup:

                output_path = os.path.join(
                    output_dir,
                    original_name
                )

            else:

                output_path = os.path.join(
                    directory_path,
                    original_name
                )

            result = self.decrypt_file(
                full_path,
                output_path=output_path,
                decrypt_filename=False,
                backup=backup
            )

            decrypted_files.append(result)

        return decrypted_files


def encrypt_file_with_password(
    file_path,
    password,
    output_path=None,
    encrypt_filename=False,
    backup=False
):
    """
    Encrypt a single file using password.
    """
    crypt = AES256(password=password)

    return crypt.encrypt_file(
        file_path,
        output_path,
        encrypt_filename=encrypt_filename,
        backup=backup
    )


def decrypt_file_with_password(
    file_path,
    password,
    output_path=None,
    decrypt_filename=False,
    backup=False
):
    """
    Decrypt a single file using password.
    """
    crypt = AES256(password=password)

    return crypt.decrypt_file(
        file_path,
        output_path,
        decrypt_filename=decrypt_filename,
        backup=backup
    )