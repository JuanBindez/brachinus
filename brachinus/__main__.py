"""
Copyright © 2025–2026 JuanBindez <juanbindez780@gmail.com>

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


AES-256 file encryption (format version 2)
==========================================

File format (all integers big-endian)::

    "BRCH" | version(1)=2 | kdf(1) | iterations(4) | chunk_log2(1)
           | salt(16, only if kdf == 1) | nonce_prefix(8)
           | chunk_0 | chunk_1 | ... | chunk_n

    kdf: 0 = raw 32-byte key (key file / random key)
         1 = PBKDF2-HMAC-SHA256 from a password

Every chunk is AES-256-GCM(ciphertext || 16-byte tag), with

    nonce = nonce_prefix || chunk_index(4)
    aad   = <whole header> || last_chunk_flag(1)

so that wrong keys, tampering, reordering and truncation are all detected.

Files written by brachinus 1.x (AES-CBC, no authentication) can still be
read; they are never produced any more.
"""

import hashlib
import hmac
import os
import stat
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

from brachinus.exceptions import (
    BrachinusError, DecryptionError, FormatError, InvalidKeyError,
)

from brachinus.helpers import (
    _b64d,
    _b64e,
    _check_name,
    _atomic_write,
    _default_mode,
    _prune_empty_dirs,
)

MAGIC = b"BRCH"
VERSION = 2
KDF_RAW = 0
KDF_PBKDF2_SHA256 = 1

DEFAULT_ITERATIONS = 600_000
MAX_ITERATIONS = 20_000_000  # refuse hostile headers asking for absurd work
DEFAULT_CHUNK_LOG2 = 20  # 1 MiB chunks
MIN_CHUNK_LOG2 = 10
MAX_CHUNK_LOG2 = 26

SALT_LEN = 16
PREFIX_LEN = 8
TAG_LEN = 16
NAME_NONCE_LEN = 12
SUFFIX = ".enc"

_HEAD = struct.Struct(">BBIB")  # version, kdf, iterations, chunk_log2
_LEGACY_ITERATIONS = 100_000
_LEGACY_SALT_PREFIX = (16).to_bytes(4, "big")

_NAME_AAD = b"brachinus/name/v2"
_NAME_KEY_LABEL = b"brachinus/name-key/v2"
_NAME_KEY_RAW = 0x01
_NAME_KEY_PWD = 0x02


class AES256:
    """AES-256 file and name encryption with a random key or a password."""

    def __init__(
        self,
        key=None,
        password=None,
        salt=None,
        iterations=DEFAULT_ITERATIONS,
        chunk_log2=DEFAULT_CHUNK_LOG2,
    ):
        if key is not None and password is not None:
            raise InvalidKeyError("give either a key or a password, not both")

        if not MIN_CHUNK_LOG2 <= chunk_log2 <= MAX_CHUNK_LOG2:
            raise ValueError(
                f"chunk_log2 must be between {MIN_CHUNK_LOG2} and {MAX_CHUNK_LOG2}"
            )

        if not 1 <= iterations <= MAX_ITERATIONS:
            raise ValueError("iterations out of range")

        self.iterations = iterations
        self.chunk_log2 = chunk_log2
        self._cache = {}

        if password is not None:
            pw = (
                password.encode("utf-8")
                if isinstance(password, str)
                else bytes(password)
            )

            if not pw:
                raise InvalidKeyError("empty password")

            if salt is not None and len(salt) != SALT_LEN:
                raise InvalidKeyError(f"salt must be {SALT_LEN} bytes")

            self.password = password
            self._pw = pw
            self.salt = bytes(salt) if salt is not None else get_random_bytes(SALT_LEN)
            self.key = self._derive(self.salt, iterations)
        elif key is None:
            self.password = self._pw = self.salt = None
            self.key = get_random_bytes(32)
        elif len(key) == 32:
            self.password = self._pw = self.salt = None
            self.key = bytes(key)
        else:
            raise InvalidKeyError("Key must be 32 bytes for AES-256")

    # -- key handling -------------------------------------------------------

    def _derive(self, salt, iterations, legacy=False):
        """Password -> key, cached so each (salt, iterations) is computed once."""
        ck = (bytes(salt), iterations, legacy)
        key = self._cache.get(ck)

        if key is None:
            if len(self._cache) >= 64:
                self._cache.clear()

            if legacy:  # version 1: PBKDF2-HMAC-SHA1
                key = PBKDF2(self._pw, salt, dkLen=32, count=iterations)
            else:
                key = PBKDF2(
                    self._pw, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256
                )

            self._cache[ck] = key

        return key

    @staticmethod
    def _name_key(master):
        return hmac.new(master, _NAME_KEY_LABEL, hashlib.sha256).digest()

    def save_key(self, path):
        """Write the random key to `path` (mode 0600). Not for passwords."""
        if self.password is not None:
            raise BrachinusError("a password-derived key cannot be saved")

        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

        with os.fdopen(fd, "wb") as f:
            f.write(self.key)

    @classmethod
    def load_from_keyfile(cls, path):
        with open(path, "rb") as f:
            return cls(key=f.read())

    def get_key_info(self):
        info = {
            "key": self.key,
            "key_hex": self.key.hex(),
            "key_type": "password-derived" if self.password is not None else "random",
        }

        if self.salt is not None:
            info["salt"] = self.salt
            info["salt_hex"] = self.salt.hex()
            info["iterations"] = self.iterations

        return info

    # -- names --------------------------------------------------------------

    def encrypt_name(self, name):
        """Authenticated, URL-safe token for a file or directory name."""
        if self.password is not None:
            tag = (
                bytes([_NAME_KEY_PWD]) + self.iterations.to_bytes(4, "big") + self.salt
            )
        else:
            tag = bytes([_NAME_KEY_RAW])

        nonce = get_random_bytes(NAME_NONCE_LEN)
        cipher = AES.new(self._name_key(self.key), AES.MODE_GCM, nonce=nonce)
        cipher.update(_NAME_AAD + tag)
        ct, mac = cipher.encrypt_and_digest(name.encode("utf-8"))
        return _b64e(tag + nonce + ct + mac)

    def decrypt_name(self, token):
        """Inverse of encrypt_name(); also reads version 1 names."""
        data = _b64d(token)
        name = self._decrypt_name_v2(data)

        if name is None:
            name = self._decrypt_name_legacy(data)

        if name is None:
            raise DecryptionError(
                "cannot decrypt name: wrong password/key or not an encrypted name"
            )

        return _check_name(name)

    def _decrypt_name_v2(self, data):
        try:
            kind = data[0]

            if kind == _NAME_KEY_RAW and self.password is None:
                tag_len, master = 1, self.key
            elif kind == _NAME_KEY_PWD and self.password is not None:
                iterations = int.from_bytes(data[1:5], "big")

                if not 1 <= iterations <= MAX_ITERATIONS:
                    return None

                tag_len = 1 + 4 + SALT_LEN
                master = self._derive(data[5 : 5 + SALT_LEN], iterations)
            else:
                return None

            tag = data[:tag_len]
            nonce = data[tag_len : tag_len + NAME_NONCE_LEN]
            body = data[tag_len + NAME_NONCE_LEN :]

            if len(nonce) != NAME_NONCE_LEN or len(body) < TAG_LEN:
                return None

            cipher = AES.new(self._name_key(master), AES.MODE_GCM, nonce=nonce)
            cipher.update(_NAME_AAD + tag)
            return cipher.decrypt_and_verify(body[:-TAG_LEN], body[-TAG_LEN:]).decode(
                "utf-8"
            )
        except (ValueError, IndexError):
            return None

    def _decrypt_name_legacy(self, data):
        if self.password is None or len(data) < 48 or (len(data) - 32) % 16:
            return None

        try:
            key = self._derive(data[:16], _LEGACY_ITERATIONS, legacy=True)
            plain = unpad(
                AES.new(key, AES.MODE_CBC, data[16:32]).decrypt(data[32:]), 16
            )
            return plain.decode("utf-8")
        except ValueError:
            return None

    # -- file streams -------------------------------------------------------

    def _encrypt_stream(self, fin, fout):
        if self.password is not None:
            kdf, salt, iterations = KDF_PBKDF2_SHA256, self.salt, self.iterations
        else:
            kdf, salt, iterations = KDF_RAW, b"", 0

        prefix = get_random_bytes(PREFIX_LEN)
        header = (
            MAGIC
            + _HEAD.pack(VERSION, kdf, iterations, self.chunk_log2)
            + salt
            + prefix
        )
        fout.write(header)

        size = 1 << self.chunk_log2
        index = 0
        cur = fin.read(size)

        while True:
            nxt = fin.read(size)
            final = not nxt

            if index >= 1 << 32:
                raise BrachinusError("file too large for this format")

            cipher = AES.new(
                self.key, AES.MODE_GCM, nonce=prefix + index.to_bytes(4, "big")
            )
            cipher.update(header + (b"\x01" if final else b"\x00"))
            ct, mac = cipher.encrypt_and_digest(cur)
            fout.write(ct + mac)

            if final:
                return

            cur, index = nxt, index + 1

    def _decrypt_stream(self, fin, fout, path):
        head = fin.read(len(MAGIC) + _HEAD.size)

        if len(head) < len(MAGIC) + _HEAD.size or head[:4] != MAGIC:
            raise FormatError("not a brachinus file")

        version, kdf, iterations, chunk_log2 = _HEAD.unpack(head[4:])

        if version != VERSION:
            raise FormatError(f"unsupported format version {version}")

        if not MIN_CHUNK_LOG2 <= chunk_log2 <= MAX_CHUNK_LOG2:
            raise FormatError("invalid chunk size")

        if kdf == KDF_PBKDF2_SHA256:
            if self.password is None:
                raise DecryptionError(
                    "encrypted with a password, but a key file was given"
                )

            if not 1 <= iterations <= MAX_ITERATIONS:
                raise FormatError("invalid KDF parameters")

            salt = fin.read(SALT_LEN)

            if len(salt) != SALT_LEN:
                raise FormatError("truncated header")

            head += salt
            key = self._derive(salt, iterations)
        elif kdf == KDF_RAW:
            if self.password is not None:
                raise DecryptionError(
                    "encrypted with a key file, but a password was given"
                )

            key = self.key
        else:
            raise FormatError(f"unknown key derivation {kdf}")

        prefix = fin.read(PREFIX_LEN)

        if len(prefix) != PREFIX_LEN:
            raise FormatError("truncated header")

        header = head + prefix
        record = (1 << chunk_log2) + TAG_LEN
        index = 0
        cur = fin.read(record)

        while True:
            nxt = fin.read(record)
            final = not nxt

            if len(cur) < TAG_LEN:
                raise FormatError("truncated file")

            cipher = AES.new(key, AES.MODE_GCM, nonce=prefix + index.to_bytes(4, "big"))
            cipher.update(header + (b"\x01" if final else b"\x00"))

            try:
                fout.write(cipher.decrypt_and_verify(cur[:-TAG_LEN], cur[-TAG_LEN:]))
            except ValueError:
                raise DecryptionError(
                    "authentication failed (wrong password/key, or the file was modified or truncated)"
                ) from None

            if final:
                return

            cur, index = nxt, index + 1

    def _decrypt_legacy(self, data, fout, path):
        """Version 1: CBC, [4-byte salt length + salt]? + IV + data."""
        if (
            self.password is not None
            and data[:4] == _LEGACY_SALT_PREFIX
            and len(data) >= 36
        ):
            key = self._derive(data[4:20], _LEGACY_ITERATIONS, legacy=True)
            iv, body = data[20:36], data[36:]
        else:
            key, iv, body = self.key, data[:16], data[16:]

        if len(iv) != 16 or not body or len(body) % 16:
            raise FormatError("not a brachinus file")

        try:
            fout.write(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(body), 16))
        except ValueError:
            raise DecryptionError("wrong password/key or corrupted file") from None

    # -- single files -------------------------------------------------------

    def encrypt_file(
        self, file_path, output_path=None, encrypt_filename=False, remove_original=False
    ):
        """Encrypt one file; returns the output path.

        The original is kept unless remove_original=True. The output is
        written atomically.
        """
        file_path = os.fspath(file_path)

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if encrypt_filename:
            directory = (
                os.path.dirname(output_path)
                if output_path
                else os.path.dirname(file_path)
            )
            output_path = os.path.join(
                directory, self.encrypt_name(os.path.basename(file_path)) + SUFFIX
            )
        elif output_path is None:
            output_path = file_path + SUFFIX

        output_path = os.fspath(output_path)

        if os.path.exists(output_path) and os.path.samefile(file_path, output_path):
            raise BrachinusError(f"{file_path}: input and output are the same file")

        mode = stat.S_IMODE(os.stat(file_path).st_mode)

        with open(file_path, "rb") as fin, _atomic_write(output_path, mode) as fout:
            self._encrypt_stream(fin, fout)

        if remove_original:
            os.unlink(file_path)

        return output_path

    def decrypt_file(
        self, file_path, output_path=None, decrypt_filename=False, remove_original=False
    ):
        """Decrypt one file; returns the output path. Reads version 1 files too.

        remove_original=True deletes the encrypted file after success.
        """
        file_path = os.fspath(file_path)

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if decrypt_filename:
            base = os.path.basename(file_path)
            token = base[: -len(SUFFIX)] if base.endswith(SUFFIX) else base
            directory = (
                os.path.dirname(output_path)
                if output_path
                else os.path.dirname(file_path)
            )
            output_path = os.path.join(directory, self.decrypt_name(token))
        elif output_path is None:
            output_path = (
                file_path[: -len(SUFFIX)]
                if file_path.endswith(SUFFIX)
                else file_path + ".dec"
            )

        output_path = os.fspath(output_path)

        if os.path.exists(output_path) and os.path.samefile(file_path, output_path):
            raise BrachinusError(f"{file_path}: input and output are the same file")

        with open(file_path, "rb") as fin:
            is_v2 = fin.read(len(MAGIC)) == MAGIC
            fin.seek(0)

            with _atomic_write(output_path, _default_mode()) as fout:
                if is_v2:
                    self._decrypt_stream(fin, fout, file_path)
                else:
                    self._decrypt_legacy(fin.read(), fout, file_path)

        if remove_original:
            os.unlink(file_path)

        return output_path

    # -- directories --------------------------------------------------------

    def encrypt_directory(
        self,
        directory_path,
        output_dir=None,
        extensions=None,
        encrypt_filenames=False,
        encrypt_dirnames=False,
        recursive=False,
        remove_original=False,
    ):
        """Encrypt the files of a directory; returns the list of outputs.

        Default output: the directory itself (files get ".enc" next to the
        originals), or, with encrypt_dirnames, a sibling directory with an
        encrypted name.
        """
        root = os.path.normpath(os.fspath(directory_path))

        if not os.path.isdir(root):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        exts = (
            {e.lower() if e.startswith(".") else "." + e.lower() for e in extensions}
            if extensions
            else None
        )
        tokens = {}

        def token(name):
            if name not in tokens:
                tokens[name] = self.encrypt_name(name)

            return tokens[name]

        if output_dir is None:
            if encrypt_dirnames:
                top = os.path.basename(os.path.abspath(root))
                output_dir = os.path.join(
                    os.path.dirname(os.path.abspath(root)), token(top)
                )
            else:
                output_dir = root

        output_dir = os.path.normpath(output_dir)
        skip = os.path.abspath(output_dir)
        in_place = skip == os.path.abspath(root)
        results = []

        for cur, dirs, files in os.walk(root):
            if recursive:
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if not os.path.islink(os.path.join(cur, d))
                    and os.path.abspath(os.path.join(cur, d)) != skip
                )
            else:
                dirs[:] = []

            rel = os.path.relpath(cur, root)
            parts = (
                []
                if rel == "."
                else [token(p) if encrypt_dirnames else p for p in rel.split(os.sep)]
            )
            outdir = os.path.join(output_dir, *parts)

            for f in sorted(files):
                src = os.path.join(cur, f)

                if f.endswith(SUFFIX) or os.path.islink(src) or not os.path.isfile(src):
                    continue

                if exts and os.path.splitext(f)[1].lower() not in exts:
                    continue

                outname = (token(f) if encrypt_filenames else f) + SUFFIX
                results.append(
                    self.encrypt_file(
                        src,
                        os.path.join(outdir, outname),
                        remove_original=remove_original,
                    )
                )

        if remove_original and not in_place:
            _prune_empty_dirs(root)

        return results

    def decrypt_directory(
        self,
        directory_path,
        output_dir=None,
        decrypt_filenames=False,
        decrypt_dirnames=False,
        recursive=False,
        remove_original=False,
    ):
        """Decrypt the ".enc" files of a directory; returns the list of outputs."""
        root = os.path.normpath(os.fspath(directory_path))

        if not os.path.isdir(root):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        if output_dir is None:
            if decrypt_dirnames:
                top = os.path.basename(os.path.abspath(root))
                top = (
                    top[: -len(SUFFIX)]
                    if top.endswith(SUFFIX) and top != SUFFIX
                    else top
                )
                output_dir = os.path.join(
                    os.path.dirname(os.path.abspath(root)), self.decrypt_name(top)
                )
            else:
                output_dir = root

        output_dir = os.path.normpath(output_dir)
        skip = os.path.abspath(output_dir)
        in_place = skip == os.path.abspath(root)
        results = []

        for cur, dirs, files in os.walk(root):
            if recursive:
                dirs[:] = sorted(
                    d
                    for d in dirs
                    if not os.path.islink(os.path.join(cur, d))
                    and os.path.abspath(os.path.join(cur, d)) != skip
                )
            else:
                dirs[:] = []

            rel = os.path.relpath(cur, root)
            parts = (
                []
                if rel == "."
                else [
                    self.decrypt_name(p) if decrypt_dirnames else p
                    for p in rel.split(os.sep)
                ]
            )
            outdir = os.path.join(output_dir, *parts)

            for f in sorted(files):
                src = os.path.join(cur, f)

                if (
                    not f.endswith(SUFFIX)
                    or f == SUFFIX
                    or os.path.islink(src)
                    or not os.path.isfile(src)
                ):
                    continue

                stem = f[: -len(SUFFIX)]
                outname = self.decrypt_name(stem) if decrypt_filenames else stem
                results.append(
                    self.decrypt_file(
                        src,
                        os.path.join(outdir, outname),
                        remove_original=remove_original,
                    )
                )

        if remove_original and not in_place:
            _prune_empty_dirs(root)

        return results


def encrypt_file_with_password(
    file_path, password, output_path=None, encrypt_filename=False, remove_original=False
):
    return AES256(password=password).encrypt_file(
        file_path,
        output_path,
        encrypt_filename=encrypt_filename,
        remove_original=remove_original,
    )


def decrypt_file_with_password(
    file_path, password, output_path=None, decrypt_filename=False, remove_original=False
):
    return AES256(password=password).decrypt_file(
        file_path,
        output_path,
        decrypt_filename=decrypt_filename,
        remove_original=remove_original,
    )
