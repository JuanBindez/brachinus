# brachinus

[![PyPI - Downloads](https://img.shields.io/pypi/dm/brachinus)](https://pypi.org/project/brachinus/)
![PyPI - License](https://img.shields.io/pypi/l/brachinus)
[![GitHub Tag](https://img.shields.io/github/v/tag/JuanBindez/brachinus?include_prereleases)](https://github.com/JuanBindez/brachinus/releases)
[![PyPI - Version](https://img.shields.io/pypi/v/brachinus)](https://pypi.org/project/brachinus/)

## AES-256 CBC file encryption library with support for individual files and directory batch operations.

### Supports single-file and directory batch operations + command-line usage

Brachinus is a simple, secure, and feature-rich AES-256 encryption library for Python.  
It supports password-based key derivation, random binary keys, file/directory encryption, and includes a built-in CLI interface.

---

##  Features

- AES-256 encryption (CBC mode)
- PBKDF2 key derivation (100k iterations)
- Automatic IV generation
- Salt + IV metadata stored in output file
- File and directory encryption/decryption
- Optional extension filtering
- Key saving/loading utilities
- Built-in command-line interface (CLI)

---

## Installation

Install:

```sh
pip install brachinus
```

Or install from source:

```sh
git clone https://github.com/JuanBindez/brachinus
cd brachinus
pip install .
```

---

# Quick Start (Python API)


## Using the AES256 Class Directly

### With a password

```python
from brachinus import AES256

PASS_WORD = "password123"

crypt = AES256(password=PASS_WORD)
crypt.encrypt_file(
    file_path="file.txt",
    encrypt_filename=True
)

crypt.decrypt_file("file.txt.enc")
```

### With a random binary key

```python
aes = AES256()  # generates a new random key
print(aes.key)
```

### Key save/load

```python
aes.save_key("aes.key")
loaded = AES256.load_from_keyfile("aes.key")
```

---

# Directory Encryption

### Encrypt all files

```python
aes.encrypt_directory("myfolder")
```

Produces:

```
myfolder_encrypted/
```

### Encrypt only specific extensions

```python
aes.encrypt_directory("photos", extensions=[".jpg", ".png"])
```

---

# Directory Decryption

```python
aes.decrypt_directory("myfolder_encrypted")
```

Creates:

```
myfolder_encrypted_decrypted/
```

---

# Key Information

```python
info = aes.get_key_info()
print(info)
```

Example:

```json
{
    "key": "...",
    "key_hex": "a4f5...",
    "salt": "...",
    "salt_hex": "d2ab...",
    "key_type": "password-derived"
}
```

---

# Internal Encrypted File Format

```
[4 bytes salt_length] [salt (if present)] [16-byte IV] [encrypted_data]
```

- Salt only stored for password-derived keys
- IV always present
- Ensures reproducible decryption

---

# Command Line Interface (CLI)

Brachinus includes a terminal command: **`brachinus`**

After installation you can run:

```sh
brachinus -h
```

---

## CLI Commands

### Encrypt a file (opitional --encryptfilename)

```sh
brachinus -ef input.txt --encryptfilename
```

### Decrypt a file

```sh
brachinus -df input.txt.enc
```

### Encrypt a directory

```sh
brachinus -ed myfolder
```

### Decrypt a directory

```sh
brachinus -dd myfolder_encrypted
```

### Use a keyfile instead of password

```sh
brachinus -ef document.pdf --keyfile aes.key
```

### Encrypt the data/ directory, including subfolders (-r) and obfuscate filenames (--encryptfilename):

```bash
brachinus -ed data/ -r --encryptfilename
```

### Decrypt the directory, restoring the original structure and names (-r, --decryptfilename):

```bash
brachinus -dd data/_encrypted -r --decryptfilename
```
---

# Security Notes

⚠️ Use strong passwords  
⚠️ Never reuse password + salt manually  
⚠️ Keep `.key` files secure  
⚠️ Lost passwords or keys cannot be recovered  

---
