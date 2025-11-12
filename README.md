# brachinus

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

# Usage (Python API)

## Encrypt a file with a password

```python
from brachinus import encrypt_file_with_password

encrypt_file_with_password("example.txt", "mypassword")
```

Creates:

```
example.txt.enc
```

---

## Decrypt a file

```python
from brachinus import decrypt_file_with_password

decrypt_file_with_password("example.txt.enc", "mypassword")
```

---

## Using the AES256 Class Directly

### With a password

```python
from brachinus import AES256

aes = AES256(password="mypassword")
aes.encrypt_file("data.pdf")
aes.decrypt_file("data.pdf.enc")
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
brachinus --help
```

---

## CLI Commands

### Encrypt a file

```sh
brachinus encrypt-file input.txt
```

### Encrypt a file with password

```sh
brachinus encrypt-file input.txt --password "mypassword"
```

### Decrypt a file

```sh
brachinus decrypt-file input.txt.enc --password "mypassword"
```

### Encrypt a directory

```sh
brachinus encrypt-dir myfolder --password "mypassword"
```

### Decrypt a directory

```sh
brachinus decrypt-dir myfolder_encrypted --password "mypassword"
```

### Use a keyfile instead of password

```sh
brachinus encrypt-file document.pdf --keyfile aes.key
```

---

# Security Notes

⚠️ Use strong passwords  
⚠️ Never reuse password + salt manually  
⚠️ Keep `.key` files secure  
⚠️ Lost passwords or keys cannot be recovered  

---