# cryptophoto

AES-256 CBC file encryption library with support for individual files and directory batch operations.

A simple and powerful AES-256 encryption library for Python, supporting:

✅ Password-based key derivation (PBKDF2)  
✅ Random binary keys  
✅ File encryption/decryption  
✅ Directory encryption/decryption  
✅ Key saving/loading  
✅ Automatic handling of salts and IVs  
✅ Minimal and easy-to-use interface  

---

## Features

- AES-256 encryption using CBC mode
- Secure key derivation using PBKDF2 (100k iterations)
- Automatic IV generation
- Optional extension filtering when encrypting directories
- Metadata handling (salt + IV stored in encrypted file)
- Utility functions for one-line encryption/decryption

---

## Installation

You need **pycryptodome**:

```sh
pip install pycryptodome
```

---

## Basic Usage

### Encrypt a file with a password

```python
from brachinus import encrypt_file_with_password

encrypt_file_with_password("example.txt", "mysecretpassword")
```

This generates a file:

```
example.txt.enc
```

---

### Decrypt a file with a password

```python
from brachinus import decrypt_file_with_password

decrypt_file_with_password("example.txt.enc", "mysecretpassword")
```

---

## Using AES256 Class Directly

### Create an instance with a password

```python
from brachinus import AES256

aes = AES256(password="mypassword")
aes.encrypt_file("data.pdf")
aes.decrypt_file("data.pdf.enc")
```

---

### Using a binary key instead of a password

```python
aes = AES256()  # generates a random 32-byte key
print(aes.key)
```

---

### Save and load a binary key

#### Save the key

```python
aes = AES256()
aes.save_key("aes.key")
```

#### Load the key

```python
loaded = AES256.load_from_keyfile("aes.key")
```

---

## Directory Encryption

### Encrypt all files in a directory

```python
aes = AES256(password="mypassword")
aes.encrypt_directory("myfolder")
```

Creates a folder:

```
myfolder_encrypted/
```

---

### Encrypt only specific file types

```python
aes.encrypt_directory("photos", extensions=[".jpg", ".png"])
```

---

## Directory Decryption

```python
aes.decrypt_directory("myfolder_encrypted")
```

Creates:

```
myfolder_encrypted_decrypted/
```

---

## Key Information

You can read key metadata:

```python
info = aes.get_key_info()
print(info)
```

Example output:

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

## Encrypted File Structure

The encrypted file is stored as:

```
[SALT_LENGTH (4 bytes)] [SALT (optional)] [IV (16 bytes)] [ENCRYPTED_DATA]
```

Notes:

- Salt is stored only for password-based encryption
- IV is always stored
- Ensures correct decryption even if the program restarts or key is regenerated

---

## Security Notes

⚠️ **Never reuse the same password + salt combination manually.**  
⚠️ Keep your password and salt safe.  
⚠️ For maximum security, use long passwords with high entropy.

---