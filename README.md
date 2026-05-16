<p align="center">
  <img
    width="220"
    alt="brachinus_logo"
    src="https://github.com/user-attachments/assets/0685264c-dead-4f72-891d-174d4c30b48e"
  />
</p>

<h1 align="center">brachinus</h1>

<p align="center">
  <img src="https://img.shields.io/pypi/dm/brachinus?style=flat-square">
  <img src="https://img.shields.io/pypi/l/brachinus?style=flat-square">
  <img src="https://img.shields.io/github/v/tag/JuanBindez/brachinus?include_prereleases&style=flat-square">
  <img src="https://img.shields.io/pypi/v/brachinus?style=flat-square">
</p>

<h2 align="center">
  AES-256 CBC file encryption library for Python with support for individual files and directory batch operations.
</h2>

### Supports single-file and directory batch operations + command-line usage

Brachinus is a simple, secure, and feature-rich AES-256 encryption library for Python.  
It supports password-based key derivation, random binary keys, file/directory encryption, and includes a built-in CLI interface.

---

## Features

- AES-256 encryption (CBC mode)
- PBKDF2 key derivation (100k iterations)
- Automatic IV generation
- Salt + IV metadata stored in output file
- File and directory encryption/decryption
- Optional extension filtering
- Filename encryption/decryption
- Directory name encryption/decryption
- In-place or backup mode operations
- Real-time progress bar in CLI
- Key saving/loading utilities
- Built-in command-line interface (CLI)

---

## Installation

Install:

    pip install brachinus

Or install from source:

    git clone https://github.com/JuanBindez/brachinus
    cd brachinus
    pip install .

---

## Quick Start (Python API)

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
aes = AES256()
print(aes.key)
```
### Key save/load

```python
aes.save_key("aes.key")
loaded = AES256.load_from_keyfile("aes.key")
```
---

## Directory Encryption

### Basic directory encryption (in-place)

```python
All files are encrypted in the same directory, original files are removed.
```

### Backup mode (creates new directory)

```python
aes.encrypt_directory("myfolder", backup=True)
```
Produces:

    myfolder_encrypted/

### Encrypt filenames

```python
aes.encrypt_directory("myfolder", encrypt_filenames=True, backup=False)
```
### Encrypt directory names

```python
aes.encrypt_directory("myfolder", encrypt_dirnames=True, recursive=True, backup=False)
```
### Encrypt only specific extensions

```python
aes.encrypt_directory("photos", extensions=[".jpg", ".png"], backup=False)
```
### Complete example with all options

```python
aes.encrypt_directory(
    directory_path="myfolder",
    extensions=[".txt", ".pdf"],
    encrypt_filenames=True,
    encrypt_dirnames=True,
    recursive=True,
    backup=False
)
```
---

## Directory Decryption

### Basic directory decryption (in-place)

```python
aes.decrypt_directory("myfolder", backup=False)
```
### Backup mode (creates new directory)

```python
aes.decrypt_directory("myfolder_encrypted", backup=True)
```
Creates:

    myfolder_encrypted_decrypted/

### Decrypt filenames

```python
aes.decrypt_directory("myfolder", decrypt_filenames=True, backup=False)
```
### Decrypt directory names

```python
aes.decrypt_directory("myfolder", decrypt_dirnames=True, recursive=True, backup=False)
```
### Complete example with all options

```python

aes.decrypt_directory(
    directory_path="myfolder_encrypted",
    decrypt_filenames=True,
    decrypt_dirnames=True,
    recursive=True,
    backup=False
)
```
---

## Key Information

```python
info = aes.get_key_info()
print(info)

Example:

{
    "key": "...",
    "key_hex": "a4f5...",
    "salt": "...",
    "salt_hex": "d2ab...",
    "key_type": "password-derived"
}
```

---

## Internal Encrypted File Format

[4 bytes salt_length] [salt (if present)] [16-byte IV] [encrypted_data]

- Salt only stored for password-derived keys
- IV always present
- Ensures reproducible decryption

---

## Command Line Interface (CLI)

Brachinus includes a terminal command: brachinus

After installation you can run:

    brachinus -h

---

## CLI Commands

### File Operations

#### Encrypt a file (optional --encryptfilename)

    brachinus -ef input.txt --encryptfilename

#### Decrypt a file

    brachinus -df input.txt.enc

### Directory Operations (Basic)

#### Encrypt a directory (in-place)

    brachinus -ed myfolder

#### Decrypt a directory (in-place)

    brachinus -dd myfolder

### Directory Operations with Filename Encryption

#### Encrypt with filename obfuscation

    brachinus -ed myfolder --encryptfilename

#### Decrypt with filename restoration

    brachinus -dd myfolder --decryptfilename

### Directory Operations with Directory Name Encryption

#### Encrypt directory names

    brachinus -ed myfolder -r --encryptfilename --encryptdirname

#### Decrypt directory names

    brachinus -dd myfolder -r --decryptfilename --decryptdirname

### Backup Mode (creates new directories)

#### Encrypt to backup directory

    brachinus -ed myfolder --backup

#### Decrypt from backup directory

    brachinus -dd myfolder_encrypted --backup

#### Encrypt with backup and name obfuscation

    brachinus -ed myfolder -r --encryptfilename --encryptdirname --backup

### Extension Filtering

#### Encrypt only specific file types

    brachinus -ed myfolder -r -e .txt -e .pdf --encryptfilename

### Recursive Processing

#### Process subdirectories

    brachinus -ed myfolder -r --encryptfilename

### Using Keyfile

#### Encrypt with binary key file

    brachinus -ef document.pdf --keyfile aes.key

#### Decrypt with binary key file

    brachinus -df document.pdf.enc --keyfile aes.key

### Complete Examples

#### Encrypt data/ directory including subfolders, obfuscate filenames and directory names (in-place):

    brachinus -ed data/ -r --encryptfilename --encryptdirname

#### Decrypt directory, restoring original structure, filenames and directory names (in-place):

    brachinus -dd data/ -r --decryptfilename --decryptdirname

#### Backup mode with full obfuscation:

    brachinus -ed data/ -r --encryptfilename --encryptdirname --backup

#### Filter by extension with real-time progress:

    brachinus -ed photos/ -r -e .jpg -e .png --encryptfilename

### Key Management

#### Generate and save a random key

    brachinus -sk mykey.bin

#### Load and display key information

    brachinus -lk mykey.bin -v

#### Display current key information

    brachinus -ki

---

## CLI Options Reference

| Option | Description |
|--------|-------------|
| -ef, --encryptfile | Encrypt a single file |
| -df, --decryptfile | Decrypt a single file |
| -ed, --encryptdir | Encrypt all files in a directory |
| -dd, --decryptdir | Decrypt all .enc files in a directory |
| -o, --output | Output file/directory path |
| -k, --keyfile | Path to binary key file |
| -r, --recursive | Process directories recursively |
| --encryptfilename | Encrypt filenames |
| --decryptfilename | Decrypt encrypted filenames |
| --encryptdirname | Encrypt directory names |
| --decryptdirname | Decrypt encrypted directory names |
| --backup | Create backup directories instead of in-place |
| -e, --extension | Only encrypt files with specific extensions |
| -v, --verbose | Verbose output |
| -ki, --keyinfo | Display key information |
| -sk, --savekey | Save binary AES key to a file |
| -lk, --loadkey | Load key and print info |

---

## Security Notes

⚠️ Use strong passwords  
⚠️ Never reuse password + salt manually  
⚠️ Keep .key files secure  
⚠️ Lost passwords or keys cannot be recovered  
⚠️ In-place mode (backup=False) permanently replaces original files  
⚠️ Always test with non-critical data first

---
