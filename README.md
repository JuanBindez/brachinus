<p align="center">
  <img
    width="150"
    alt="brachinus_logo"
    src="https://github.com/user-attachments/assets/b7946b12-886d-4ec1-9eb3-14502ffe4dc8"
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

### Supports single-file and directory batch operations + a Unix-style command-line tool

Brachinus is a simple, secure, and feature-rich AES-256 encryption library for Python.  
It supports password-based key derivation, random binary keys, file/directory encryption, and includes a built-in CLI that follows Unix conventions.

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
- In-place or backup mode operations (Python API)
- Key saving/loading utilities
- Unix-style command-line interface (CLI): silent on success, pipes, exit codes, per-file errors

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

Brachinus includes a terminal command: `brachinus`

```
brachinus encrypt [options] [FILE...]
brachinus decrypt [options] [FILE...]
brachinus key generate [-f] FILE
brachinus key show [--reveal] FILE
```

Run `brachinus -h`, or `brachinus encrypt -h` for the options of a subcommand.

The CLI follows Unix conventions:

- **Silent on success.** If everything worked, nothing is printed and the exit status is 0.
- **Messages go to stderr, data goes to stdout.** Errors look like `brachinus: FILE: message`.
- **Originals are kept** unless you pass `--remove`. Existing outputs are never overwritten unless you pass `-f`.
- **One failing file does not stop the others.** The error is reported and the exit status is 1 at the end.
- **Pipes work.** `-` (or no `FILE` at all) means stdin/stdout.
- **Safe output.** Each result is produced in a private temporary directory and moved into place, so a failure never leaves a half-written file.

### Options

| Option | Description |
|--------|-------------|
| `-k, --key-file FILE` | Use the binary key in `FILE` (default: ask for a password) |
| `--password-file FILE` | Read the password from the first line of `FILE` |
| `--password-fd N` | Read the password from file descriptor `N` |
| `-o, --output PATH` | Output file or directory (`-` for stdout) |
| `-r, --recursive` | Process directories recursively (required for directories) |
| `-f, --force` | Overwrite existing files |
| `--remove` | Delete each input file after it was processed successfully |
| `-e, --ext EXT` | `encrypt` only: in directories, only process files with this extension (repeatable) |
| `--encrypt-names` | `encrypt` only: also encrypt file and directory names |
| `-v, --verbose` | One line per file on stderr (`brachinus: src -> dest`) |
| `-q, --quiet` | Suppress warnings and the progress bar |
| `-V, --version` | Print the version |

`-v` and `-q` can be placed before or after the subcommand.

### Encrypt and decrypt a file

```
$ brachinus encrypt -k aes.key photo.jpg
$ ls
photo.jpg  photo.jpg.enc

$ rm photo.jpg
$ brachinus decrypt -k aes.key photo.jpg.enc
$ ls
photo.jpg  photo.jpg.enc
```

Without `-k`, the password is requested on the terminal (with confirmation when encrypting):

```
$ brachinus encrypt photo.jpg
Password:
Verify password:
```

### Directories

Directories require `-r`. The result is a new directory next to the original (`docs` becomes `docs.enc`), which is left untouched.

```
$ brachinus encrypt -r -k aes.key docs
$ brachinus decrypt -r -k aes.key docs.enc     # recreates docs/
```

Only encrypt some file types:

```
$ brachinus encrypt -r -k aes.key -e jpg -e .png photos
```

Files already ending in `.enc` are skipped when encrypting a directory.

### Encrypted names

`--encrypt-names` encrypts file names and directory names, including the top-level directory:

```
$ brachinus encrypt -r -k aes.key --encrypt-names docs
$ ls
docs  UrjepyYQsYOdwh3HPOmvBKq58cUousq6Q677EL0LYUU.enc
```

There is no flag for decryption: `decrypt` detects encrypted names automatically and restores the originals. Use the encrypted name shown by `ls`:

```
$ brachinus -v decrypt -r -k aes.key UrjepyYQsYOdwh3HPOmvBKq58cUousq6Q677EL0LYUU.enc
brachinus: UrjepyYQ....enc/Qk3x....enc -> docs/a.txt
```

If a name cannot be decrypted (wrong key, or it was never encrypted), it is kept as it is.

**Name length limit.** Encrypted names are longer than the originals, and most filesystems limit a name to 255 bytes. When an encrypted name would not fit, that file is reported and skipped, and the others continue:

```
brachinus: docs/very-long-name.txt: encrypted name of 'very-long-name.txt' is 260 bytes (limit 255); use a shorter name or drop --encrypt-names
```

### Choosing the output

```
$ brachinus encrypt -k aes.key photo.jpg -o backup/photo.enc     # exact file
$ brachinus encrypt -r -k aes.key docs -o vault/                 # directory
$ brachinus decrypt -k aes.key photo.jpg.enc -o -                # to stdout
```

- With a single file and `-o FILE`, the output is exactly `FILE`.
- With several inputs, a directory input, or an `-o` ending in `/`, `-o` is a directory.
- `-o -` writes to stdout and needs exactly one input file.
- When decrypting a directory whose name does not end in `.enc`, the default output is `NAME_decrypted`.

### Deleting the originals

```
$ brachinus encrypt -r -k aes.key --remove docs
```

An original is removed only after its own output was written successfully, and directories emptied this way are removed as well.

### Pipes

```
$ tar cz project/ | brachinus encrypt -k aes.key > project.tar.gz.enc
$ brachinus decrypt -k aes.key < project.tar.gz.enc | tar xz
```

Encrypted data is never written to a terminal:

```
brachinus: refusing to write encrypted data to a terminal (use -o FILE or redirect)
```

> The library works on file paths, so data coming from stdin is first copied to a private temporary file (mode 0700, removed afterwards). When encrypting from a pipe, the plain text briefly exists on disk. Point `TMPDIR` to a RAM disk (tmpfs) if that matters to you.

### Passwords in scripts

The password is never accepted as a command-line argument, because it would show up in `ps` and in the shell history. Use one of:

```
$ brachinus encrypt -r --password-file pass.txt docs
$ echo "secret" | brachinus encrypt -r --password-fd 0 docs
```

### Key management

```
$ brachinus key generate aes.key
$ ls -l aes.key
-rw------- 1 user user 32 ... aes.key

$ brachinus key show aes.key
type:         binary
fingerprint:  SHA256:Ivt0MqigR7QG5EqTPaHv51u7ll+flvkHPIos500b7Bc

$ brachinus key show --reveal aes.key      # prints the key itself, in hex
```

`key generate` creates the file with mode 0600 and refuses to overwrite an existing file unless `-f` is given. `key show` hides the key by default so it does not leak into logs or terminal history.

### Progress bar

For several files, a progress bar is drawn on stderr, but only when stderr is a terminal and neither `-v` nor `-q` is used. It disappears when the work is done. With `-v` you get one line per file instead.

### Exit status

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | runtime error (missing file, wrong password, name too long, output exists, ...) |
| 2 | usage error (invalid arguments) |
| 130 | interrupted with Ctrl+C |

### Common errors

```
$ brachinus encrypt missing.txt
brachinus: missing.txt: No such file or directory

$ brachinus encrypt -k aes.key photo.jpg
brachinus: photo.jpg.enc: already exists (use -f to overwrite)

$ brachinus encrypt docs
brachinus: docs: is a directory (use -r)

$ brachinus decrypt photo.jpg
brachinus: photo.jpg: unknown suffix (expected .enc); use -o FILE

$ brachinus encrypt
usage: brachinus encrypt [-h] ...
brachinus encrypt: error: no input files (use '-' for stdin)
```

### Migrating from the old CLI

| Old | New |
|-----|-----|
| `-ef FILE` | `brachinus encrypt FILE` |
| `-df FILE` | `brachinus decrypt FILE` |
| `-ed DIR` | `brachinus encrypt -r DIR` |
| `-dd DIR` | `brachinus decrypt -r DIR` |
| `--keyfile FILE` | `-k FILE` / `--key-file FILE` |
| `--encryptfilename`, `--encryptdirname` | `--encrypt-names` |
| `--decryptfilename`, `--decryptdirname` | not needed, detected automatically |
| `--backup` | removed: originals are kept by default (use `--remove` to delete them) |
| `-sk FILE` | `key generate FILE` |
| `-lk FILE`, `-ki` | `key show FILE` |
| `-e .txt` | `-e txt` (the dot is optional) |

Files encrypted with the old CLI use the same file format and can be decrypted by the new one.

---

## Security Notes

⚠️ Use strong passwords  
⚠️ Never reuse password + salt manually  
⚠️ Keep .key files secure  
⚠️ Lost passwords or keys cannot be recovered  
⚠️ The CLI keeps originals by default; `--remove` and the in-place mode of the Python API (backup=False) permanently replace them  
⚠️ CBC mode does not authenticate the data: a wrong password is normally detected through a padding error, but it cannot be guaranteed  
⚠️ Always test with non-critical data first

---