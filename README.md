<h1 align="center">brachinus</h1>

<p align="center">
  <img src="https://img.shields.io/pypi/dm/brachinus?style=flat-square">
  <img src="https://img.shields.io/pypi/l/brachinus?style=flat-square">
  <img src="https://img.shields.io/github/v/tag/JuanBindez/brachinus?include_prereleases&style=flat-square">
  <img src="https://img.shields.io/pypi/v/brachinus?style=flat-square">
</p>

<h2 align="center">
  Authenticated AES-256-GCM file encryption for Python, with a Unix-style command-line tool.
</h2>

### Single files, whole directories, encrypted file names, pipes

Brachinus is a small, safe-by-default encryption library for Python. It supports password-based keys, random binary keys, file and directory encryption, optional encryption of file and directory names, and includes a CLI that follows Unix conventions.

---

## Features

- AES-256-GCM, authenticated: a wrong password or a modified file is always detected
- Streaming, chunked encryption: files of any size, constant memory
- PBKDF2-HMAC-SHA256 key derivation (600,000 iterations, stored in the file header)
- Versioned file format; truncation and reordering of data are detected
- Atomic writes: a failure never leaves a half-written file
- Originals are kept unless you ask to remove them
- File and directory encryption/decryption, with extension filtering
- File name and directory name encryption (authenticated, path-traversal safe)
- Key saving/loading utilities
- Reads files written by brachinus 1.x (AES-CBC)
- Unix-style command-line interface: silent on success, pipes, exit codes, per-file errors

---

## Installation

    pip install brachinus

Or from source:

    git clone https://github.com/JuanBindez/brachinus
    cd brachinus
    pip install .

---

## Quick Start (Python API)

### With a password

```python
from brachinus import AES256

crypt = AES256(password="password123")

enc = crypt.encrypt_file("file.txt")        # writes file.txt.enc, keeps file.txt
crypt.decrypt_file(enc, "restored.txt")
```

### With a random binary key

```python
aes = AES256()
aes.save_key("aes.key")                     # file mode 0600

loaded = AES256.load_from_keyfile("aes.key")
```

### Encrypted file names

```python
enc = crypt.encrypt_file("secret plans.txt", encrypt_filename=True)
# enc is something like "5pJm....enc"; the original name is inside it

crypt.decrypt_file(enc, decrypt_filename=True)   # restores "secret plans.txt"
```

### Removing the original

By default the original file is **kept**. Pass `remove_original=True` to delete it after the output was written successfully:

```python
crypt.encrypt_file("file.txt", remove_original=True)
crypt.decrypt_file("file.txt.enc", remove_original=True)   # deletes the .enc
```

> `backup=` from earlier versions is deprecated and still accepted: `backup=True` means `remove_original=False`, and `backup=False` means `remove_original=True`.

### Key information

```python
aes.get_key_info()
# {"key": b"...", "key_hex": "a4f5...", "key_type": "random"}

crypt.get_key_info()
# {"key": ..., "key_hex": ..., "key_type": "password-derived",
#  "salt": ..., "salt_hex": ..., "iterations": 600000}
```

Password-derived keys cannot be saved with `save_key()`; keep the password instead.

### Errors

All errors derive from `BrachinusError` (and also from `ValueError`):

| Exception | Meaning |
|-----------|---------|
| `InvalidKeyError` | bad key size, empty password, bad salt |
| `FormatError` | not a brachinus file, or structurally damaged |
| `DecryptionError` | wrong password/key, or the data was modified or truncated |

```python
from brachinus import AES256, DecryptionError

try:
    AES256(password="wrong").decrypt_file("file.txt.enc")
except DecryptionError as e:
    print(e)
```

---

## Directories

`encrypt_directory()` and `decrypt_directory()` return the list of files they wrote. Directories are processed **in place** by default: each file gets its `.enc` next to the original, and directories are never renamed with `.enc`. Symbolic links are skipped, and files already ending in `.enc` are not encrypted again.

```python
aes.encrypt_directory("myfolder", recursive=True)                       # keep originals
aes.encrypt_directory("myfolder", recursive=True, remove_original=True)
aes.encrypt_directory("myfolder", recursive=True, output_dir="vault")   # write elsewhere
aes.encrypt_directory("photos", recursive=True, extensions=[".jpg", ".png"])
```

Encrypted names (a new sibling directory with an encrypted name is created, so use `remove_original=True` to replace the tree):

```python
aes.encrypt_directory(
    "myfolder",
    recursive=True,
    encrypt_filenames=True,
    encrypt_dirnames=True,
    remove_original=True,
)
```

Decryption is symmetrical:

```python
aes.decrypt_directory("myfolder", recursive=True, remove_original=True)

aes.decrypt_directory(
    "5pJm...",                    # the encrypted directory name shown by ls
    recursive=True,
    decrypt_filenames=True,
    decrypt_dirnames=True,
    remove_original=True,
)
```

Without `recursive=True` only the files directly inside the directory are processed.

---

## File format (version 2)

```
"BRCH" | version(1)=2 | kdf(1) | iterations(4) | chunk_log2(1)
       | salt(16, password mode only) | nonce_prefix(8)
       | chunk_0 | chunk_1 | ... | chunk_n
```

- `kdf` is `0` for a raw 32-byte key and `1` for PBKDF2-HMAC-SHA256.
- Each chunk (1 MiB by default) is AES-256-GCM ciphertext followed by a 16-byte tag.
- The nonce of a chunk is `nonce_prefix || chunk_index`, and the authenticated data is the whole header plus a flag marking the last chunk. Wrong keys, tampering, reordering and truncation therefore all fail authentication.
- Names are encrypted with AES-256-GCM too, using a key derived from the main key.

Files written by brachinus 1.x (AES-CBC, no authentication) can still be decrypted. They are never produced any more, and **files written by this version cannot be read by brachinus 1.x**.

---

## Command Line Interface (CLI)

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
| `--remove` | Delete each input file after its output was written successfully |
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

Directories require `-r` and are processed **in place**: only files get the `.enc` suffix, directories keep their names.

```
$ brachinus encrypt -r -k aes.key docs
$ tree docs
docs
├── a.txt
├── a.txt.enc
└── notes
    ├── b.txt
    └── b.txt.enc
```

Add `--remove` to keep only the encrypted files:

```
$ brachinus encrypt -r -k aes.key --remove docs
$ tree docs
docs
├── a.txt.enc
└── notes
    └── b.txt.enc

$ brachinus decrypt -r -k aes.key --remove docs
```

If the originals still exist when decrypting, `decrypt` reports `already exists (use -f to overwrite)` for each of them. Use `-f` to overwrite, or `--remove` when encrypting.

Only encrypt some file types:

```
$ brachinus encrypt -r -k aes.key -e jpg -e .png photos
```

Files already ending in `.enc` are skipped when encrypting a directory.

### Encrypted names

`--encrypt-names` encrypts file names and directory names, including the top-level directory. Because the top-level name changes, a new directory is created next to the original, so combine it with `--remove` to replace the tree:

```
$ brachinus encrypt -r -k aes.key --encrypt-names --remove docs
$ ls
5pJmQx...Wq0
$ tree 5pJmQx...Wq0
5pJmQx...Wq0
├── Zk3v...Hd8.enc
└── Lr9T...n2A
    └── Y7bC...u1E.enc
```

Directories have no `.enc` suffix; files do. There is no flag for decryption: `decrypt` detects encrypted names automatically and restores the originals. Use the encrypted name shown by `ls`:

```
$ brachinus -v decrypt -r -k aes.key --remove 5pJmQx...Wq0
brachinus: 5pJmQx...Wq0/Zk3v...Hd8.enc -> docs/a.txt
```

If a name cannot be decrypted (wrong key, or it was never encrypted), it is kept as it is.

**Name length limit.** Encrypted names are longer than the originals, and most filesystems limit a name to 255 bytes. In practice file names up to about 139 bytes work with a password and about 159 bytes with a key file. When an encrypted name would not fit, that file is reported and skipped, and the others continue:

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

### Deleting the originals

```
$ brachinus encrypt -r -k aes.key --remove docs
```

An original is removed only after its own output was written successfully, and only if that output exists and is a different file. On a failure (for example a wrong password) nothing is removed. Directories emptied this way are removed as well.

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

The key is derived once per run, so a batch of files pays the password-hashing cost only once.

### Key management

```
$ brachinus key generate aes.key
$ ls -l aes.key
-rw------- 1 user user 32 ... aes.key

$ brachinus key show aes.key
type:         random
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

$ brachinus decrypt --password-file wrong.txt photo.jpg.enc
brachinus: photo.jpg.enc: authentication failed (wrong password/key, or the file was modified or truncated)

$ brachinus decrypt -k aes.key notes.txt.enc      # a file that is not from brachinus
brachinus: notes.txt.enc: not a brachinus file

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

Files encrypted with the old CLI can still be decrypted by the new one. New files use the version 2 format and cannot be opened by old versions.

---

## Security Notes

⚠️ Use strong passwords; the key is only as strong as the password  
⚠️ Keep .key files secure (the CLI warns if they are readable by other users)  
⚠️ Lost passwords or keys cannot be recovered  
⚠️ A wrong password or a modified file is detected by authentication, but the data cannot be recovered without the right key  
⚠️ Do not pass your own `salt` to `AES256()` unless you know why; by default a random one is generated  
⚠️ The CLI keeps originals by default; `--remove` and `remove_original=True` permanently delete them after a successful write  
⚠️ File sizes, the number of files and the directory layout are not hidden; `--encrypt-names` only hides the names  
⚠️ Always test with non-critical data first

---