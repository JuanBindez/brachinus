#!/usr/bin/env python3
"""brachinus - command line interface for the brachinus AES256 library.

    brachinus encrypt [options] [FILE...]
    brachinus decrypt [options] [FILE...]
    brachinus key generate FILE
    brachinus key show [--reveal] FILE

All cryptography is done by brachinus.AES256; this module only handles the
command line, file selection, naming, error reporting and safe output.

Conventions followed:
  * silence on success; messages go to stderr, data goes to stdout;
  * errors look like "brachinus: FILE: message" and set a non-zero status;
  * '-' (or no FILE) means stdin/stdout, so it works in pipelines;
  * a failure on one file does not stop the others;
  * outputs are produced in a private temp dir and renamed into place;
  * originals are kept unless --remove is given.

Exit status: 0 success, 1 runtime error, 2 usage error, 130 interrupted.
"""

import argparse
import base64
import contextlib
import getpass
import hashlib
import os
import shutil
import signal
import stat
import sys
import tempfile

from tqdm import tqdm

from brachinus.version import __version__
from brachinus import AES256

PROG = "brachinus"
SUFFIX = ".enc"
NAME_MAX = 255  # bytes per path component on most filesystems


# --------------------------------------------------------------------------
# Errors and logging
# --------------------------------------------------------------------------

class CliError(Exception):
    def __init__(self, message, path=None):
        super().__init__(message)
        self.message = message
        self.path = path


class Fatal(CliError):
    """Aborts the whole run instead of just the current file."""


class Log:
    def __init__(self, verbose=False, quiet=False):
        self.quiet = quiet
        self.verbose = verbose and not quiet
        self.failures = 0

    @staticmethod
    def _emit(msg):
        # tqdm.write keeps an active progress bar intact
        tqdm.write(f"{PROG}: {msg}", file=sys.stderr)

    def error(self, msg):
        self.failures += 1
        self._emit(msg)

    def warn(self, msg):
        if not self.quiet:
            self._emit(f"warning: {msg}")

    def note(self, msg):
        if self.verbose:
            self._emit(msg)

    def fail(self, exc, path=None):
        if isinstance(exc, CliError):
            where, msg = exc.path or path, exc.message
        elif isinstance(exc, OSError):
            where, msg = exc.filename or path, exc.strerror or str(exc)
        else:
            where, msg = path, str(exc)
        self.error(f"{where}: {msg}" if where else msg)


# --------------------------------------------------------------------------
# Cipher: key file or password -> AES256 (created lazily, once per run)
# --------------------------------------------------------------------------

def read_password(args, confirm):
    try:
        if args.password_file:
            with open(args.password_file, "r", encoding="utf-8") as f:
                password = f.readline()
        elif args.password_fd is not None:
            with os.fdopen(args.password_fd, "r", encoding="utf-8", closefd=False) as f:
                password = f.readline()
        else:
            password = getpass.getpass("Password: ")

            if confirm and getpass.getpass("Verify password: ") != password:
                raise Fatal("passwords do not match")
    except EOFError:
        raise Fatal("unexpected end of input while reading the password")
    except OSError as e:
        raise Fatal(e.strerror or str(e), e.filename)

    password = password.rstrip("\r\n")

    if not password:
        raise Fatal("empty password")

    return password


class Cipher:
    def __init__(self, args, confirm, log):
        self._args = args
        self._confirm = confirm
        self._log = log
        self._aes = None

    @property
    def aes(self):
        if self._aes is None:
            self._aes = self._build()

        return self._aes

    def _build(self):
        args = self._args

        if args.key_file:
            if os.stat(args.key_file).st_mode & 0o077:
                self._log.warn(f"{args.key_file}: key file is accessible by other users (chmod 600)")

            with open(args.key_file, "rb") as f:
                key = f.read()

            try:
                return AES256(key=key)
            except Exception as e:
                raise Fatal(str(e), args.key_file)

        password = read_password(args, self._confirm)

        try:
            return AES256(password=password)
        except Exception as e:
            raise Fatal(str(e))


class Names:
    """Filename encryption through AES256.encrypt_name / decrypt_name."""

    def __init__(self, cipher):
        self._cipher = cipher
        self._cache = {}

    def encrypt(self, name):
        if name not in self._cache:
            token = self._cipher.aes.encrypt_name(name)

            if not isinstance(token, str) or not token or "/" in token or "\x00" in token:
                raise CliError(f"cannot use the encrypted form of {name!r} as a file name")

            self._cache[name] = token

        return self._cache[name]

    def decrypt(self, token):
        """Original name if token is an encrypted name; otherwise token itself."""
        try:
            name = self._cipher.aes.decrypt_name(token)
        except Exception:
            return token

        if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\x00" in name:
            return token

        return name


# --------------------------------------------------------------------------
# Doing the work: one file, one output, atomically
# --------------------------------------------------------------------------

def current_umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


def process(encrypting, aes, src, dest, force):
    """src: path or None (stdin). dest: path or '-' (stdout)."""
    if dest == "-":
        parent = None
    else:
        if os.path.lexists(dest) and not force:
            raise CliError("already exists (use -f to overwrite)", dest)

        if os.path.isdir(dest):
            raise CliError("is a directory", dest)

        parent = os.path.dirname(dest) or "."
        os.makedirs(parent, exist_ok=True)

    # Private (0700) work dir next to the destination, so the final rename is atomic.
    with tempfile.TemporaryDirectory(prefix=".brachinus-", dir=parent) as work:
        if src is None:
            src_path = os.path.join(work, "stdin" if encrypting else "stdin" + SUFFIX)

            with open(src_path, "wb") as f:
                shutil.copyfileobj(sys.stdin.buffer, f)

            mode = 0o666 & ~current_umask()
        else:
            src_path = src
            mode = (
                stat.S_IMODE(os.stat(src).st_mode)
                if encrypting
                else 0o666 & ~current_umask()
            )

        out_path = os.path.join(work, "out" + SUFFIX if encrypting else "out")

        try:
            if encrypting:
                produced = aes.encrypt_file(
                    src_path, out_path, encrypt_filename=False, backup=True
                )
            else:
                produced = aes.decrypt_file(
                    src_path, out_path, decrypt_filename=False, backup=True
                )
        except OSError:
            raise
        except Exception as e:
            if encrypting:
                raise CliError(f"encryption failed: {e}")

            raise CliError(f"decryption failed: {e} (wrong password/key or corrupted file?)")

        result = out_path

        if isinstance(produced, (str, os.PathLike)) and os.path.exists(produced):
            result = os.fspath(produced)

        if not os.path.exists(result):
            raise CliError("the library did not produce an output file")

        if dest == "-":
            with open(result, "rb") as f:
                shutil.copyfileobj(f, sys.stdout.buffer)

            sys.stdout.buffer.flush()
        else:
            os.chmod(result, mode)
            os.replace(result, dest)


def prune_empty_dirs(removed, tops):
    """After --remove, drop directories that were emptied by it."""

    def inside(d):
        return any(d == t or d.startswith(t + os.sep) for t in tops)

    dirs = set()

    for path in removed:
        d = os.path.dirname(path)

        while d and inside(d) and d not in dirs:
            dirs.add(d)
            d = os.path.dirname(d)

    for d in sorted(dirs, key=len, reverse=True):
        with contextlib.suppress(OSError):
            os.rmdir(d)


# --------------------------------------------------------------------------
# Planning: which file goes where
# --------------------------------------------------------------------------

def output_is_dir(args):
    out = args.output

    if not out or out == "-":
        return False

    return (
        os.path.isdir(out)
        or out.endswith(("/", os.sep))
        or len(args.files) > 1
        or any(f != "-" and os.path.isdir(f) for f in args.files)
    )


def dir_parts(arg):
    """(normalized path, directory's own name, directory containing it)."""
    base = os.path.normpath(arg)
    top = os.path.basename(os.path.abspath(arg))

    if os.path.basename(base) in (".", ".."):
        parent = os.path.dirname(os.path.abspath(arg))
    else:
        parent = os.path.dirname(base)

    return base, top, parent


def check_length(name, original, encrypted):
    size = len(os.fsencode(name))

    if size > NAME_MAX:
        if encrypted:
            raise CliError(
                f"encrypted name of {original!r} is {size} bytes (limit {NAME_MAX}); "
                "use a shorter name or drop --encrypt-names"
            )

        raise CliError(f"File name too long ({size} bytes, limit {NAME_MAX})")


def enc_component(names, name, args, suffix=""):
    out = names.encrypt(name) if args.encrypt_names else name
    out += suffix
    check_length(out, name, args.encrypt_names)
    return out


def plan_encrypt(args, names, log):
    """Returns ([(src, dest)], [top_dirs])."""
    jobs, tops = [], []
    out = args.output
    into_dir = output_is_dir(args)

    for arg in args.files:
        if arg == "-":
            jobs.append((None, out or "-"))
            continue

        if not os.path.lexists(arg):
            log.error(f"{arg}: No such file or directory")
            continue

        if not os.path.isdir(arg):
            try:
                if out == "-":
                    dest = "-"
                elif out and not into_dir:
                    dest = out
                else:
                    outname = enc_component(names, os.path.basename(arg), args, SUFFIX)
                    dest = os.path.join(out if into_dir else os.path.dirname(arg), outname)
            except CliError as e:
                log.error(f"{arg}: {e.message}")
                continue

            jobs.append((arg, dest))
            continue

        if not args.recursive:
            log.error(f"{arg}: is a directory (use -r)")
            continue

        base, top, parent = dir_parts(arg)

        if not top:
            log.error(f"{arg}: cannot process the root directory")
            continue

        try:
            top_out = enc_component(names, top, args, SUFFIX)
        except CliError as e:
            log.error(f"{arg}: {e.message}")
            continue

        if out and len(args.files) == 1:
            outroot = out
        elif out:
            outroot = os.path.join(out, top_out)
        else:
            outroot = os.path.join(parent, top_out)

        skip = os.path.abspath(outroot)
        tops.append(base)
        count = 0

        for root, dirs, files in os.walk(base, onerror=log.fail):
            dirs[:] = sorted(
                d for d in dirs if os.path.abspath(os.path.join(root, d)) != skip
            )
            rel = os.path.relpath(root, base)

            try:
                parts = [] if rel == "." else [
                    enc_component(names, p, args) for p in rel.split(os.sep)
                ]
            except CliError as e:
                log.error(f"{root}: {e.message}")
                dirs[:] = []
                continue

            outdir = os.path.join(outroot, *parts)

            for f in sorted(files):
                src = os.path.join(root, f)

                if f.endswith(SUFFIX):
                    continue

                if args.ext and os.path.splitext(f)[1].lower() not in args.ext:
                    continue

                if not os.path.isfile(src):
                    log.warn(f"{src}: not a regular file, skipped")
                    continue

                try:
                    outname = enc_component(names, f, args, SUFFIX)
                except CliError as e:
                    log.error(f"{src}: {e.message}")
                    continue

                jobs.append((src, os.path.join(outdir, outname)))
                count += 1

        if not count:
            log.warn(f"{arg}: no files to encrypt")

    return jobs, tops


def plan_decrypt(args, names, log):
    """Returns ([(src, dest)], [top_dirs])."""
    jobs, tops = [], []
    out = args.output
    into_dir = output_is_dir(args)

    for arg in args.files:
        if arg == "-":
            if out and out != "-" and os.path.isdir(out):
                log.error("(stdin): -o must be a file, not a directory")
                continue

            jobs.append((None, out or "-"))
            continue

        if not os.path.lexists(arg):
            log.error(f"{arg}: No such file or directory")
            continue

        if not os.path.isdir(arg):
            if out == "-":
                dest = "-"
            elif out and not into_dir:
                dest = out
            else:
                fname = os.path.basename(arg)

                if not fname.endswith(SUFFIX) or fname == SUFFIX:
                    log.error(f"{arg}: unknown suffix (expected {SUFFIX}); use -o FILE")
                    continue

                dest = os.path.join(
                    out if into_dir else os.path.dirname(arg),
                    names.decrypt(fname[: -len(SUFFIX)]),
                )

            jobs.append((arg, dest))
            continue

        if not args.recursive:
            log.error(f"{arg}: is a directory (use -r)")
            continue

        base, top, parent = dir_parts(arg)

        if not top:
            log.error(f"{arg}: cannot process the root directory")
            continue

        if top.endswith(SUFFIX) and top != SUFFIX:
            top_out = names.decrypt(top[: -len(SUFFIX)])
        else:
            top_out = top + "_decrypted"

        if out and len(args.files) == 1:
            outroot = out
        elif out:
            outroot = os.path.join(out, top_out)
        else:
            outroot = os.path.join(parent, top_out)

        tops.append(base)
        count = 0

        for root, dirs, files in os.walk(base, onerror=log.fail):
            dirs.sort()
            rel = os.path.relpath(root, base)
            parts = [] if rel == "." else [names.decrypt(p) for p in rel.split(os.sep)]
            outdir = os.path.join(outroot, *parts)

            for f in sorted(files):
                if f.endswith(SUFFIX) and f != SUFFIX:
                    jobs.append(
                        (os.path.join(root, f),
                         os.path.join(outdir, names.decrypt(f[: -len(SUFFIX)])))
                    )
                    count += 1

        if not count:
            log.warn(f"{arg}: no {SUFFIX} files found")

    return jobs, tops


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def run_crypto(args, parser, log):
    encrypting = args.cmd == "encrypt"

    if not args.files:
        if sys.stdin.isatty():
            parser.error("no input files (use '-' for stdin)")

        args.files = ["-"]

    if "-" in args.files and len(args.files) > 1:
        parser.error("'-' (stdin) cannot be combined with other files")

    if args.output == "-":
        if len(args.files) != 1 or (args.files[0] != "-" and os.path.isdir(args.files[0])):
            parser.error("'-o -' needs exactly one input file")

        if args.remove:
            parser.error("--remove cannot be combined with '-o -'")

    if encrypting:
        args.ext = [
            e.lower() if e.startswith(".") else "." + e.lower() for e in (args.ext or [])
        ]

    cipher = Cipher(args, confirm=encrypting, log=log)
    names = Names(cipher)
    jobs, tops = (plan_encrypt if encrypting else plan_decrypt)(args, names, log)

    if encrypting and sys.stdout.isatty() and any(dest == "-" for _, dest in jobs):
        raise Fatal("refusing to write encrypted data to a terminal (use -o FILE or redirect)")

    if jobs:
        cipher.aes  # asks for the password once, before any work starts

    show_bar = (
        not (args.quiet or args.verbose) and sys.stderr.isatty() and len(jobs) > 1
    )
    removed = []

    with tqdm(
        total=len(jobs),
        desc="Encrypting" if encrypting else "Decrypting",
        unit="file",
        file=sys.stderr,
        disable=not show_bar,
        leave=False,
    ) as bar:
        for src, dest in jobs:
            label = src or "(stdin)"

            try:
                process(encrypting, cipher.aes, src, dest, args.force)
                log.note(f"{label} -> {'(stdout)' if dest == '-' else dest}")

                if args.remove and src is not None:
                    os.unlink(src)
                    removed.append(src)
            except (KeyboardInterrupt, Fatal):
                raise
            except Exception as e:
                log.fail(e, label)

            bar.update(1)

    if removed:
        prune_empty_dirs(removed, tops)


def cmd_key(args, log):
    if args.keycmd == "generate":
        if os.path.lexists(args.path) and not args.force:
            raise CliError("already exists (use -f to overwrite)", args.path)

        aes = AES256()
        old = os.umask(0o077)

        try:
            aes.save_key(args.path)
        finally:
            os.umask(old)

        os.chmod(args.path, 0o600)
        log.note(f"key written to {args.path}")
        return

    if os.stat(args.path).st_mode & 0o077:
        log.warn(f"{args.path}: key file is accessible by other users (chmod 600)")

    info = AES256.load_from_keyfile(args.path).get_key_info()

    if args.reveal:
        print(info["key_hex"])
        return

    digest = hashlib.sha256(bytes.fromhex(info["key_hex"])).digest()
    print(f"type:         {info['key_type']}")
    print(f"fingerprint:  SHA256:{base64.b64encode(digest).decode().rstrip('=')}")


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def add_verbosity(p, default):
    p.add_argument("-v", "--verbose", action="store_true", default=default,
                   help="print one line per file on stderr")
    p.add_argument("-q", "--quiet", action="store_true", default=default,
                   help="suppress warnings and progress")


def add_common(p):
    add_verbosity(p, argparse.SUPPRESS)

    p.add_argument("files", nargs="*", metavar="FILE",
                   help="files or directories ('-' or none: stdin)")

    secret = p.add_mutually_exclusive_group()
    secret.add_argument("-k", "--key-file", metavar="FILE",
                        help="use the binary key in FILE (default: ask for a password)")
    secret.add_argument("--password-file", metavar="FILE",
                        help="read the password from the first line of FILE")
    secret.add_argument("--password-fd", metavar="N", type=int,
                        help="read the password from file descriptor N")

    p.add_argument("-o", "--output", metavar="PATH",
                   help="output file or directory ('-' for stdout)")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="process directories recursively")
    p.add_argument("-f", "--force", action="store_true",
                   help="overwrite existing files")
    p.add_argument("--remove", action="store_true",
                   help="delete each input file after it was processed successfully")


def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            f"Brachinus v{__version__}, Copyright (C) 2025 - 2026, Juan Bindez. "
            "AES-256 file encryption."
        ),
    )
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")
    add_verbosity(parser, False)

    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND", required=True)

    enc = sub.add_parser("encrypt", help="encrypt files (writes FILE.enc)")
    add_common(enc)
    enc.add_argument("-e", "--ext", action="append", metavar="EXT",
                     help="in directories, only encrypt files with this extension")
    enc.add_argument("--encrypt-names", action="store_true",
                     help="also encrypt file and directory names")

    dec = sub.add_parser("decrypt",
                         help="decrypt .enc files (encrypted names are restored automatically)")
    add_common(dec)

    key = sub.add_parser("key", help="manage key files")
    ksub = key.add_subparsers(dest="keycmd", metavar="SUBCOMMAND", required=True)

    gen = ksub.add_parser("generate", help="create a new random key file (mode 0600)")
    gen.add_argument("path", metavar="FILE", help="key file to create")
    gen.add_argument("-f", "--force", action="store_true", help="overwrite an existing file")

    show = ksub.add_parser("show", help="show the fingerprint of a key file")
    show.add_argument("path", metavar="FILE")
    show.add_argument("--reveal", action="store_true", help="print the key itself, in hex")

    return parser, {"encrypt": enc, "decrypt": dec}


def main(argv=None):
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    parser, subparsers = build_parser()
    args = parser.parse_args(argv)
    log = Log(verbose=args.verbose, quiet=args.quiet)

    try:
        if args.cmd == "key":
            cmd_key(args, log)
        else:
            run_crypto(args, subparsers[args.cmd], log)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        log.fail(e)

    return 1 if log.failures else 0


if __name__ == "__main__":
    sys.exit(main())