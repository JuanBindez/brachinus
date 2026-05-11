import argparse
import os
import getpass
import sys
from tqdm import tqdm

from brachinus.version import __version__
from brachinus import AES256


def wai_process_message():
    return "[*] Processing. Please wait..."


def ensure_parent(path):
    parent = os.path.dirname(path)

    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def build_encrypt_backup_base(aes, directory_path, output_dir, encrypt_dirnames):
    if output_dir:
        return output_dir

    if encrypt_dirnames:
        dir_name = os.path.basename(os.path.normpath(directory_path))
        enc_dir_name = aes.encrypt_name(dir_name)
        return os.path.join(
            os.path.dirname(directory_path),
            enc_dir_name + "_encrypted"
        )

    return directory_path + "_encrypted"


def build_decrypt_backup_base(aes, directory_path, output_dir, decrypt_dirnames):
    if output_dir:
        return output_dir

    if decrypt_dirnames:
        try:
            dir_name = os.path.basename(os.path.normpath(directory_path))
            original_name = aes.decrypt_name(dir_name)

            return os.path.join(
                os.path.dirname(directory_path),
                original_name + "_decrypted"
            )

        except Exception:
            pass

    return directory_path + "_decrypted"


def encrypt_directory_with_progress(
    aes,
    directory_path,
    output_dir,
    extensions,
    encrypt_filenames,
    encrypt_dirnames,
    recursive,
    backup,
    total_files
):
    backup_base = None

    if backup:
        backup_base = build_encrypt_backup_base(
            aes,
            directory_path,
            output_dir,
            encrypt_dirnames
        )

        os.makedirs(backup_base, exist_ok=True)

    with tqdm(total=total_files, desc="[*] Encrypting", ncols=80) as bar:
        for root, dirs, files in os.walk(directory_path):
            if not recursive:
                dirs[:] = []

            if backup and encrypt_dirnames:
                relative_root = os.path.relpath(root, directory_path)

                if relative_root == ".":
                    current_backup_root = backup_base
                else:
                    encrypted_parts = []

                    for part in relative_root.split(os.sep):
                        encrypted_parts.append(aes.encrypt_name(part))

                    current_backup_root = os.path.join(
                        backup_base,
                        *encrypted_parts
                    )
            elif backup:
                relative_root = os.path.relpath(root, directory_path)

                if relative_root == ".":
                    current_backup_root = backup_base
                else:
                    current_backup_root = os.path.join(
                        backup_base,
                        relative_root
                    )

            for file in files:
                if file.endswith(".enc"):
                    continue

                if extensions:
                    ext = os.path.splitext(file)[1].lower()

                    if ext not in extensions:
                        continue

                full_path = os.path.join(root, file)

                if backup:
                    if encrypt_filenames:
                        encrypted_filename = aes.encrypt_name(file) + ".enc"
                    else:
                        encrypted_filename = file + ".enc"

                    new_path = os.path.join(
                        current_backup_root,
                        encrypted_filename
                    )
                else:
                    if encrypt_filenames:
                        encrypted_filename = aes.encrypt_name(file) + ".enc"
                        new_path = os.path.join(root, encrypted_filename)
                    else:
                        new_path = full_path + ".enc"

                ensure_parent(new_path)

                aes.encrypt_file(
                    full_path,
                    new_path,
                    encrypt_filename=False,
                    backup=True
                )

                if not backup and os.path.exists(full_path):
                    os.unlink(full_path)

                bar.update(1)

        if encrypt_dirnames and not backup:
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for dir_name in dirs:
                    full_dir_path = os.path.join(root, dir_name)

                    try:
                        encrypted_name = aes.encrypt_name(dir_name)

                        new_dir_path = os.path.join(
                            root,
                            encrypted_name
                        )

                        if (
                            os.path.exists(full_dir_path)
                            and not os.path.exists(new_dir_path)
                        ):
                            os.rename(full_dir_path, new_dir_path)

                    except Exception:
                        pass

                if not recursive:
                    break


def decrypt_directory_with_progress(
    aes,
    directory_path,
    output_dir,
    decrypt_filenames,
    decrypt_dirnames,
    recursive,
    backup,
    total_files
):
    backup_base = None

    if backup:
        backup_base = build_decrypt_backup_base(
            aes,
            directory_path,
            output_dir,
            decrypt_dirnames
        )

        os.makedirs(backup_base, exist_ok=True)

    with tqdm(total=total_files, desc="[*] Decrypting", ncols=80) as bar:
        for root, dirs, files in os.walk(directory_path):
            if not recursive:
                dirs[:] = []

            if backup and decrypt_dirnames:
                relative_root = os.path.relpath(root, directory_path)

                if relative_root == ".":
                    current_backup_root = backup_base
                else:
                    decrypted_parts = []

                    for part in relative_root.split(os.sep):
                        try:
                            decrypted_parts.append(aes.decrypt_name(part))
                        except Exception:
                            decrypted_parts.append(part)

                    current_backup_root = os.path.join(
                        backup_base,
                        *decrypted_parts
                    )
            elif backup:
                relative_root = os.path.relpath(root, directory_path)

                if relative_root == ".":
                    current_backup_root = backup_base
                else:
                    current_backup_root = os.path.join(
                        backup_base,
                        relative_root
                    )

            for file in files:
                if not file.endswith(".enc"):
                    continue

                full_path = os.path.join(root, file)

                if backup:
                    if decrypt_filenames:
                        encrypted_name = file[:-4]

                        try:
                            output_name = aes.decrypt_name(encrypted_name)
                        except Exception:
                            output_name = encrypted_name
                    else:
                        output_name = file[:-4]

                    new_path = os.path.join(
                        current_backup_root,
                        output_name
                    )
                else:
                    if decrypt_filenames:
                        encrypted_name = file[:-4]

                        try:
                            output_name = aes.decrypt_name(encrypted_name)
                        except Exception:
                            output_name = encrypted_name

                        new_path = os.path.join(root, output_name)
                    else:
                        new_path = full_path[:-4]

                ensure_parent(new_path)

                aes.decrypt_file(
                    full_path,
                    new_path,
                    decrypt_filename=False,
                    backup=True
                )

                if not backup and os.path.exists(full_path):
                    os.unlink(full_path)

                bar.update(1)

        if decrypt_dirnames and not backup:
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for dir_name in dirs:
                    full_dir_path = os.path.join(root, dir_name)

                    try:
                        original_name = aes.decrypt_name(dir_name)

                        original_dir_path = os.path.join(
                            root,
                            original_name
                        )

                        if (
                            original_name != dir_name
                            and not os.path.exists(original_dir_path)
                        ):
                            os.rename(full_dir_path, original_dir_path)

                    except Exception:
                        pass

                if not recursive:
                    break


def count_encrypt_files(directory_path, recursive, extensions):
    total = 0

    for root, dirs, files in os.walk(directory_path):
        if not recursive:
            dirs[:] = []

        for file in files:
            if file.endswith(".enc"):
                continue

            if extensions:
                ext = os.path.splitext(file)[1].lower()

                if ext not in extensions:
                    continue

            total += 1

    return total


def count_decrypt_files(directory_path, recursive):
    total = 0

    for root, dirs, files in os.walk(directory_path):
        if not recursive:
            dirs[:] = []

        for file in files:
            if file.endswith(".enc"):
                total += 1

    return total


def load_aes(args):
    if args.keyfile:
        with open(args.keyfile, "rb") as f:
            key = f.read()

        return AES256(key=key)

    password = getpass.getpass("[?] Enter password: ")
    return AES256(password=password)


def main():
    parser = argparse.ArgumentParser(
        description=(
            f"Brachinus {__version__}, Copyright (C) 2025, "
            f"Juan Bindez — AES256 encryption and decryption CLI"
        )
    )

    operation_group = parser.add_mutually_exclusive_group(required=True)

    operation_group.add_argument(
        "-ef",
        "--encryptfile",
        help="Encrypt a file",
        metavar="FILE"
    )

    operation_group.add_argument(
        "-df",
        "--decryptfile",
        help="Decrypt a file",
        metavar="FILE"
    )

    operation_group.add_argument(
        "-ed",
        "--encryptdir",
        help="Encrypt all files in a directory",
        metavar="DIR"
    )

    operation_group.add_argument(
        "-dd",
        "--decryptdir",
        help="Decrypt all .enc files in a directory",
        metavar="DIR"
    )

    operation_group.add_argument(
        "-ki",
        "--keyinfo",
        action="store_true",
        help="Display key information"
    )

    operation_group.add_argument(
        "-sk",
        "--savekey",
        help="Save binary AES key to a file",
        metavar="KEYFILE"
    )

    operation_group.add_argument(
        "-lk",
        "--loadkey",
        help="Load key and print info",
        metavar="KEYFILE"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file/directory path"
    )

    parser.add_argument(
        "-k",
        "--keyfile",
        help="Path to binary key file"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output"
    )

    parser.add_argument(
        "--encryptfilename",
        action="store_true",
        help="Encrypt filenames"
    )

    parser.add_argument(
        "--decryptfilename",
        action="store_true",
        help="Decrypt encrypted filenames"
    )

    parser.add_argument(
        "--encryptdirname",
        action="store_true",
        help="Encrypt directory names"
    )

    parser.add_argument(
        "--decryptdirname",
        action="store_true",
        help="Decrypt encrypted directory names"
    )

    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Process directories recursively"
    )

    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create backup files/directories instead of in-place processing"
    )

    parser.add_argument(
        "-e",
        "--extension",
        action="append",
        help="Only process files with specific extensions",
        metavar="EXT"
    )

    args = parser.parse_args()

    if args.extension:
        args.extension = [
            ext.lower() if ext.startswith(".") else "." + ext.lower()
            for ext in args.extension
        ]

    if args.encryptdir:
        aes = load_aes(args)

        try:
            print("[*] Counting files...")

            total_files = count_encrypt_files(
                args.encryptdir,
                args.recursive,
                args.extension
            )

            if total_files == 0:
                print("[!] No files to encrypt")
                return

            encrypt_directory_with_progress(
                aes=aes,
                directory_path=args.encryptdir,
                output_dir=args.output,
                extensions=args.extension,
                encrypt_filenames=args.encryptfilename,
                encrypt_dirnames=args.encryptdirname,
                recursive=args.recursive,
                backup=args.backup,
                total_files=total_files
            )

            print("[+] Directory encryption completed")

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.decryptdir:
        aes = load_aes(args)

        try:
            print("[*] Counting files...")

            total_files = count_decrypt_files(
                args.decryptdir,
                args.recursive
            )

            if total_files == 0:
                print("[!] No .enc files found")
                return

            decrypt_directory_with_progress(
                aes=aes,
                directory_path=args.decryptdir,
                output_dir=args.output,
                decrypt_filenames=args.decryptfilename,
                decrypt_dirnames=args.decryptdirname,
                recursive=args.recursive,
                backup=args.backup,
                total_files=total_files
            )

            print("[+] Directory decryption completed")

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.encryptfile:
        aes = load_aes(args)

        try:
            print(wai_process_message())

            output_file = aes.encrypt_file(
                args.encryptfile,
                args.output,
                encrypt_filename=args.encryptfilename,
                backup=args.backup
            )

            print("[+] File encrypted!")
            print("[+] Output:", output_file)

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.decryptfile:
        aes = load_aes(args)

        try:
            print(wai_process_message())

            output_file = aes.decrypt_file(
                args.decryptfile,
                args.output,
                decrypt_filename=args.decryptfilename,
                backup=args.backup
            )

            print("[+] File decrypted!")
            print("[+] Output:", output_file)

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.keyinfo:
        try:
            if args.keyfile:
                aes = AES256.load_from_keyfile(args.keyfile)
            else:
                password = getpass.getpass("[?] Enter password: ")
                aes = AES256(password=password)

            print(wai_process_message())

            info = aes.get_key_info()

            print("[+] Key info:")
            print("[+] Key (hex):", info["key_hex"])

            if args.verbose:
                print("[!] Salt:", info["salt"])
                print("[!] Salt hex:", info["salt_hex"])

            print("[!] Type:", info["key_type"])

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.savekey:
        try:
            if args.keyfile:
                with open(args.keyfile, "rb") as f:
                    key = f.read()

                aes = AES256(key=key)
            else:
                aes = AES256()

            print(wai_process_message())

            aes.save_key(args.savekey)

            print("[+] Key saved!")
            print("[!] Key file:", args.savekey)

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.loadkey:
        try:
            aes = AES256.load_from_keyfile(args.loadkey)

            print(wai_process_message())

            info = aes.get_key_info()

            print("[+] Key loaded!")
            print("[!] Key hex:", info["key_hex"])

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return


if __name__ == "__main__":
    main()