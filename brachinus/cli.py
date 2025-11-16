import argparse
import os
import getpass
import sys
from tqdm import tqdm

from brachinus.version import __version__
from brachinus import AES256, encrypt_file_with_password, decrypt_file_with_password


def wai_process_message():
    return "[*] Processing. Please wait..."

def ensure_parent(path):
    """Ensure that the parent directory exists before writing a file."""
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description=f"Brachinus {__version__}, Copyright (C) 2025, "
                    f"Juan Bindez — AES256 encryption and decryption CLI"
    )

    # Operations
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument("-ef", "--encryptfile", help="Encrypt a file", metavar="FILE")
    operation_group.add_argument("-df", "--decryptfile", help="Decrypt a file", metavar="FILE")
    operation_group.add_argument("-ed", "--encryptdir", help="Encrypt all files in a directory", metavar="DIR")
    operation_group.add_argument("-dd", "--decryptdir", help="Decrypt all .enc files in a directory", metavar="DIR")
    operation_group.add_argument("-ki", "--keyinfo", action="store_true", help="Display key information")
    operation_group.add_argument("-sk", "--savekey", help="Save binary AES key to a file", metavar="KEYFILE")
    operation_group.add_argument("-lk", "--loadkey", help="Load key and print info", metavar="KEYFILE")

    # Options
    parser.add_argument("-o", "--output", help="Output file/directory path")
    parser.add_argument("-k", "--keyfile", help="Path to binary key file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    parser.add_argument("--encryptfilename", action="store_true", help="Encrypt filenames")
    parser.add_argument("--decryptfilename", action="store_true", help="Decrypt encrypted filenames")
    parser.add_argument("-r", "--recursive", action="store_true", help="Process directories recursively")

    args = parser.parse_args()

    if args.encryptdir:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        output_dir = args.output or args.encryptdir + "_encrypted"

        print("[*] Counting files...")
        all_files = []

        for root, dirs, files in os.walk(args.encryptdir):
            for f in files:
                full_path = os.path.join(root, f)
                all_files.append(full_path)
            if not args.recursive:
                break

        with tqdm(total=len(all_files), desc="[*] Encrypting", ncols=80) as bar:
            for file_path in all_files:

                # folder structure preservation
                rel_path = os.path.relpath(file_path, args.encryptdir)
                new_path = os.path.join(output_dir, rel_path + ".enc")

                # create parent folders before saving
                ensure_parent(new_path)

                aes.encrypt_file(
                    file_path,
                    new_path,
                    encrypt_filename=args.encryptfilename
                )

                bar.update(1)

        print("[+] Directory encrypted!")
        return

    if args.decryptdir:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        output_dir = args.output or args.decryptdir + "_decrypted"

        print("[*] Counting files...")
        enc_files = []

        for root, dirs, files in os.walk(args.decryptdir):
            for f in files:
                if f.endswith(".enc"):
                    enc_files.append(os.path.join(root, f))
            if not args.recursive:
                break

        print("[*] Decrypting...")
        with tqdm(total=len(enc_files), desc="Decrypting", ncols=80) as bar:
            for enc_file in enc_files:
                rel_path = os.path.relpath(enc_file, args.decryptdir)
                rel_path = rel_path[:-4]  # remove ".enc"

                new_path = os.path.join(output_dir, rel_path)

                ensure_parent(new_path)

                aes.decrypt_file(
                    enc_file,
                    new_path,
                    decrypt_filename=args.decryptfilename
                )

                bar.update(1)

        print("[+] Directory decrypted!")
        return

    if args.encryptfile:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        print(wai_process_message())
        output_file = aes.encrypt_file(
            args.encryptfile,
            args.output,
            encrypt_filename=args.encryptfilename
        )
        print("[+] File encrypted!")
        print("[+] Output:", output_file)
        return

    if args.decryptfile:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        print(wai_process_message())
        output = aes.decrypt_file(
            args.decryptfile,
            args.output,
            decrypt_filename=args.decryptfilename
        )
        print("[+] File decrypted!")
        print("[*] Output:", output)
        return

    if args.keyinfo:
        password = getpass.getpass("Enter password: ")
        aes = AES256(password=password)

        print(wai_process_message())
        info = aes.get_key_info()

        print("[+] Key info:")
        print("[+] Key (hex):", info["key_hex"])
        if args.verbose:
            print("[!] Salt:", info["salt"])
            print("[!] Salt hex:", info["salt_hex"])
        print("[!] Type:", info["key_type"])
        return

    if args.savekey:
        aes = AES256()
        print(wai_process_message())
        aes.save_key(args.savekey)
        print("[+] Key saved!")
        print("[!] Key file:", args.savekey)
        return

    if args.loadkey:
        aes = AES256.load_from_keyfile(args.loadkey)
        print(wai_process_message())
        info = aes.get_key_info()
        print("[+] Key loaded!")
        print("[!] Key hex:", info["key_hex"])
        return

if __name__ == "__main__":
    main()