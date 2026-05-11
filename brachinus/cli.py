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
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def encrypt_directory_with_progress(aes, directory_path, output_dir, extensions, encrypt_filenames, encrypt_dirnames, recursive, backup, total_files):
    with tqdm(total=total_files, desc="[*] Encrypting", ncols=80) as bar:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(".enc"):
                    continue
                if extensions:
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in extensions:
                        continue
                
                full_path = os.path.join(root, file)
                
                rel_path = os.path.relpath(full_path, directory_path)
                
                if backup:
                    if output_dir:
                        out_base = output_dir
                    else:
                        if encrypt_dirnames:
                            dir_name = os.path.basename(directory_path)
                            enc_dir_name = aes.encrypt_name(dir_name)
                            out_base = os.path.join(os.path.dirname(directory_path), enc_dir_name + "_encrypted")
                        else:
                            out_base = directory_path + "_encrypted"
                    
                    if encrypt_filenames:
                        enc_name = aes.encrypt_name(file)
                        new_path = os.path.join(out_base, os.path.dirname(rel_path), enc_name + ".enc")
                    else:
                        new_path = os.path.join(out_base, rel_path + ".enc")
                else:
                    if encrypt_filenames:
                        enc_name = aes.encrypt_name(file)
                        new_path = os.path.join(root, enc_name + ".enc")
                    else:
                        new_path = full_path + ".enc"
                
                ensure_parent(new_path)
                
                aes.encrypt_file(full_path, new_path, encrypt_filename=encrypt_filenames)
                
                if not backup:
                    os.unlink(full_path)
                
                bar.update(1)
            
            if not recursive:
                break
        
        if encrypt_dirnames and not backup:
            for root, dirs, files in os.walk(directory_path):
                for dir_name in dirs:
                    if dir_name.endswith(".enc"):
                        continue
                    full_dir_path = os.path.join(root, dir_name)
                    try:
                        new_dir_name = aes.encrypt_name(dir_name)
                        new_dir_path = os.path.join(root, new_dir_name)
                        if os.path.exists(full_dir_path) and not os.path.exists(new_dir_path):
                            os.rename(full_dir_path, new_dir_path)
                    except Exception:
                        pass
                if not recursive:
                    break


def decrypt_directory_with_progress(aes, directory_path, output_dir, decrypt_filenames, decrypt_dirnames, recursive, backup, total_files):
    with tqdm(total=total_files, desc="[*] Decrypting", ncols=80) as bar:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if not file.endswith(".enc"):
                    continue
                
                full_path = os.path.join(root, file)
                
                rel_path = os.path.relpath(full_path, directory_path)
                rel_path = rel_path[:-4]
                
                if backup:
                    if output_dir:
                        out_base = output_dir
                    else:
                        if decrypt_dirnames:
                            try:
                                dir_name = os.path.basename(directory_path)
                                original_name = aes.decrypt_name(dir_name)
                                out_base = os.path.join(os.path.dirname(directory_path), original_name + "_decrypted")
                            except Exception:
                                out_base = directory_path + "_decrypted"
                        else:
                            out_base = directory_path + "_decrypted"
                    
                    if decrypt_filenames:
                        enc_name = file[:-4]
                        original_name = aes.decrypt_name(enc_name)
                        new_path = os.path.join(out_base, os.path.dirname(rel_path), original_name)
                    else:
                        new_path = os.path.join(out_base, rel_path)
                else:
                    if decrypt_filenames:
                        enc_name = file[:-4]
                        original_name = aes.decrypt_name(enc_name)
                        new_path = os.path.join(root, original_name)
                    else:
                        new_path = full_path[:-4]
                
                ensure_parent(new_path)
                
                aes.decrypt_file(full_path, new_path, decrypt_filename=decrypt_filenames)
                
                if not backup:
                    os.unlink(full_path)
                
                bar.update(1)
            
            if not recursive:
                break
        
        if decrypt_dirnames and not backup:
            for root, dirs, files in os.walk(directory_path):
                for dir_name in dirs:
                    if dir_name.endswith(".enc"):
                        continue
                    full_dir_path = os.path.join(root, dir_name)
                    try:
                        original_name = aes.decrypt_name(dir_name)
                        original_dir_path = os.path.join(root, original_name)
                        if original_name != dir_name and not os.path.exists(original_dir_path):
                            os.rename(full_dir_path, original_dir_path)
                    except Exception:
                        pass
                if not recursive:
                    break


def main():
    parser = argparse.ArgumentParser(
        description=f"Brachinus {__version__}, Copyright (C) 2025, "
                    f"Juan Bindez — AES256 encryption and decryption CLI"
    )

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument("-ef", "--encryptfile", help="Encrypt a file", metavar="FILE")
    operation_group.add_argument("-df", "--decryptfile", help="Decrypt a file", metavar="FILE")
    operation_group.add_argument("-ed", "--encryptdir", help="Encrypt all files in a directory", metavar="DIR")
    operation_group.add_argument("-dd", "--decryptdir", help="Decrypt all .enc files in a directory", metavar="DIR")
    operation_group.add_argument("-ki", "--keyinfo", action="store_true", help="Display key information")
    operation_group.add_argument("-sk", "--savekey", help="Save binary AES key to a file", metavar="KEYFILE")
    operation_group.add_argument("-lk", "--loadkey", help="Load key and print info", metavar="KEYFILE")

    parser.add_argument("-o", "--output", help="Output file/directory path")
    parser.add_argument("-k", "--keyfile", help="Path to binary key file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    parser.add_argument("--encryptfilename", action="store_true", help="Encrypt filenames")
    parser.add_argument("--decryptfilename", action="store_true", help="Decrypt encrypted filenames")
    parser.add_argument("--encryptdirname", action="store_true", help="Encrypt directory names")
    parser.add_argument("--decryptdirname", action="store_true", help="Decrypt encrypted directory names")
    parser.add_argument("-r", "--recursive", action="store_true", help="Process directories recursively")
    parser.add_argument("--backup", action="store_true", help="Create backup files/directories instead of in-place processing")
    parser.add_argument("-e", "--extension", action="append", help="Only encrypt files with specific extensions (can be used multiple times)", metavar="EXT")

    args = parser.parse_args()

    if args.encryptdir:
        if args.keyfile:
            with open(args.keyfile, "rb") as f:
                key = f.read()
            aes = AES256(key=key)
        else:
            password = getpass.getpass("[?] Enter password: ")
            aes = AES256(password=password)

        try:
            print("[*] Counting files...")
            all_files = []

            for root, dirs, files in os.walk(args.encryptdir):
                for f in files:
                    if f.endswith(".enc"):
                        continue
                    if args.extension:
                        ext = os.path.splitext(f)[1].lower()
                        if ext not in args.extension:
                            continue
                    all_files.append(os.path.join(root, f))
                if not args.recursive:
                    break

            if not all_files:
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
                total_files=len(all_files)
            )

            if args.backup:
                if args.encryptdirname:
                    print("[+] Directory encrypted to backup location with encrypted directory names!")
                else:
                    print("[+] Directory encrypted to backup location!")
            else:
                if args.encryptdirname:
                    print("[+] Directory encrypted in-place with encrypted directory names!")
                else:
                    print("[+] Directory encrypted in-place!")

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.decryptdir:
        if args.keyfile:
            with open(args.keyfile, "rb") as f:
                key = f.read()
            aes = AES256(key=key)
        else:
            password = getpass.getpass("[?] Enter password: ")
            aes = AES256(password=password)

        try:
            print("[*] Counting files...")
            enc_files = []

            for root, dirs, files in os.walk(args.decryptdir):
                for f in files:
                    if f.endswith(".enc"):
                        enc_files.append(os.path.join(root, f))
                if not args.recursive:
                    break

            if not enc_files:
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
                total_files=len(enc_files)
            )

            if args.backup:
                if args.decryptdirname:
                    print("[+] Directory decrypted to backup location with decrypted directory names!")
                else:
                    print("[+] Directory decrypted to backup location!")
            else:
                if args.decryptdirname:
                    print("[+] Directory decrypted in-place with decrypted directory names!")
                else:
                    print("[+] Directory decrypted in-place!")

        except ValueError as e:
            error_msg = str(e)
            if "Failed to decrypt directory name" in error_msg:
                print("[!] Note: Some directory names were not encrypted and were skipped")
                print("[+] Directory decrypted successfully (ignored non-encrypted directory names)")
            else:
                print(f"[-] Decryption failed: {e}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.encryptfile:
        if args.keyfile:
            with open(args.keyfile, "rb") as f:
                key = f.read()
            aes = AES256(key=key)
        else:
            password = getpass.getpass("[?] Enter password: ")
            aes = AES256(password=password)

        try:
            print(wai_process_message())

            output_file = aes.encrypt_file(
                args.encryptfile,
                args.output,
                encrypt_filename=args.encryptfilename,
                backup=args.backup
            )

            if not args.backup:
                if os.path.exists(args.encryptfile):
                    os.unlink(args.encryptfile)

            print("[+] File encrypted!")
            print("[+] Output:", output_file)

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)

        return

    if args.decryptfile:
        if args.keyfile:
            with open(args.keyfile, "rb") as f:
                key = f.read()
            aes = AES256(key=key)
        else:
            password = getpass.getpass("[?] Enter password: ")
            aes = AES256(password=password)

        try:
            print(wai_process_message())

            output = aes.decrypt_file(
                args.decryptfile,
                args.output,
                decrypt_filename=args.decryptfilename,
                backup=args.backup
            )

            if not args.backup:
                if os.path.exists(args.decryptfile):
                    os.unlink(args.decryptfile)

            print("[+] File decrypted!")
            print("[*] Output:", output)

        except ValueError as e:
            print(f"[-] Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

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