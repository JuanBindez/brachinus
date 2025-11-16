import argparse
import os
import getpass
import sys

from brachinus.version import __version__
from brachinus import AES256, encrypt_file_with_password, decrypt_file_with_password


def wai_process_message():
    return "[*] Processing. Please wait..."

def main():
    parser = argparse.ArgumentParser(
        description=f"Brachinus {__version__} AES256 encryption and decryption CLI"
    )

    # Operações principais
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument("-ef", "--encryptfile", help="Encrypt a file", metavar="FILE")
    operation_group.add_argument("-df", "--decryptfile", help="Decrypt a file", metavar="FILE")
    operation_group.add_argument("-ed", "--encryptdir", help="Encrypt all files in a directory", metavar="DIR")
    operation_group.add_argument("-dd", "--decryptdir", help="Decrypt all .enc files in a directory", metavar="DIR")
    operation_group.add_argument("-ki", "--keyinfo", action="store_true", help="Display key information")
    operation_group.add_argument("-sk", "--savekey", help="Save binary AES key to a file", metavar="KEYFILE")
    operation_group.add_argument("-lk", "--loadkey", help="Load key and print info", metavar="KEYFILE")

    # Opções extras
    parser.add_argument("-o", "--output", help="Output file/directory path")
    parser.add_argument("-k", "--keyfile", help="Path to binary key file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # *** NOVOS PARÂMETROS ***
    parser.add_argument("--encryptfilename", action="store_true",
                        help="Encrypt the filename when saving output (.enc)")
    parser.add_argument("--decryptfilename", action="store_true",
                        help="Decrypt encrypted filename (.enc → original name)")

    args = parser.parse_args()

    # --------------------------------------------------
    # Encrypt file
    # --------------------------------------------------
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

    # --------------------------------------------------
    # Decrypt file
    # --------------------------------------------------
    elif args.decryptfile:
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

    # --------------------------------------------------
    # Encrypt directory
    # --------------------------------------------------
    elif args.encryptdir:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        print(wai_process_message())
        output_dir = args.output or args.encryptdir + "_encrypted"

        files = aes.encrypt_directory(
            args.encryptdir,
            output_dir,
            encrypt_filenames=args.encryptfilename
        )
        print("[+] Directory encrypted!")
        print("[*] Files processed:", len(files))

    # --------------------------------------------------
    # Decrypt directory
    # --------------------------------------------------
    elif args.decryptdir:
        password = getpass.getpass("[?] Enter password: ")
        aes = AES256(password=password)

        print(wai_process_message())
        output_dir = args.output or args.decryptdir + "_decrypted"

        files = aes.decrypt_directory(
            args.decryptdir,
            output_dir,
            decrypt_filenames=args.decryptfilename
        )
        print("[+] Directory decrypted!")
        print("[*] Files processed:", len(files))

    # --------------------------------------------------
    # Key info
    # --------------------------------------------------
    elif args.keyinfo:
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

    # --------------------------------------------------
    # Save Key
    # --------------------------------------------------
    elif args.savekey:
        aes = AES256()
        print(wai_process_message())
        aes.save_key(args.savekey)
        print("[+] Key saved!")
        print("[!] Key file:", args.savekey)

    # --------------------------------------------------
    # Load Key
    # --------------------------------------------------
    elif args.loadkey:
        aes = AES256.load_from_keyfile(args.loadkey)
        print(wai_process_message())
        info = aes.get_key_info()
        print("[+] Key loaded!")
        print("[!] Key hex:", info["key_hex"])


if __name__ == "__main__":
    main()
