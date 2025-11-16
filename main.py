from brachinus import AES256

PASS_WORD = "password123"

crypt = AES256(password=PASS_WORD)
crypt.encrypt_file(
    file_path="file.txt",
    encrypt_filename=True
)