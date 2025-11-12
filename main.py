from brachinus import AES256

PASS_WORD = "12345678"

crypt = AES256(password=PASS_WORD)
crypt.decrypt_directory(directory_path="DIR_TEST_encrypted")