from brachinus import AES256

PASS_WORD = "12345678"

crypt = AES256(password=PASS_WORD)
#crypt.encrypt_file(input_path="1478698374768.jpg", encrypt_filename=True)

crypt.decrypt_file(input_path="ymL9vCiP3OQ==.enc", decrypt_filename=False)