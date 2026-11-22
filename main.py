from brachinus import AES256

PASS = "12345678"


aes = AES256(password=PASS)

aes.decrypt_directory(directory_path="AgAJJ8BcF8z39cUiSFx0iu3SsWbSix2fn0oxj6EvnMsK7Wk_u8p0WI5TGaT6I2CugyaOo9XGlXFzf9qV",
                      decrypt_filenames=True,
                      decrypt_dirnames=True,
                      recursive=True,
                      remove_original=False
                    )