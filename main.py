from cryptophoto import AES

# Create instance (automatically generates key)
crypt = AES()

# Encrypt image
crypt.encrypt('photo.jpg', 'photo_encrypted.bin')

# Decrypt image
crypt.decrypt('photo_encrypted.bin', 'photo_decrypted.jpg')

# Save key for future use
crypt.save_key('my_key.bin')

# Load with existing key
crypt2 = AES.load_from_keyfile('my_key.bin')
crypt2.decrypt('photo_encrypted.bin', 'another_copy.jpg')

# Create with new random key
crypt3 = AES.create_with_new_key()