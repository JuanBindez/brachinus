from cryptophoto import AESFileCrypt

PASSWORD = "senhashjsdhs12245"


"""
# Usando com senha
crypt = AESFileCrypt.create_with_password(PASSWORD)
crypt.encrypt("foto.jpg", "foto_criptografada.bin")

"""



# Para descriptografar depois com a mesma senha
crypt2 = AESFileCrypt.create_with_password(PASSWORD)
crypt2.decrypt("foto_criptografada.bin", "foto_descriptografada.jpg")



"""
# Usando com chave binária (modo original)
crypt3 = AESFileCrypt()  # Gera chave aleatória
crypt3.encrypt("documento.pdf", "doc_criptografado.bin")

# Carregando chave de arquivo
crypt4 = AESFileCrypt.load_from_keyfile("minha_chave.bin")"""