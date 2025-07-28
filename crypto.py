from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import os

KEY = b"dLINAjtur1QdHKuoWl5eR4h1WRsuq4XV"

def encrypt(plaintext: str) -> str:
    iv = os.urandom(16)  # 16 байт IV
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()


import urllib.parse

def decrypt(encrypted_b64: str) -> str:
    encrypted_b64 = urllib.parse.unquote(encrypted_b64)  # Декодируем URL-энкодирование
    encrypted_data = base64.b64decode(encrypted_b64)  # Теперь можно декодировать в base64
    iv, encrypted = encrypted_data[:16], encrypted_data[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()

    return (unpadder.update(decrypted_padded) + unpadder.finalize()).decode()



