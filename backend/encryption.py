from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import time
import base64

def rsa_encrypt_decrypt(message: str, key_size: int = 2048):
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()

    # Encryption
    start = time.time()
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    enc_time = time.time() - start

    # Decryption
    start = time.time()
    decipher = PKCS1_OAEP.new(private_key)
    plaintext = decipher.decrypt(ciphertext).decode()
    dec_time = time.time() - start

    return {
        "method": f"RSA ({key_size})",
        "encrypted": base64.b64encode(ciphertext).decode(),
        "decrypted": plaintext,
        "enc_time": enc_time,
        "dec_time": dec_time,
        "public_key": public_key.export_key().decode(),
        "private_key": private_key.export_key().decode()
    }


def aes_encrypt_decrypt(message: str):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    start = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    enc_time = time.time() - start

    start = time.time()
    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = decipher.decrypt(ciphertext).decode()
    dec_time = time.time() - start

    return {
        "method": "AES (128)",
        "encrypted": base64.b64encode(ciphertext).decode(),
        "decrypted": plaintext,
        "enc_time": enc_time,
        "dec_time": dec_time
    }
