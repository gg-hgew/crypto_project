# rsa_performance_analysis.py

# ---
# Install packages before running:
# pip install pycryptodome pandas matplotlib
# ---

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import time
import pandas as pd
import matplotlib.pyplot as plt

# ---
# Helper function for timing
# ---
def time_function(func, *args, **kwargs):
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    return result, end - start

# ---
# RSA Encryption/Decryption Test
# ---
def test_rsa(key_size=2048, message="Hello World!"):
    key = RSA.generate(key_size)
    public_key = key.publickey()
    
    cipher = PKCS1_OAEP.new(public_key)
    enc_result, enc_time = time_function(cipher.encrypt, message.encode())

    cipher = PKCS1_OAEP.new(key)
    dec_result, dec_time = time_function(cipher.decrypt, enc_result)

    return {
        'Key Size (bits)': key_size,
        'Encrypt Time (s)': enc_time,
        'Decrypt Time (s)': dec_time,
        'Message Match': dec_result.decode() == message
    }

# ---
# AES Encryption/Decryption Test
# ---
def test_aes(message="Hello World!"):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    
    enc_result, enc_time = time_function(cipher.encrypt, message.encode())
    
    cipher_dec = AES.new(key, AES.MODE_EAX, cipher.nonce)
    dec_result, dec_time = time_function(cipher_dec.decrypt, enc_result)

    return {
        'Method': "AES-128",
        'Encrypt Time (s)': enc_time,
        'Decrypt Time (s)': dec_time,
        'Message Match': dec_result.decode() == message
    }

# ---
# Hybrid Encryption Test (RSA + AES)
# ---
def hybrid_encrypt(message, rsa_key):
    aes_key = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())
    
    rsa_cipher = PKCS1_OAEP.new(rsa_key.publickey())
    enc_aes_key = rsa_cipher.encrypt(aes_key)
    
    return enc_aes_key, aes_cipher.nonce, ciphertext, tag

def hybrid_decrypt(enc_aes_key, nonce, ciphertext, tag, rsa_key):
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = rsa_cipher.decrypt(enc_aes_key)
    
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    message = aes_cipher.decrypt_and_verify(ciphertext, tag)
    
    return message.decode()

# ---
# Main execution
# ---
if __name__ == "__main__":
    # Messages and RSA key sizes
    messages = ["Hello", "This is a longer test message to measure performance."]
    key_sizes = [1024, 2048, 4096]
    
    results = []
    for msg in messages:
        for size in key_sizes:
            result = test_rsa(key_size=size, message=msg)
            result['Message'] = msg
            results.append(result)
        
        aes_result = test_aes(message=msg)
        aes_result['Key Size (bits)'] = "128 (AES)"
        aes_result['Message'] = msg
        results.append(aes_result)

    # Convert results to DataFrame
    df = pd.DataFrame(results)
    print(df)

    # Plot Results
    for msg in messages:
        sub_df = df[df['Message'] == msg]
        rsa_df = sub_df[sub_df['Key Size (bits)'] != "128 (AES)"]
        aes_df = sub_df[sub_df['Key Size (bits)'] == "128 (AES)"]
        
        plt.figure(figsize=(10,5))
        plt.plot(rsa_df['Key Size (bits)'], rsa_df['Encrypt Time (s)'], marker='o', label='RSA Encrypt Time')
        plt.plot(rsa_df['Key Size (bits)'], rsa_df['Decrypt Time (s)'], marker='o', label='RSA Decrypt Time')
        plt.axhline(aes_df['Encrypt Time (s)'].iloc[0], linestyle='--', label='AES Encrypt Time')
        plt.axhline(aes_df['Decrypt Time (s)'].iloc[0], linestyle='--', label='AES Decrypt Time')

        plt.title(f"RSA vs AES Performance ({msg})")
        plt.xlabel("RSA Key Size (bits)")
        plt.ylabel("Time (s)")
        plt.legend()
        plt.grid(True)
        plt.show()

    # Hybrid Encryption Demo
    rsa_key = RSA.generate(2048)
    message = "Hello from hybrid encryption!"
    enc_key, nonce, ciphertext, tag = hybrid_encrypt(message, rsa_key)
    dec_message = hybrid_decrypt(enc_key, nonce, ciphertext, tag, rsa_key)

    print("\n--- Hybrid Encryption Test ---")
    print("Original Message:", message)
    print("Decrypted Message:", dec_message)
    print("Match:", message == dec_message)
