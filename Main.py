from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_data(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted_data

def decrypt_data(data, key):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# Example usage
data = b"Hello, World!"
key = b"thisisasecretkey"

encrypted_data = encrypt_data(data, key)
print("Encrypted data:", encrypted_data)

decrypted_data = decrypt_data(encrypted_data, key)
print("Decrypted data:", decrypted_data)
