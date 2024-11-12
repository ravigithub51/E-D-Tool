import os
import streamlit as st
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Fernet Encryption/Decryption

def generate_fernet_key():
    return Fernet.generate_key()

def encrypt_fernet(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_fernet(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

# RSA Encryption/Decryption

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(data)

def decrypt_rsa(encrypted_data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_data)

# AES Encryption/Decryption

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def decrypt_aes(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Base64 Encoding/Decoding

def encrypt_base64(data):
    return b64encode(data)

def decrypt_base64(encoded_data):
    return b64decode(encoded_data)

# Streamlit UI
st.title("Simple Encryption and Decryption App")

algorithms = ["Fernet", "RSA", "AES", "Base64"]
algorithm = st.selectbox("Choose an encryption algorithm", algorithms)

operation = st.radio("Operation", ("Encrypt", "Decrypt"))
data = st.text_area("Enter data to encrypt/decrypt")

if algorithm == "Fernet":
    key = st.text_input("Enter key (leave blank to generate a new one)")
    if not key:
        key = generate_fernet_key()
        st.write("Generated Key:", key.decode())

    key = key.encode()
    if st.button("Run"):
        if operation == "Encrypt":
            encrypted_data = encrypt_fernet(data.encode(), key)
            st.write("Encrypted Data:", encrypted_data.decode())
        else:
            decrypted_data = decrypt_fernet(data.encode(), key)
            st.write("Decrypted Data:", decrypted_data.decode())

elif algorithm == "RSA":
    private_key = st.text_area("Enter private key (for decryption)")
    public_key = st.text_area("Enter public key (for encryption)")

    if st.button("Generate RSA Keys"):
        private_key, public_key = generate_rsa_keys()
        st.write("Private Key:", private_key.decode())
        st.write("Public Key:", public_key.decode())

    if st.button("Run"):
        if operation == "Encrypt" and public_key:
            encrypted_data = encrypt_rsa(data.encode(), public_key.encode())
            st.write("Encrypted Data:", b64encode(encrypted_data).decode())
        elif operation == "Decrypt" and private_key:
            decrypted_data = decrypt_rsa(b64decode(data.encode()), private_key.encode())
            st.write("Decrypted Data:", decrypted_data.decode())

elif algorithm == "AES":
    key = st.text_input("Enter 16-byte key (leave blank to generate a new one)")
    if not key:
        key = get_random_bytes(16)
        st.write("Generated Key:", b64encode(key).decode())
    else:
        key = b64decode(key)

    if st.button("Run"):
        if operation == "Encrypt":
            nonce, ciphertext, tag = encrypt_aes(data.encode(), key)
            st.write("Encrypted Data:", b64encode(nonce + ciphertext + tag).decode())
        else:
            nonce = st.text_input("Enter nonce (base64-encoded)")
            tag = st.text_input("Enter tag (base64-encoded)")
            if nonce and tag:
                nonce = b64decode(nonce)
                tag = b64decode(tag)
                ciphertext = b64decode(data)
                decrypted_data = decrypt_aes(nonce, ciphertext, tag, key)
                st.write("Decrypted Data:", decrypted_data.decode())

elif algorithm == "Base64":
    if st.button("Run"):
        if operation == "Encrypt":
            encrypted_data = encrypt_base64(data.encode())
            st.write("Encoded Data:", encrypted_data.decode())
        else:
            decrypted_data = decrypt_base64(data.encode())
            st.write("Decoded Data:", decrypted_data.decode())
