import os
import time
from cryptography.fernet import Fernet
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import zipfile

# Function to load or generate the Fernet encryption key
# Use a fixed Fernet key (generated manually)
FERNET_KEY = b'dVwZK5cNtxs0NrvRxaLH8M7IaN0qm1qmBmgNL86ccwo='

def load_key():
    return FERNET_KEY

# Function to encrypt files using Fernet
def encrypt_file_fernet(file_data):
    key = load_key()
    fernet = Fernet(key)
    return fernet.encrypt(file_data)

# Function to decrypt files using Fernet
def decrypt_file_fernet(file_data):
    key = load_key()
    fernet = Fernet(key)
    return fernet.decrypt(file_data)

# Simple Caesar Cipher Encryption/Decryption
def caesar_cipher(text, shift, mode='encrypt'):
    result = []
    shift = shift if mode == 'encrypt' else -shift
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result).encode()  # Return as bytes for uniformity

# XOR Cipher Encryption/Decryption
def xor_cipher(data, key):
    return bytes([b ^ key for b in data])  # XOR each byte with the key

# Function to handle batch encryption for all methods
def encrypt_files_batch(uploaded_files, encryption_method, shift=3, xor_key=123):
    comparison_data = {
        "File Name": [], "Original Size (KB)": [], "Encryption Time (s)": [], "Encrypted Size (KB)": []
    }

    encrypted_files = []

    for uploaded_file in uploaded_files:
        file_data = uploaded_file.read()
        file_size = len(file_data) / 1024  # in KB

        start_time = time.time()

        if encryption_method == "Fernet":
            encrypted_data = encrypt_file_fernet(file_data)
        elif encryption_method == "Caesar Cipher":
            try:
                encrypted_data = caesar_cipher(file_data.decode(), shift)
            except UnicodeDecodeError:
                st.warning(f"Caesar Cipher can only encrypt text files. Skipping {uploaded_file.name}")
                continue
        elif encryption_method == "XOR Cipher":
            encrypted_data = xor_cipher(file_data, xor_key)

        encryption_time = time.time() - start_time
        encrypted_file_size = len(encrypted_data) / 1024  # in KB

        # Append data to comparison table
        comparison_data["File Name"].append(uploaded_file.name)
        comparison_data["Original Size (KB)"].append(round(file_size, 2))
        comparison_data["Encryption Time (s)"].append(round(encryption_time, 4))
        comparison_data["Encrypted Size (KB)"].append(round(encrypted_file_size, 2))

        if encrypted_data:
            encrypted_files.append((uploaded_file.name + '.encrypted', encrypted_data))

    return encrypted_files, comparison_data

# Function to handle batch decryption for all methods
def decrypt_files_batch(uploaded_files, encryption_method, shift=3, xor_key=123):
    comparison_data = {
        "File Name": [], "Encrypted Size (KB)": [], "Decryption Time (s)": [], "Decrypted Size (KB)": []
    }

    decrypted_files = []

    for uploaded_file in uploaded_files:
        file_data = uploaded_file.read()
        file_size = len(file_data) / 1024  # in KB

        start_time = time.time()

        if encryption_method == "Fernet":
            try:
                decrypted_data = decrypt_file_fernet(file_data)
            except:
                st.error(f"Failed to decrypt {uploaded_file.name} - possibly not a Fernet encrypted file")
                continue
        elif encryption_method == "Caesar Cipher":
            try:
                decrypted_data = caesar_cipher(file_data.decode(), shift, mode='decrypt')
            except UnicodeDecodeError:
                st.warning(f"Caesar Cipher can only decrypt text files. Skipping {uploaded_file.name}")
                continue
        elif encryption_method == "XOR Cipher":
            decrypted_data = xor_cipher(file_data, xor_key)

        decryption_time = time.time() - start_time
        decrypted_file_size = len(decrypted_data) / 1024  # in KB

        # Append data to comparison table
        comparison_data["File Name"].append(uploaded_file.name)
        comparison_data["Encrypted Size (KB)"].append(round(file_size, 2))
        comparison_data["Decryption Time (s)"].append(round(decryption_time, 4))
        comparison_data["Decrypted Size (KB)"].append(round(decrypted_file_size, 2))

        if decrypted_data:
            original_name = uploaded_file.name.replace('.encrypted', '')
            decrypted_files.append((original_name, decrypted_data))

    return decrypted_files, comparison_data

# Function to generate the comparison chart
def plot_comparison_chart(comparison_data, operation="Encryption"):
    df = pd.DataFrame(comparison_data)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))
    
    # Time comparison
    time_col = f"{operation} Time (s)"
    df.plot(x="File Name", y=[time_col], kind="bar", ax=ax1, color='skyblue')
    ax1.set_title(f"{operation} Time Comparison")
    ax1.set_ylabel("Time (seconds)")
    ax1.tick_params(axis='x', rotation=45)
    
    # Size comparison
    size_cols = ["Original Size (KB)", f"{operation}d Size (KB)"] if operation == "Encryption" else ["Encrypted Size (KB)", "Decrypted Size (KB)"]
    df.plot(x="File Name", y=size_cols, kind="bar", ax=ax2)
    ax2.set_title("File Size Comparison")
    ax2.set_ylabel("Size (KB)")
    ax2.tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    return fig

# Function to create a downloadable ZIP file
def create_zip(files):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        for file_name, file_data in files:
            zip_file.writestr(file_name, file_data)
    zip_buffer.seek(0)
    return zip_buffer

# Streamlit UI
st.set_page_config(page_title="File Encryption Tool", layout="wide")
st.title("📁 Batch File Encryption/Decryption Tool")
st.write("""
This tool allows you to encrypt or decrypt multiple files using different algorithms. 
Compare the performance of Fernet (AES), Caesar Cipher, and XOR Cipher methods.
""")

# Sidebar for settings
with st.sidebar:
    st.header("Settings")
    encryption_method = st.radio(
        "Encryption Method",
        ("Fernet", "Caesar Cipher", "XOR Cipher"),
        help="Fernet: Strong AES encryption\nCaesar Cipher: Simple letter shifting\nXOR Cipher: Bitwise XOR operation"
    )
    
    if encryption_method == "Caesar Cipher":
        shift = st.number_input("Caesar Shift Value", min_value=1, max_value=25, value=3)
    else:
        shift = 3
        
    if encryption_method == "XOR Cipher":
        xor_key = st.number_input("XOR Key (0-255)", min_value=0, max_value=255, value=123)
    else:
        xor_key = 123
        
    operation = st.radio("Operation", ("Encrypt", "Decrypt"))

# Main content area
col1, col2 = st.columns([3, 2])

with col1:
    st.subheader(f"{operation} Files")
    uploaded_files = st.file_uploader(
        f"Choose files to {operation.lower()}",
        accept_multiple_files=True,
        type=None if operation == "Decrypt" else None,
        help="For decryption, make sure files were encrypted with the same method"
    )

with col2:
    st.subheader("Method Information")
    if encryption_method == "Fernet":
        st.info("""
        **Fernet Encryption**:
        - Uses AES-128 in CBC mode
        - Provides strong security
        - Adds authentication (HMAC)
        - Encrypted files will be larger than original
        """)
    elif encryption_method == "Caesar Cipher":
        st.warning("""
        **Caesar Cipher**:
        - Simple letter shifting algorithm
        - Only works on text files
        - Not secure for sensitive data
        - Maintains original file size
        """)
    elif encryption_method == "XOR Cipher":
        st.warning("""
        **XOR Cipher**:
        - Bitwise XOR operation
        - Works on any file type
        - Weak security with single byte key
        - Maintains original file size
        """)

# Process files when uploaded
if uploaded_files:
    st.divider()
    st.subheader(f"{operation}ion Results")
    
    if operation == "Encrypt":
        encrypted_files, comparison_data = encrypt_files_batch(
            uploaded_files, encryption_method, shift, xor_key
        )
        
        if encrypted_files:
            zip_buffer = create_zip(encrypted_files)
            
            # Show comparison table
            st.dataframe(
                pd.DataFrame(comparison_data).style.highlight_max(
                    subset=["Encryption Time (s)"], color='salmon'
                ).highlight_min(
                    subset=["Encryption Time (s)"], color='lightgreen'
                ),
                use_container_width=True
            )
            
            # Download button
            st.download_button(
                "⬇️ Download Encrypted Files",
                data=zip_buffer,
                file_name=f"{encryption_method.lower()}_encrypted_files.zip",
                mime="application/zip"
            )
            
            # Show charts
            st.pyplot(plot_comparison_chart(comparison_data, operation="Encryption"))
        else:
            st.warning("No files were successfully encrypted.")
            
    elif operation == "Decrypt":
        decrypted_files, comparison_data = decrypt_files_batch(
            uploaded_files, encryption_method, shift, xor_key
        )
        
        if decrypted_files:
            zip_buffer = create_zip(decrypted_files)
            
            # Show comparison table
            st.dataframe(
                pd.DataFrame(comparison_data).style.highlight_max(
                    subset=["Decryption Time (s)"], color='salmon'
                ).highlight_min(
                    subset=["Decryption Time (s)"], color='lightgreen'
                ),
                use_container_width=True
            )
            
            # Download button
            st.download_button(
                "⬇️ Download Decrypted Files",
                data=zip_buffer,
                file_name=f"{encryption_method.lower()}_decrypted_files.zip",
                mime="application/zip"
            )
            
            # Show charts
            st.pyplot(plot_comparison_chart(comparison_data, operation="Decryption"))
        else:
            st.warning("No files were successfully decrypted.")
else:
    st.info("👆 Please upload files to get started")

# Footer
st.divider()
st.caption("""
Note: Fernet is recommended for real security. Caesar and XOR ciphers are provided for educational purposes only.
For production use, always prefer strong encryption like Fernet (AES).
""")
