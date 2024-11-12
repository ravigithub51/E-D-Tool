import os
import gnupg
import time
from cryptography.fernet import Fernet
import streamlit as st       
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import zipfile

# Initialize GnuPG
gpg = gnupg.GPG()

# Function to load or generate the Fernet encryption key
def load_key():
    key_file = "secret.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as key_out:
            key_out.write(key)
    else:
        with open(key_file, "rb") as key_in:
            key = key_in.read()
    return key

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

# Function to encrypt files using GnuPG
def encrypt_file_gnupg(file_data, passphrase):
    if isinstance(file_data, bytes):
        file_data = file_data.decode('utf-8', errors='ignore')  # Decode bytes to a string for GnuPG
    
    encrypted_data = gpg.encrypt(file_data, None, symmetric='AES256', passphrase=passphrase, always_trust=True)
    return encrypted_data.data if encrypted_data.ok else None

# Function to decrypt files using GnuPG
def decrypt_file_gnupg(encrypted_data, passphrase):
    decrypted_data = gpg.decrypt(encrypted_data, passphrase=passphrase)
    return decrypted_data.data if decrypted_data.ok else None



# Function to handle batch encryption for both Fernet and GnuPG
def encrypt_files_batch(uploaded_files, encryption_method, passphrase=None):
    comparison_data = {
        "File Name": [], "File Size (KB)": [], "Encryption Time (s)": [], "Encrypted File Size (KB)": []
    }

    encrypted_files = []

    for uploaded_file in uploaded_files:
        file_data = uploaded_file.read()
        file_size = len(file_data) / 1024  # in KB

        start_time = time.time()

        if encryption_method == "Fernet":
            encrypted_data = encrypt_file_fernet(file_data)
        elif encryption_method == "GnuPG":
            encrypted_data = encrypt_file_gnupg(file_data, passphrase)

        encryption_time = time.time() - start_time
        encrypted_file_size = len(encrypted_data) / 1024 if encrypted_data else 0  # in KB

        # Append data to comparison table
        comparison_data["File Name"].append(uploaded_file.name)
        comparison_data["File Size (KB)"].append(file_size)
        comparison_data["Encryption Time (s)"].append(encryption_time)
        comparison_data["Encrypted File Size (KB)"].append(encrypted_file_size)

        if encrypted_data:
            encrypted_files.append((uploaded_file.name + '.encrypted', encrypted_data))

    return encrypted_files, comparison_data

# Function to handle batch decryption for both Fernet and GnuPG
def decrypt_files_batch(uploaded_files, encryption_method, passphrase=None):
    comparison_data = {
        "File Name": [], "File Size (KB)": [], "Decryption Time (s)": [], "Decrypted File Size (KB)": []
    }

    decrypted_files = []

    for uploaded_file in uploaded_files:
        file_data = uploaded_file.read()
        file_size = len(file_data) / 1024  # in KB

        start_time = time.time()

        if encryption_method == "Fernet":
            decrypted_data = decrypt_file_fernet(file_data)
        elif encryption_method == "GnuPG":
            decrypted_data = decrypt_file_gnupg(file_data, passphrase)

        decryption_time = time.time() - start_time
        decrypted_file_size = len(decrypted_data) / 1024 if decrypted_data else 0  # in KB

        # Append data to comparison table
        comparison_data["File Name"].append(uploaded_file.name)
        comparison_data["File Size (KB)"].append(file_size)
        comparison_data["Decryption Time (s)"].append(decryption_time)
        comparison_data["Decrypted File Size (KB)"].append(decrypted_file_size)

        if decrypted_data:
            decrypted_files.append((uploaded_file.name.replace('.encrypted', ''), decrypted_data))

    return decrypted_files, comparison_data

# Function to generate the comparison chart
def plot_comparison_chart(comparison_data, comparison_type="Encryption"):
    df = pd.DataFrame(comparison_data)
    fig, ax = plt.subplots(figsize=(10, 6))

    if comparison_type == "Encryption":
        df.plot(x="File Name", y=["Encryption Time (s)", "Encrypted File Size (KB)"], kind="line", marker='o', ax=ax)
        ax.set_title("Encryption Time and File Size Comparison")
        ax.set_ylabel("Time (seconds) / File Size (KB)")
    else:
        df.plot(x="File Name", y=["Decryption Time (s)", "Decrypted File Size (KB)"], kind="line", marker='o', ax=ax)
        ax.set_title("Decryption Time and File Size Comparison")
        ax.set_ylabel("Time (seconds) / File Size (KB)")

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
st.title("Batch File Encryption and Decryption Tool")

st.write("Upload files to encrypt or decrypt them in batches. A comparison graph of encryption/decryption time and file sizes will be generated.")

# Choose encryption method (Fernet or GnuPG)
encryption_method = st.radio("Select Encryption Method", ("Fernet", "GnuPG"))

# Enter passphrase for GnuPG (if selected)
gpg_passphrase = None
if encryption_method == "GnuPG":
    gpg_passphrase = st.text_input("Enter passphrase for GnuPG encryption", type="password")

# Choose operation (Encrypt or Decrypt)
operation = st.radio("Select operation", ("Encrypt", "Decrypt"))

# Upload files
uploaded_files = st.file_uploader("Upload files", accept_multiple_files=True)

# Process files (Encrypt/Decrypt) and show results
if uploaded_files:
    if operation == "Encrypt":
        st.write("Processing encryption...")
        encrypted_files, comparison_data = encrypt_files_batch(uploaded_files, encryption_method, gpg_passphrase)
        zip_buffer = create_zip(encrypted_files)

        # Display results
        st.write("### Encryption Results")
        st.write(pd.DataFrame(comparison_data))

        # Display download link for ZIP file
        st.download_button("Download Encrypted Files", data=zip_buffer, file_name="encrypted_files.zip", mime="application/zip")

        # Plot and show the comparison chart
        st.pyplot(plot_comparison_chart(comparison_data, comparison_type="Encryption"))

    elif operation == "Decrypt":
        st.write("Processing decryption...")
        decrypted_files, comparison_data = decrypt_files_batch(uploaded_files, encryption_method, gpg_passphrase)
        zip_buffer = create_zip(decrypted_files)

        # Display results
        st.write("### Decryption Results")
        st.write(pd.DataFrame(comparison_data))

        # Display download link for ZIP file
        st.download_button("Download Decrypted Files", data=zip_buffer, file_name="decrypted_files.zip", mime="application/zip")

        # Plot and show the comparison chart
        st.pyplot(plot_comparison_chart(comparison_data, comparison_type="Decryption"))

    else:
        st.error("Invalid operation selected.")
else:
    st.warning("Please upload files to proceed.")
