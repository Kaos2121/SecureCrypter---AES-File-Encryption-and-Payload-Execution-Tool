
**SecureCrypter** is a robust encryption tool designed to help developers, cybersecurity professionals, and enthusiasts securely encrypt files and package them into standalone executable files. The tool ensures the confidentiality of sensitive files or scripts by implementing AES encryption, dynamically embedding decryption logic into an output EXE, and providing additional security features like anti-debugging and anti-virtual machine (VM) detection.

---

### Key Features:
1. **Advanced AES Encryption**:
   - Protect your payload files using AES encryption with a secure key derived via PBKDF2.
   - Ensures robust security with unique salts and initialization vectors (IVs) for each encryption.

2. **Dynamic Decryption & Execution**:
   - Outputs standalone executables that can dynamically decrypt and execute the payload without leaving traces of decrypted files on disk.

3. **Anti-Debugging & Anti-VM Checks**:
   - Implements measures to detect suspicious debugging processes and virtualized environments, preventing reverse engineering and misuse.

4. **User-Friendly GUI**:
   - Built with `customtkinter` for an intuitive and modern graphical user interface (GUI).
   - Allows easy file selection, output folder designation, and visual progress tracking during the encryption process.

5. **Standalone Executables**:
   - Leverages PyInstaller to convert encrypted payloads and decryption logic into portable, self-contained EXE files.

---

### How to Use SecureCrypter:
Follow this detailed step-by-step guide to encrypt your files and generate a secure EXE:

#### **1. Setup Prerequisites**
- **Install Python**: Ensure Python 3.9 or higher is installed on your system.
- **Install Required Libraries**:
  Run the following command to install the dependencies:
  ```bash
  pip install cryptography customtkinter pyinstaller
  ```
- **Prepare Your Payload**:
  Ensure the file you want to encrypt is ready and accessible.

---

#### **2. Launch the SecureCrypter Tool**
- Open the script file in your Python environment and run it:
  ```bash
  python securecrypter.py
  ```
- The SecureCrypter GUI will launch.

---

#### **3. Select a File for Encryption**
- Click the **Browse** button to select your payload file.
- The file can be of any type (e.g., `.exe`, `.pdf`, `.txt`, etc.).

---

#### **4. Choose an Output Folder**
- After selecting the payload, you will be prompted to choose a folder where the output EXE will be saved.
- Select or create a directory to store the final encrypted executable.

---

#### **5. Encrypt the File**
- The encryption process will start automatically, and a progress bar will appear in a new window.
- During encryption:
  - The file is securely encrypted using AES with a dynamically generated password.
  - The encrypted data, key, salt, and IV are embedded in a Python stub script along with decryption logic.

---

#### **6. Generate the Standalone EXE**
- SecureCrypter uses PyInstaller to compile the Python stub script into a standalone EXE.
- After compilation:
  - The resulting EXE will be moved to the output folder you selected.
  - Temporary files (e.g., intermediate scripts, build folders) will be automatically deleted to ensure cleanliness.

---

#### **7. Execute the Final EXE**
- The generated EXE can decrypt and execute the original payload dynamically.
- When run:
  - The EXE performs anti-debugging and anti-VM checks.
  - If no issues are detected, the payload is decrypted and executed from memory.

---

### Important Notes:
1. **Anti-Debugging and Anti-VM Features**:
   - The tool detects and prevents execution in environments with suspicious processes or debugger tools like `wireshark.exe` or `ollydbg.exe`.

2. **Payload Decryption**:
   - The decrypted payload is written to a temporary file for execution and deleted immediately after running.

3. **Security of Encrypted EXEs**:
   - While the tool encrypts payloads securely, attackers with sufficient resources might attempt to reverse-engineer the EXE. Use only in trusted environments.

---

### Ethical Usage:
**SecureCrypter is a powerful tool intended strictly for educational purposes and ethical use cases.** It is the user's responsibility to ensure compliance with all applicable laws and ethical guidelines. Misuse of this tool for malicious purposes, such as creating ransomware, is prohibited and may result in severe legal consequences.

---

### Example Use Case:
Suppose you have a proprietary script `script.py` that you want to share securely with a colleague:
1. Use SecureCrypter to encrypt the script and package it into an EXE.
2. Share the EXE with your colleague, who can run it to decrypt and execute the script securely.

---

### Repository Includes:
- **`crypter.py`**: Main script for running the tool.
- **README.md**: Comprehensive setup and usage guide.
---
