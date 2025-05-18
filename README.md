Split-Key File Encryption Tool (Python)
This is a Python-based tool for securely encrypting and decrypting files using the cryptography library (Fernet) and password-derived keys split across local storage and a USB drive.

Each file is:

Encrypted with a random Fernet key
Protected using a PBKDF2-derived key
Bound to a user-supplied password
Linked to a hidden UUID metadata file

Features
AES-based encryption (Fernet)
Password protection using PBKDF2 (with salt)
Split key storage:
    Half stored locally (.key_parts/)
    Half stored on a user-specified USB (KeyParts/)
Per-file UUID linkage (stored in .uuid_store/)
Encrypted file renaming to avoid collisions
Restores original filename (or renames if it already exists)
Automatically deletes encrypted file, key parts, and UUID after decryption
Lists available drives to help identify the correct USB volume

Requirements
Python 3.6+
cryptography package

Usage

Encrypt a file:
python script.py encrypt filename.txt
You’ll be prompted to:
Set and confirm a password
Enter the volume label of your USB drive
The encryption key is split and saved across:
    Local .key_parts/ folder
    USB KeyParts/ folder

Decrypt a file:
python script.py decrypt filename.txt.enc
You’ll be prompted to:
Enter the same password used during encryption
Provide the USB volume label

How It Works
During Encryption:
The user enters a password.
A key is derived using PBKDF2 with a random salt.
The key is split into two halves.
A random Fernet key is generated and XOR’d with the derived key.
The file is encrypted.
Metadata (UUID, salt, encrypted Fernet key) is stored in .uuid_store/.

During Decryption:
Metadata is looked up based on the encrypted filename.
The user provides the password.
Key halves are loaded from local and USB storage.
If valid, the Fernet key is reconstructed.
The file is decrypted and saved, avoiding overwriting existing files.

Notes
Do not rename .enc files manually.
Keep .key_parts/, .uuid_store/, and the USB's KeyParts/ folder intact until decryption is complete.
The .uuid_store/ directory is hidden on Windows for added security.
Deletion of all sensitive material occurs automatically after decryption.

