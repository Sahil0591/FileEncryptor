This is a Python-based tool for securely encrypting and decrypting files using the cryptography library (Fernet). Each file is encrypted with a unique, randomly generated key. No visible mapping is left between files and keys.

Features
AES-based encryption (Fernet)
Unique UUID-based key per file
Encrypted files are renamed if duplicates exist
Keys stored in Keys/ using UUIDs
UUID metadata stored in randomly named files inside a hidden .uuid_store/ directory
Automatically restores original file name on decryption
Cleans up encrypted file, key, and UUID after decryption

Requirements
Python 3.6+
cryptography package

Install with:
pip install cryptography

Usage

Encrypt a file:
python script.py encrypt filename.txt

Decrypt a file:
python script.py decrypt filename.txt.enc

How it Works
On encryption: a UUID is generated, the file is encrypted, the key is saved in Keys/, and a .uuid_store/ file links the UUID to the encrypted filename.
On decryption: the script finds the matching UUID, loads the key, decrypts the file, and removes the encrypted file, UUID, and key.

Notes
The .uuid_store/ directory is hidden on Windows.

Do not rename .enc files manually.

Keep the Keys/ and .uuid_store/ folders intact until decryption is complete.

