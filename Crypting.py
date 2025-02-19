from cryptography.fernet import Fernet
import os
import sys 

# Directory to save keys, will probably try to make it hidden
KEY_DIRECTORY = os.path.join(os.getcwd(), "Keys")

# Ensure the key directory exists
if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)

# Generating a secret key here
def generate_key():
    return Fernet.generate_key()

# Saving the secret key into directory
def save_key(key, encrypted_filename):
    key_file = os.path.join(KEY_DIRECTORY, encrypted_filename + '.key')
    with open(key_file, 'wb') as keyfile:
        keyfile.write(key)

def load_key(encrypted_filename):
    key_file = os.path.join(KEY_DIRECTORY, encrypted_filename + '.key')
    if not os.path.exists(key_file):
        raise Exception(f"Key file for {encrypted_filename} not found!")

    with open(key_file, 'rb') as keyfile:
        return keyfile.read()
    
def delete_key(encrypted_filename):
    key_file = os.path.join(KEY_DIRECTORY, encrypted_filename + '.key')
    if os.path.exists(key_file):
        os.remove(key_file)
        print(f"Key file '{key_file}' deleted.")
    else:
        print(f"Key file '{key_file}' not found. It may have been deleted already.")

def encrypt_file(filename):
    key = generate_key()
    fernet = Fernet(key)

    # Read original file
    with open(filename, "rb") as file:
        file_data = file.read()

    # Encrypt data
    encrypted_data = fernet.encrypt(file_data)

    # Write encrypted data to a new file
    encrypted_filename = filename + ".enc"
    with open(encrypted_filename, "wb") as enc_file:
        enc_file.write(encrypted_data)

    save_key(key, encrypted_filename)
    # Delete the original file
    os.remove(filename)
    print(f"File '{filename}' encrypted successfully!")
    
# Encrypt command
# Python Cryptic.py encrypt hey.txt

def decrypt_file(encrypted_filename):
    original_filename = encrypted_filename.replace('.enc', '')
    try:
        key = load_key(encrypted_filename)  # Fix: Load key using original filename
        fernet = Fernet(key)

        with open(encrypted_filename, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Attempt to decrypt
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(original_filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        print(f"File '{encrypted_filename}' decrypted successfully!")

        # Delete encrypted file and key, cuz we want a new secret key to 
        # be associated with the file for a new encryption
        os.remove(encrypted_filename)
        delete_key(encrypted_filename)

    except Exception as e:
        print(f"Failed to decrypt '{encrypted_filename}': {e}")
# Decrypt command
# Python Cryptic.py decrypt hey.txt.enc

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  To encrypt: python script.py encrypt filename.txt")
        print("  To decrypt: python script.py decrypt filename.txt.enc")
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]

    if action == "encrypt":
        encrypt_file(filename)
    elif action == "decrypt":
        decrypt_file(filename)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")

