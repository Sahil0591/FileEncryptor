from cryptography.fernet import Fernet
import os
import sys 
import uuid
import random
import string

# Directories for storing keys and UUIDs
KEY_DIRECTORY = os.path.join(os.getcwd(), "Keys")
UUID_DIRECTORY = os.path.join(os.getcwd(), ".uuid_store")  # Hidden directory

# Ensure required directories exist before encryption or decryption
def ensure_directories():
    os.makedirs(KEY_DIRECTORY, exist_ok=True)
    os.makedirs(UUID_DIRECTORY, exist_ok=True)

    # On Windows, make the UUID directory hidden
    if os.name == "nt":
        os.system(f'attrib +h "{KEY_DIRECTORY}"')
        os.system(f'attrib +h "{UUID_DIRECTORY}"')

# Generating a secret key here
def generate_key():
    return Fernet.generate_key()

# Saving the secret key into directory
def save_key(key, file_uuid):
    key_file = os.path.join(KEY_DIRECTORY, file_uuid + '.key')
    with open(key_file, 'wb') as keyfile:
        keyfile.write(key)

def load_key(file_uuid):
    key_file = os.path.join(KEY_DIRECTORY, file_uuid + '.key')
    if not os.path.exists(key_file):
        raise Exception(f"Key file for {file_uuid} not found!")

    with open(key_file, 'rb') as keyfile:
        return keyfile.read()
    
def delete_key(file_uuid):
    key_file = os.path.join(KEY_DIRECTORY, file_uuid + '.key')
    if os.path.exists(key_file):
        os.remove(key_file)
        print(f"Key file '{key_file}' deleted.")
    else:
        print(f"Key file '{key_file}' not found. It may have been deleted already.")

# Generate a random filename for the UUID file
def generate_random_filename():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + ".tmp"

# Check if an encrypted file already exists and rename if necessary
def get_unique_filename(filename):
    base_name, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename

    while os.path.exists(new_filename + ".enc"):
        new_filename = f"{base_name}_{counter}{ext}"
        counter += 1

    return new_filename
# Function to find the correct UUID file based on the encrypted filename

def find_uuid_for_file(encrypted_filename):
    """Find the correct UUID file in the hidden .uuid_store directory."""
    ensure_directories()  # Ensure directories exist before decryption

    for uuid_file in os.listdir(UUID_DIRECTORY):
        uuid_path = os.path.join(UUID_DIRECTORY, uuid_file)
        with open(uuid_path, "r") as file:
            content = file.read().strip()
            file_uuid, stored_filename = content.split(":", 1)  # Split UUID and filename

            if stored_filename == encrypted_filename:
                return file_uuid, uuid_path  # Return the UUID and file path

    raise Exception(f"No matching UUID file found for '{encrypted_filename}'.")

def encrypt_file(filename):
    # Ensure directories exist before encryption (expansion for flashdrive storage for keys)
    ensure_directories()  
    # Ensure the encrypted filename is unique
    unique_filename = get_unique_filename(filename) + ".enc"
    key = generate_key()
    fernet = Fernet(key)

    # Read original file
    with open(filename, "rb") as file:
        file_data = file.read()

    # Encrypt data
    encrypted_data = fernet.encrypt(file_data)

    # Write encrypted data to a new file
    with open(unique_filename, "wb") as enc_file:
        enc_file.write(encrypted_data)

    # Generate a unique UUID for this encryption session
    file_uuid = str(uuid.uuid4())

    # Generate a random filename for the UUID file
    uuid_filename = os.path.join(UUID_DIRECTORY, generate_random_filename())

    # Save the UUID **and the encrypted filename** inside this file
    with open(uuid_filename, "w") as uuid_file:
        uuid_file.write(f"{file_uuid}:{unique_filename}")

    # Save the encryption key using the UUID
    save_key(key, file_uuid)

    # Delete the original file
    os.remove(filename)
    print(f"File '{filename}' encrypted successfully as '{unique_filename}' with hidden UUID file.")
    
# Encrypt command
# Python Cryptic.py encrypt hey.txt

def decrypt_file(encrypted_filename):
    try:
        # Ensure directories exist before decryption
        ensure_directories()  
        # Find the correct UUID file for this encrypted file
        file_uuid, uuid_filepath = find_uuid_for_file(encrypted_filename)
        key = load_key(file_uuid)  # Fix: Load key using original filename
        fernet = Fernet(key)

        with open(encrypted_filename, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Attempt to decrypt
        decrypted_data = fernet.decrypt(encrypted_data)
        # Step 1: Derive original filename
        original_filename = encrypted_filename[:-4] if encrypted_filename.endswith(".enc") else encrypted_filename

        # Step 2: Check if file with same name exists
        base, ext = os.path.splitext(original_filename)
        counter = 1
        new_filename = original_filename

        while os.path.exists(new_filename):
            new_filename = f"{base}_restored_{counter}{ext}"
            counter += 1

        # Step 3: Notify the user
        if new_filename != original_filename:
            print(f"File with name '{original_filename}' already exists.")
            print(f"Decrypted file saved as '{new_filename}' instead.")

        # Step 4: Save decrypted content
        with open(new_filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        print(f"File '{encrypted_filename}' decrypted successfully as '{new_filename}'!")

        # Delete encrypted file and key, cuz we want a new secret key to 
        # be associated with the file for a new encryption
        os.remove(encrypted_filename)
        os.remove(uuid_filepath)
        delete_key(file_uuid)

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

