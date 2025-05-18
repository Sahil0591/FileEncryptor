import os
import string
import sys
import uuid
import random
import ctypes
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Directories
KEY_PARTS_DIR = os.path.join(os.getcwd(), ".key_parts")
UUID_DIRECTORY = os.path.join(os.getcwd(), ".uuid_store")

# Ensure required directories
def ensure_directories():
    os.makedirs(KEY_PARTS_DIR, exist_ok=True)
    os.makedirs(UUID_DIRECTORY, exist_ok=True)
    if os.name == "nt":
        os.system(f'attrib +h "{UUID_DIRECTORY}"')
        os.system(f'attrib +h "{KEY_PARTS_DIR}"')

def list_connected_drives():
    print("\nAvailable Drives and Volume Labels:")
    drives = [f"{chr(c)}:/" for c in range(65, 91) if os.path.exists(f"{chr(c)}:/")]
    for drive in drives:
        try:
            vol_name = ctypes.create_unicode_buffer(1024)
            fs_name = ctypes.create_unicode_buffer(1024)
            serial = ctypes.c_ulong()
            max_len = ctypes.c_ulong()
            flags = ctypes.c_ulong()

            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive),
                vol_name,
                ctypes.sizeof(vol_name),
                ctypes.byref(serial),
                ctypes.byref(max_len),
                ctypes.byref(flags),
                fs_name,
                ctypes.sizeof(fs_name)
            )

            print(f"  [{drive}] - {vol_name.value}")
        except:
            continue

# Get drive label on Windows
def get_windows_usb_drive(label):
    drives = [f"{chr(c)}:/" for c in range(65, 91) if os.path.exists(f"{chr(c)}:/")]
    for drive in drives:
        try:
            vol_name = ctypes.create_unicode_buffer(1024)
            fs_name = ctypes.create_unicode_buffer(1024)
            serial = ctypes.c_ulong()
            max_len = ctypes.c_ulong()
            flags = ctypes.c_ulong()

            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive),
                vol_name,
                ctypes.sizeof(vol_name),
                ctypes.byref(serial),
                ctypes.byref(max_len),
                ctypes.byref(flags),
                fs_name,
                ctypes.sizeof(fs_name)
            )

            if vol_name.value.strip().lower() == label.strip().lower():
                return drive
        except:
            continue
    return None

def generate_random_filename():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + ".tmp"

def get_unique_filename(filename):
    base_name, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    while os.path.exists(new_filename + ".enc"):
        new_filename = f"{base_name}_{counter}{ext}"
        counter += 1
    return new_filename

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filename):
    ensure_directories()
    list_connected_drives()
    usb_label = input("Enter the name (volume label) of your USB drive: ").strip()
    usb_root = get_windows_usb_drive(usb_label)
    if not usb_root:
        print("Error: Could not locate USB drive with that label.")
        return
    usb_key_dir = os.path.join(usb_root, "KeyParts")# remove later
    print(f"(TEST MODE) Saving Half B to: {usb_key_dir}")# remove later
    os.makedirs(usb_key_dir, exist_ok=True)

    password = getpass("Enter password to protect this file: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return

    salt = os.urandom(16)
    derived_key = derive_key_from_password(password, salt)
    half_a = derived_key[:16]
    half_b = derived_key[16:]

    file_uuid = str(uuid.uuid4())
    unique_filename = get_unique_filename(filename) + ".enc"

    # Save halves
    with open(os.path.join(KEY_PARTS_DIR, f"{file_uuid}.partA"), 'wb') as file:
        file.write(half_a)
    with open(os.path.join(usb_key_dir, f"{file_uuid}.partB"), 'wb') as file:
        file.write(half_b)
    

    # Generate Fernet key and encrypt it using the derived key
    raw_fernet_key = os.urandom(32)  # generate raw 32 bytes
    fernet_key = base64.urlsafe_b64encode(raw_fernet_key)
    fernet = Fernet(fernet_key)
    encrypted_fernet_key = bytes([a ^ b for a, b in zip(raw_fernet_key, derived_key)])
    metadata = f"{file_uuid}:{unique_filename}:{salt.hex()}:{base64.urlsafe_b64encode(encrypted_fernet_key).decode()}"
    

    # Encrypt the file
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)

    # Save encrypted file
    with open(unique_filename, "wb") as enc_file:
        enc_file.write(encrypted_data)

    # Save metadata in uuid_store
    metadata = f"{file_uuid}:{unique_filename}:{salt.hex()}:{base64.urlsafe_b64encode(encrypted_fernet_key).decode()}"
    with open(os.path.join(UUID_DIRECTORY, generate_random_filename()), "w") as uuid_file:
        uuid_file.write(metadata)

    os.remove(filename)
    print(f"File '{filename}' encrypted successfully as '{unique_filename}'.")
    print(f"Key split: Half A stored locally, Half B stored in: {usb_key_dir}")

def safe_restore_filename(encrypted_filename):
    original_filename = encrypted_filename[:-4] if encrypted_filename.endswith(".enc") else encrypted_filename
    base, ext = os.path.splitext(original_filename)
    counter = 1
    new_filename = original_filename
    while os.path.exists(new_filename):
        new_filename = f"{base}_restored_{counter}{ext}"
        counter += 1
    if new_filename != original_filename:
        print(f"File with name '{original_filename}' already exists.")
        print(f"Decrypted file saved as '{new_filename}' instead.")
    return new_filename

def decrypt_file(encrypted_filename):
    ensure_directories()
    print("[DEBUG] Starting decryption...")
    try:
        # Locate metadata file and extract info
        for meta_file in os.listdir(UUID_DIRECTORY):
            with open(os.path.join(UUID_DIRECTORY, meta_file), 'r') as f:
                content = f.read().strip()
                file_uuid, stored_filename, salt_hex, encrypted_key_b64 = content.split(":")
                if stored_filename == encrypted_filename:
                    break
        else:
            print("No matching UUID metadata found.")
            return

        usb_label = input("Enter the name (volume label) of your USB drive: ").strip()
        usb_root = get_windows_usb_drive(usb_label)
        if not usb_root:
            print("Error: Could not locate USB drive with that label.")
            return

        password = getpass("Enter password to decrypt this file: ")
        salt = bytes.fromhex(salt_hex)
        derived_key = derive_key_from_password(password, salt)

        # Load key halves
        with open(os.path.join(KEY_PARTS_DIR, f"{file_uuid}.partA"), 'rb') as f:
            half_a = f.read()
        with open(os.path.join(os.path.join(usb_root, "KeyParts"), f"{file_uuid}.partB"), 'rb') as f:
            half_b = f.read()

        # Validate reconstructed key
        full_key = half_a + half_b
        if full_key != derived_key:
            print("Password or key parts do not match.")
            return
            print("Password or stored key does not match.")
            return

        print("[DEBUG] UUID:", file_uuid)
        print("[DEBUG] Salt (hex):", salt_hex)
        print("[DEBUG] Derived Key:", derived_key.hex())
        print("[DEBUG] Half A:", half_a.hex())
        print("[DEBUG] Half B:", half_b.hex())
        print("[DEBUG] Full Key:", full_key.hex())
        print("[DEBUG] Encrypted Fernet Key (base64):", encrypted_key_b64)

        encrypted_fernet_key = base64.urlsafe_b64decode(encrypted_key_b64)
        raw_fernet_key = bytes([a ^ b for a, b in zip(encrypted_fernet_key, derived_key)])  # XOR to get raw key
        fernet_key = base64.urlsafe_b64encode(raw_fernet_key)  # encode for Fernet
        print("[DEBUG] Fernet Key (decoded):", base64.urlsafe_b64encode(fernet_key))
        fernet = Fernet(fernet_key)

        with open(encrypted_filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)

        output_filename = safe_restore_filename(encrypted_filename)
        with open(output_filename, 'wb') as f:
            f.write(decrypted_data)

        print(f"File '{encrypted_filename}' decrypted successfully as '{output_filename}'!")

        # Clean up
        os.remove(encrypted_filename)
        os.remove(os.path.join(KEY_PARTS_DIR, f"{file_uuid}.partA"))
        os.remove(os.path.join(os.path.join(usb_root, "KeyParts"), f"{file_uuid}.partB"))
        os.remove(os.path.join(UUID_DIRECTORY, meta_file))

    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  To encrypt: python Crypting.py encrypt filename")
        print("  To decrypt: python Crypting.py decrypt filename.enc")
        sys.exit(1)

    action = sys.argv[1].lower()
    filename = sys.argv[2]

    if action == "encrypt":
        encrypt_file(filename)
    elif action == "decrypt":
        decrypt_file(filename)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")