import os
import argparse
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import sha256
import getpass
from tqdm import tqdm

def generate_key(password):
    """Generate an encryption key from the given password."""
    return urlsafe_b64encode(sha256(password.encode()).digest())

def encrypt_data(data, key):
    """Encrypts data and returns the encrypted data."""
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data)

def decrypt_data(encrypted_data, key):
    """Decrypts the encrypted data."""
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_data)

def create_encrypted_file(folder, output_folder, password):
    """Encrypts all files in the specified folder and saves them to a single .enc file."""
    key = generate_key(password)

    folder = os.path.abspath(folder)
    output_folder = os.path.abspath(output_folder)

    enc_file_name = f"encrypted_{os.path.basename(folder)}.enc"
    output_path = os.path.join(output_folder, enc_file_name)

    chunk_size = 4096

    total_size = sum(os.path.getsize(os.path.join(root, f))
                  for root, _, files in os.walk(folder) for f in files)

    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Encrypting")

    with open(output_path, "wb") as encrypted_file:
        for root, _, files in os.walk(folder):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Save the relative path for later reconstruction
                relative_path = os.path.relpath(file_path, folder).ljust(4096)[:4096]
                encrypted_file.write(relative_path.encode('utf-8'))

                with open(file_path, "rb") as f:
                    while True:
                        file_data = f.read(chunk_size)
                        if not file_data:  # EOF
                            break
                        encrypted_data = encrypt_data(file_data, key)

                        progress_bar.update(len(file_data))

                        # Fixed size for encrypted data length
                        encrypted_file.write(len(encrypted_data).to_bytes(4, byteorder='big'))
                        encrypted_file.write(encrypted_data)

                # Write the end marker for the file
                end_flag = 32767
                encrypted_file.write(end_flag.to_bytes(4, byteorder='big'))

    progress_bar.close()
    print(f"Encrypted file created: {output_path}")

def decrypt_file(input_file, output_folder, password):
    """Decrypts the specified .enc file and saves the original files to the output folder."""
    key = generate_key(password)

    input_file = os.path.abspath(input_file)
    output_folder = os.path.abspath(output_folder)

    # Extract the folder name from the encrypted file name
    folder_name = os.path.basename(input_file).replace("encrypted_", "").replace(".enc", "")
    output_subfolder = os.path.join(output_folder, folder_name)
    os.makedirs(output_subfolder, exist_ok=True)  # Create the output folder

    # Get the total size of the input file for the progress bar
    total_size = os.path.getsize(input_file)
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Decrypting")

    with open(input_file, "rb") as encrypted_file:
        while True:
            # Read the relative path of the file
            relative_path_bytes = encrypted_file.read(4096)
            if not relative_path_bytes:
                break

            relative_path = relative_path_bytes.decode('utf-8').rstrip()

            # Create the necessary directories within the output subfolder
            original_file_path = os.path.join(output_subfolder, relative_path)
            os.makedirs(os.path.dirname(original_file_path), exist_ok=True)

            with open(original_file_path, "wb") as output_file:
                while True:
                    size_bytes = encrypted_file.read(4)
                    if not size_bytes:
                        break

                    size = int.from_bytes(size_bytes, byteorder='big')

                    if size == 32767:
                        break

                    encrypted_data = encrypted_file.read(size)

                    # Update the progress bar
                    progress_bar.update(4 + size)  # 4 bytes for the size + size of encrypted data

                    try:
                        decrypted_data = decrypt_data(encrypted_data, key)
                        output_file.write(decrypted_data)
                    except Exception as e:
                        print("Decryption failed: Incorrect password.")
                        return  # Exit if decryption fails

    progress_bar.close()
    print(f"Decrypted files created in: {output_subfolder}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt a folder into a single .enc file.")
    parser.add_argument("input", type=str, help="The path to the folder containing files or the encrypted file.")
    parser.add_argument("output_folder", type=str, help="The path to the output folder.")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the encrypted file.")
    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    if args.decrypt:
        decrypt_file(args.input, args.output_folder, password)
    else:
        create_encrypted_file(args.input, args.output_folder, password)

if __name__ == "__main__":
    main()
