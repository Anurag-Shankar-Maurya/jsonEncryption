from cryptography.fernet import Fernet
import json

# Generate a key (you should save this key securely for decryption)
key = Fernet.generate_key()
cipher = Fernet(key)

# Save the key to a file (for demonstration purposes)
with open("key.key", "wb") as key_file:
    key_file.write(key)

# Read the key back (in real usage, you'd load it securely)
with open("key.key", "rb") as key_file:
    key = key_file.read()
cipher = Fernet(key)


# Function to encrypt a JSON file
def encrypt_json(input_file, output_file):
    with open(input_file, "r") as file:
        data = json.load(file)  # Load JSON data
    json_string = json.dumps(data)  # Convert JSON to string
    encrypted_data = cipher.encrypt(json_string.encode())  # Encrypt the string
    with open(output_file, "wb") as file:
        file.write(encrypted_data)  # Save encrypted data
    print(f"File '{input_file}' encrypted and saved as '{output_file}'.")


# Function to decrypt a JSON file
def decrypt_json(input_file, output_file):
    with open(input_file, "rb") as file:
        encrypted_data = file.read()  # Read encrypted data
    decrypted_data = cipher.decrypt(encrypted_data).decode()  # Decrypt and decode
    json_data = json.loads(decrypted_data)  # Convert back to JSON
    with open(output_file, "w") as file:
        json.dump(json_data, file, indent=4)  # Save decrypted JSON
    print(f"File '{input_file}' decrypted and saved as '{output_file}'.")


# Encrypt a JSON file
encrypt_json("data.json", "encrypted_data.json")

# Decrypt the JSON file
decrypt_json("encrypted_data.json", "decrypted_data.json")
