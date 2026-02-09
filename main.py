import sys
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
import base64
from dotenv import load_dotenv


def load_pass():
    load_dotenv()

    password = os.getenv("ENCRYPTION_PASSWORD")
    key_bytes = password.encode('utf-8').ljust(32)[:32]
    key = base64.urlsafe_b64encode(key_bytes)
    return key


def encrypt_file(filepath: str):
    path = Path(filepath)

    key = load_pass()
    f = Fernet(key)

    output_path = path.with_suffix(path.suffix + ".encrypted")
    with open(path, "rb") as f_in:
        data = f_in.read()
    
    encrypted = f.encrypt(data)
    
    with open(output_path, "wb") as f_out:
        f_out.write(encrypted)
    
    print(f"Encrypted:  {output_path}")
    print(f"Original:   {path}")



def decrypt_file(filepath: str):
    path = Path(filepath)
    if not path.is_file():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    key = load_pass()
    f = Fernet(key)

    # Guess output filename
    if path.suffix == ".encrypted":
        output_path = path.with_suffix("")
    else:
        output_path = path.with_suffix(path.suffix + ".decrypted")

    try:
        with open(path, "rb") as f_in:
            data = f_in.read()
        
        try:
            decrypted = f.decrypt(data)
        except InvalidToken:
            print("Decryption failed: Invalid token / wrong password")
            sys.exit(1)
        
        with open(output_path, "wb") as f_out:
            f_out.write(decrypted)
        
        print(f"Decrypted:  {output_path}")
        print(f"From:       {path}")
    
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    filename = sys.argv[2]

    if command == "encrypt":
        encrypt_file(filename)
    elif command == "decrypt":
        decrypt_file(filename)
    else:
        print("Error: Command must be 'encrypt' or 'decrypt'")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()