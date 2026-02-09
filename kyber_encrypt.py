#!/usr/bin/env python3
"""
Simple hybrid encryption example using Kyber-768 + AES-256-GCM
For small files/documents (< ~16 KB is comfortable)

Requires: pip install kyber-py cryptography
"""

import os
import sys
from getpass import getpass

from kyber_py.kyber import Kyber512, Kyber768, Kyber1024
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_symmetric_key(shared_secret: bytes, context: bytes = b"kyber-hybrid-2025") -> bytes:
    """HKDF to turn Kyber shared secret → AES-256 key"""
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,                  # AES-256
        salt=None,
        info=context,
    ).derive(shared_secret)


def encrypt_file_or_text(input_data: bytes, filename_out: str = "example.md.encrypted") -> None:
    # 1. Generate Kyber keypair (receiver)
    public_key, secret_key = Kyber768.keygen()

    # 2. Encapsulate → get ciphertext + shared secret (sender side)
    ciphertext, shared_secret = Kyber768.encaps(public_key)

    # 3. Derive AES key from shared secret
    aes_key = derive_symmetric_key(shared_secret)

    # 4. Encrypt the actual document with AES-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_data = aesgcm.encrypt(nonce, input_data, None)  # no associated data

    # 5. Save format: Kyber ciphertext || nonce || AES ciphertext
    #    (and public key or not — here we include it for simplicity)
    with open(filename_out, "wb") as f:
        f.write(public_key)             # 1184 bytes (Kyber-768)
        f.write(ciphertext)             # 1088 bytes (Kyber-768)
        f.write(nonce)                  # 12 bytes
        f.write(ciphertext_data)        # len(input) + 16

    print(f"Encrypted file saved as: {filename_out}")
    print(f"Size: {len(public_key) + len(ciphertext) + len(nonce) + len(ciphertext_data)} bytes")
    print("\nTo decrypt you need the Kyber secret key (private key).")
    print("In real usage → send public_key + Kyber ciphertext to receiver\n")


def main():
    if len(sys.argv) >= 2 and os.path.isfile(sys.argv[1]):
        # Use file
        with open(sys.argv[1], "rb") as f:
            plaintext = f.read()
        print(f"Reading file: {sys.argv[1]}  ({len(plaintext):,} bytes)")
    else:
        # Interactive input
        print("Paste or type your text (finish with Ctrl+D or Ctrl+Z + Enter):\n")
        lines = sys.stdin.read()
        plaintext = lines.encode("utf-8")
        if not plaintext.strip():
            print("No input received.")
            return

    output_name = "document.encrypted"
    if len(sys.argv) >= 2:
        base = os.path.basename(sys.argv[1])
        output_name = base + ".encrypted"

    encrypt_file_or_text(plaintext, output_name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)