## Verdict

Confirmed. ECB mode on line 18 is unauthenticated symmetric encryption using a primitive that leaks plaintext structure through repetition patterns in ciphertext. Replacement with authenticated encryption (AES-GCM) is required.

## Source

```python
ENCRYPTION_KEY = b'0123456789abcdef'  # 16-byte AES-128 key
```

The static encryption key is the source. The key size (128-bit) is acceptable per NIST, but the mode (ECB) is not.

## Fix

```python
import os
from flask import Flask, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

app = Flask(__name__)

ENCRYPTION_KEY = os.urandom(32)  # 32-byte (256-bit) AES-256 key generated at startup


@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message'].encode('utf-8')

    padder = PKCS7(128).padder()  # 128-bit block size for AES
    padded_message = padder.update(message) + padder.finalize()

    # Generate a fresh 96-bit nonce for each encryption
    nonce = os.urandom(12)

    # Use AES-256-GCM for authenticated encryption
    cipher = AESGCM(ENCRYPTION_KEY)
    ciphertext = cipher.encrypt(nonce, padded_message, None)

    # Return nonce + ciphertext (nonce must be transmitted with ciphertext for decryption)
    return (nonce + ciphertext).hex()


if __name__ == '__main__':
    app.run()
```

## Explanation

ECB mode is inherently weak because it encrypts each plaintext block independently using the same key, causing identical plaintext blocks to produce identical ciphertext blocks. This leaks information about plaintext structure.

The fix replaces ECB with AES-GCM, an authenticated encryption mode that:
1. Encrypts each block with a unique nonce-derived keystream, preventing plaintext structure leakage.
2. Automatically authenticates the ciphertext, detecting tampering (failed authentication raises `cryptography.exceptions.InvalidTag` on decryption).
3. Requires a fresh 96-bit nonce for each encryption under the same key—reusing a nonce destroys both confidentiality and authentication.

The key is upgraded from 128-bit to 256-bit for additional security margin. The nonce is generated fresh on every call and prepended to the ciphertext for transmission (the recipient extracts the first 12 bytes as the nonce before decryption).

The padder is retained because GCM itself does not pad; PKCS7 padding is still required for the underlying plaintext length.

## Behaviour changes

- **Ciphertext output format**: now returns `nonce || ciphertext` instead of ciphertext alone. Decryption must extract the first 12 bytes as the nonce before passing to `AESGCM.decrypt()`.
- **Key generation**: key is now generated at application startup rather than hardcoded, using cryptographic randomness via `os.urandom()`.
- **Authentication**: ciphertext is now authenticated; any bit flip in transit or storage will cause decryption to raise `InvalidTag` instead of silently returning corrupted plaintext.
- **Nonce uniqueness**: a new nonce is generated for every encryption. Nonce exhaustion (2^96 encryptions under one key) is astronomically unlikely in practice; if the application approaches this, key rotation is required.
- **Decryption impact**: any existing ciphertexts encrypted under ECB mode cannot be decrypted by this new code. A migration path must handle legacy records (e.g., decrypt with the old cipher, re-encrypt with GCM).
