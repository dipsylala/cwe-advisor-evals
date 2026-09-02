## Verdict

Exploitable. ECB mode (Electronic Codebook) is cryptographically weak and is listed as a taint sink in the CWE-326 Python guidance. Identical plaintext blocks encrypt to identical ciphertext blocks, allowing an attacker to discern patterns in the encrypted data and mount known-plaintext attacks.

## Source

The hardcoded 16-byte AES key `ENCRYPTION_KEY = b'0123456789abcdef'` at line 7 is used with the weak ECB cipher mode to encrypt user-supplied messages from `request.form['message']`.

## Fix

**Vulnerable code:**
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

ENCRYPTION_KEY = b'0123456789abcdef'  # 16-byte AES-128 key

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message'].encode('utf-8')

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
    encryptor = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB()).encryptor()

    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext.hex()
```

**Fixed code:**
```python
from flask import Flask, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

app = Flask(__name__)

ENCRYPTION_KEY = b'0123456789abcdef'  # 16-byte AES-128 key


@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message'].encode('utf-8')

    # Generate a random nonce for this encryption
    nonce = os.urandom(12)

    # Use AES-GCM (authenticated encryption) instead of ECB
    cipher = AESGCM(ENCRYPTION_KEY)
    ciphertext = cipher.encrypt(nonce, message, None)

    # Return nonce (needed for decryption) + ciphertext, hex-encoded
    return (nonce + ciphertext).hex()


if __name__ == '__main__':
    app.run()
```

## Explanation

The fix replaces unauthenticated ECB mode with AES-GCM, which is an authenticated encryption mode that provides both confidentiality and authenticity. ECB mode is cryptographically broken because identical plaintext blocks encrypt to identical ciphertext blocks, revealing patterns to attackers. AES-GCM eliminates this weakness by using a nonce (number used once) that randomizes the encryption of each message, ensuring identical plaintexts produce different ciphertexts. The nonce must be unique for every encryption under the same key and is prepended to the output so the recipient can extract it during decryption. The authenticated encryption also prevents tampering: any modification to the ciphertext or nonce will cause decryption to fail with an `InvalidTag` exception rather than silently returning corrupted plaintext.

## Behaviour changes

- **Nonce generation**: A fresh 12-byte nonce is generated using `os.urandom(12)` for every encryption call. The original code used no nonce (ECB mode characteristic).
- **Return value change**: The output now contains nonce + ciphertext concatenated as hex, rather than ciphertext alone. The recipient must extract the first 12 bytes (24 hex characters) as the nonce before decrypting.
- **Padding removed**: AESGCM is a streaming cipher that does not require PKCS7 block padding; padding is applied internally by the cipher. The original explicit padding step is no longer needed.
- **Authentication added**: The ciphertext now includes an authentication tag that verifies both the ciphertext integrity and the nonce. Tampered ciphertexts will raise `InvalidTag` on decryption, preventing silent corruption.
- **Error handling**: AESGCM.encrypt() does not raise exceptions on normal operation, but any decryption attempt on modified data will raise `cryptography.exceptions.InvalidTag`.
