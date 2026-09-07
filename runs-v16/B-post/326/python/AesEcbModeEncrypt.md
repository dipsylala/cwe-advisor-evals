## Verdict

exploitable

## Source

- **CWE**: 326 (Inadequate Encryption Strength)
- **Location**: evals/cases/326/python/AesEcbModeEncrypt/AesEcbModeEncrypt.py, line 18
- **Source**: `message` parameter from `request.form['message']` (line 12, user-controlled input)
- **Sink**: `modes.ECB()` at line 18 - ECB mode is a cryptographically weak cipher mode listed in the CWE-326 Python guidance taint sinks

## Fix

**Vulnerable code:**
```python
encryptor = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB()).encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()
return ciphertext.hex()
```

**Fixed code:**
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

nonce = os.urandom(12)
cipher = AESGCM(ENCRYPTION_KEY)
ciphertext = cipher.encrypt(nonce, padded_message, None)
return (nonce + ciphertext).hex()
```

## Explanation

ECB mode is cryptographically weak because identical plaintext blocks encrypt to identical ciphertext blocks, which reveals patterns in the plaintext and violates semantic security. The fix replaces ECB with AES-GCM, an authenticated encryption mode from `cryptography.hazmat.primitives.ciphers.aead`. AES-GCM provides both confidentiality and authentication in a single operation. A fresh 12-byte nonce is generated for each encryption using `os.urandom(12)`, which is required because reusing a nonce under the same key destroys both confidentiality and authentication. The nonce is prepended to the ciphertext so decryption can extract it; GCM includes the authentication tag in the ciphertext, so no separate tag transmission is needed.

## Behaviour changes

- **Nonce generation and transmission**: The original code used a static key with no nonce; the fixed code generates a fresh nonce per encryption and prepends it to the ciphertext. This is necessary for GCM security and does not break the API - the receiver extracts the first 12 bytes as the nonce before decrypting.
- **Ciphertext format**: The output is now `nonce || ciphertext_with_tag` instead of `ciphertext_only`. The ciphertext length increases by 12 bytes for the nonce and 16 bytes for the authentication tag.
- **Authentication**: GCM provides built-in authentication via the tag. On decryption, a tampered ciphertext or tag will raise `cryptography.exceptions.InvalidTag` instead of returning corrupted plaintext.
- **PKCS7 padding removal**: AESGCM does not require external padding - it operates on raw bytes. The existing PKCS7 padding can be removed post-decryption or padding can be left in place (it becomes part of the authenticated plaintext); the fix shown preserves the padding for minimal code changes, but decryption should remove it via `unpadder.update() + unpadder.finalize()`.
