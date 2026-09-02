## Verdict
Confirmed. Line 18 uses AES in ECB mode, which is cryptographically weak.

## Source
```python
encryptor = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB()).encryptor()
```

## Fix
```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generate a random IV for each encryption
iv = os.urandom(16)

# Use CBC mode instead of ECB
encryptor = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv)).encryptor()

# Prepend IV to ciphertext for decryption
ciphertext = encryptor.update(padded_message) + encryptor.finalize()
return (iv + ciphertext).hex()
```

## Explanation
ECB mode encrypts each plaintext block identically, revealing patterns in the input. An attacker observing the ciphertext can detect repetition and potentially infer structure of the encrypted data. CBC mode with a random initialization vector (IV) breaks this pattern, as each block's encryption depends on the previous ciphertext block and the unique IV. The IV must be prepended to the ciphertext and transmitted with it so the decryptor can retrieve it (IVs do not need to be secret, only unpredictable). Alternatively, use authenticated encryption like AES-GCM which provides both confidentiality and integrity.
