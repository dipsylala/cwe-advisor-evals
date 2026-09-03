## Verdict

**CONFIRMED** – The vulnerability is real and exploitable. The code uses `Cipher.getInstance("AES")` without specifying a mode or padding, which defaults to ECB mode. ECB is cryptographically weak because identical plaintext blocks produce identical ciphertext blocks, violating semantic security and enabling plaintext recovery through pattern analysis. The sensitive data (SSN) is encrypted with this weak cipher and sent to the response.

## Source

**CWE-326: Inadequate Encryption Strength**
- File: `evals/cases/326/java/EcbDefaultCipher/EcbDefaultCipher.java`
- Line: 21
- Sink: `Cipher.getInstance("AES")`

The vulnerability: `Cipher.getInstance("AES")` uses the JDK's default transformation, which is ECB mode with PKCS5Padding (as documented by Oracle). ECB is inadequate for protecting sensitive data.

## Fix

**Replace the transformation to use authenticated encryption with a fresh IV per message:**

```java
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;

// In the handle method, replace lines 21-23:

// Generate a fresh 96-bit IV for this message
byte[] iv = new byte[12];
SecureRandom secureRandom = new SecureRandom();
secureRandom.nextBytes(iv);

// Use AES/GCM/NoPadding (authenticated encryption)
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

// Prepend IV to ciphertext for transmission (IV must accompany the ciphertext for decryption)
byte[] output = new byte[iv.length + ciphertext.length];
System.arraycopy(iv, 0, output, 0, iv.length);
System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(output));
```

## Explanation

The fix replaces ECB mode with AES/GCM (Galois/Counter Mode), which provides:

1. **Semantic security**: Each message encrypts to a different ciphertext even if plaintext is repeated, because each encryption uses a fresh IV. GCM is a NIST-approved authenticated encryption mode.

2. **Authentication**: GCM produces a 128-bit authentication tag (included in the ciphertext) that verifies the message has not been tampered with. Decryption fails if the tag is invalid, preventing padding-oracle and tampering attacks.

3. **IV handling**: A fresh 96-bit (12-byte) IV is generated per message using `SecureRandom`. The IV is deterministic (not secret) and must be transmitted with the ciphertext so the recipient can decrypt. The fix concatenates IV + ciphertext before Base64 encoding, making decryption possible.

4. **Complete transformation**: `"AES/GCM/NoPadding"` is explicit, eliminating reliance on provider defaults.

The JDK's `GCMParameterSpec` API requires the tag length (128 bits is maximum and standard) and the IV to be supplied at initialization. SunJCE throws `InvalidAlgorithmParameterException` if the IV is reused with the same key, providing runtime protection against IV misuse.

## Behaviour changes

- **Ciphertext length increases**: The output now includes a 12-byte IV and a 16-byte authentication tag, plus the original plaintext length. Code that assumes a fixed relationship between plaintext and ciphertext size will break.
- **IV transmission**: The IV is now part of the output sent to the client. This is required for decryption and is not a secret.
- **Decryption change required**: Any code that decrypts this output must extract the first 12 bytes as the IV, pass it to `GCMParameterSpec`, and supply it to `Cipher.init()` before decrypting the remaining bytes.
- **Authentication**: Failed decryption now throws `AEADBadTagException` instead of silently returning corrupted plaintext. Callers must handle this new exception.
- **Performance**: GCM is computationally similar to CBC but requires the full plaintext buffered before encryption (which this code already does with `doFinal()`).

