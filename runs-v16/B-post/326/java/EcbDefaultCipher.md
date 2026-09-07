## Verdict
exploitable

## Source
Line 13: `ssn = request.getParameter("ssn")` — attacker-controlled user input from HTTP request parameter.

## Fix

**Vulnerable code (line 21):**
```java
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(ciphertext));
```

**Fixed code (lines 21–40):**
```java
// Use AES/GCM/NoPadding instead of ECB default for authenticated encryption
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

// Generate a fresh 12-byte IV for this message
byte[] iv = new byte[12];
SecureRandom random = new SecureRandom();
random.nextBytes(iv);

// Initialize cipher with GCM parameters (128-bit tag)
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);

byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

// Prepend IV to ciphertext so decryption side can extract it
byte[] output = new byte[iv.length + ciphertext.length];
System.arraycopy(iv, 0, output, 0, iv.length);
System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(output));
```

**Required imports (add to top of file):**
```java
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
```

## Explanation

The original code calls `Cipher.getInstance("AES")` without specifying a mode and padding. Java defaults this to ECB (Electronic CodeBook) mode with PKCS5Padding. ECB is cryptographically weak because identical plaintext blocks encrypt to identical ciphertext blocks, allowing an attacker to infer patterns in the SSN data—for example, repeated digits become visible in the encrypted output. The fix replaces ECB with AES/GCM/NoPadding, which provides both confidentiality through AES-GCM authenticated encryption and prevents tampering detection at decryption time. A fresh 12-byte IV is generated for each encryption using SecureRandom, ensuring that identical plaintexts produce different ciphertexts. The IV is prepended to the ciphertext before Base64 encoding so the decryption side can extract and use it, as required by GCM mode. The 128-bit authentication tag is verified automatically during decryption, preventing tampered ciphertexts from being accepted.

## Behaviour changes

1. **IV generation and transmission**: The original code produced only ciphertext; the fixed code generates a fresh 12-byte IV per message and prepends it to the ciphertext before Base64 encoding. The decryption side must extract the first 12 bytes as the IV before proceeding. This is necessary for GCM mode and follows standard authenticated encryption practice.

2. **Output size**: The output is now 12 bytes (IV) + ciphertext length + 16 bytes (GCM authentication tag). ECB with PKCS5Padding produced variable padding; GCM produces a fixed 16-byte tag with no additional padding, so the net size change depends on the original padding.

3. **Authentication**: GCM mode provides authenticated encryption. Decryption will fail with an `AEADBadTagException` if the ciphertext or IV has been tampered with. The original ECB mode provided no authenticity check.

4. **Decryption requirement**: Any code decrypting the output must be updated to extract the IV, create a `GCMParameterSpec`, and use `Cipher.init(Cipher.DECRYPT_MODE, key, spec)` before decryption. ECB decryption required no IV.

5. **Randomness dependency**: The fix introduces a call to `SecureRandom.nextBytes()` to generate the IV. This adds a runtime system resource dependency but is essential for cryptographic security.
