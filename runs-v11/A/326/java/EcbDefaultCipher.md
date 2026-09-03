## Verdict
CWE-326 confirmed. The code uses ECB mode (Electronic Codebook), the default for `Cipher.getInstance("AES")`, which is cryptographically weak. ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking information about the plaintext structure.

## Source
Line 21 in `EcbDefaultCipher.java`:
```java
Cipher cipher = Cipher.getInstance("AES");
```

When only the algorithm name is passed to `getInstance()`, Java defaults to ECB mode with no initialization vector. ECB is not suitable for encrypting variable-length or repeated data.

## Fix
Replace the cipher initialization to use CBC mode with a random IV:

```java
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

// Generate a random IV
SecureRandom random = new SecureRandom();
byte[] iv = new byte[16];
random.nextBytes(iv);

// Initialize cipher with CBC mode and IV
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

// Prepend the IV to the ciphertext so the recipient can decrypt
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));
byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(ivAndCiphertext));
```

Alternatively, use GCM mode (authenticated encryption):
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecureRandom random = new SecureRandom();
byte[] iv = new byte[12]; // GCM typically uses 12-byte IVs
random.nextBytes(iv);

cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
// ... rest of encryption and IV handling as above
```

## Explanation
ECB mode is deterministic and reuses the same ciphertext for the same plaintext block, making it vulnerable to pattern analysis. In this example, encrypting multiple SSNs with the same prefix would reveal those common prefixes in the ciphertext.

CBC (Cipher Block Chaining) mode eliminates this weakness by XORing each plaintext block with the previous ciphertext block (or the IV for the first block). Each encryption operation uses a unique, random IV, so identical plaintexts produce different ciphertexts.

GCM (Galois/Counter Mode) provides authenticated encryption—it both encrypts and verifies the integrity of the data, protecting against tampering.

The IV must be:
- Random and unpredictable (use `SecureRandom`)
- Never reused with the same key
- Transmitted or stored alongside the ciphertext (it does not need to be secret)

The fix above prepends the IV to the ciphertext before Base64 encoding, allowing the decryption side to extract and use the same IV.
