## Verdict

CWE-326 (Inadequate Encryption Strength) confirmed. The bare `Cipher.getInstance("AES")` call defaults to ECB mode with PKCS5Padding. ECB is insecure because identical plaintexts produce identical ciphertexts, revealing patterns in the plaintext. The fix is to specify the full transformation as `AES/GCM/NoPadding` for authenticated encryption, generate a fresh IV per message, and transmit the IV alongside the ciphertext for decryption.

## Source

```java
// Line 21 in EcbDefaultCipher.java
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));
```

The transformation string is incomplete, leaving mode and padding selection to the JDK's defaults (ECB and PKCS5Padding).

## Fix

```java
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

// ...in the handle method:
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
SecureRandom random = new SecureRandom();
random.nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

// Prepend the IV to the ciphertext so the recipient can decrypt
byte[] result = new byte[iv.length + ciphertext.length];
System.arraycopy(iv, 0, result, 0, iv.length);
System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(result));
```

## Explanation

- `AES/GCM/NoPadding` is authenticated encryption: GCM adds a 128-bit authentication tag that fails decryption if the ciphertext is tampered with.
- ECB mode reuses the cipher state for each block, producing identical ciphertexts from identical plaintexts; GCM uses a per-message IV to ensure identical plaintexts produce different ciphertexts.
- Each encryption call generates a fresh 12-byte IV (96 bits), the standard length for GCM.
- `GCMParameterSpec(128, iv)` specifies the IV and requests a 128-bit authentication tag (the maximum, and the default SunJCE accepts).
- The IV must be transmitted with the ciphertext; it is not secret. Prepending the IV allows the recipient to extract it and pass it to `GCMParameterSpec` during decryption with the same cipher key.
- `NoPadding` is required for GCM; the mode handles framing internally and does not add padding bytes.

## Behaviour changes

- Ciphertext size increases by 28 bytes per message: 12 bytes for the IV and 16 bytes for the GCM authentication tag.
- Decryption now verifies authenticity: a tampered or corrupted ciphertext throws `AEADBadTagException`, preventing silent corruption or manipulation.
- Each encryption of the same plaintext now produces a different ciphertext due to the fresh IV, masking plaintext patterns.
- The IV must be transmitted alongside the ciphertext; callers cannot assume the IV is known to both parties.
- Identical plaintexts no longer map to identical ciphertexts, eliminating the primary weakness of ECB.
