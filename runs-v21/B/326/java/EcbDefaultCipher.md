## Verdict

The finding is confirmed. `Cipher.getInstance("AES")` defaults to ECB mode, which is inadequate encryption because identical plaintexts produce identical ciphertexts, leaking plaintext patterns. The SSN, a sensitive and potentially repetitive value, should be encrypted with an AEAD mode.

## Source

Line 21: `Cipher cipher = Cipher.getInstance("AES");`

The call omits the transformation's mode and padding arguments, causing the JDK to default to ECB mode with PKCS5Padding. ECB is cryptographically weak for this purpose.

## Fix

Replace the transformation with `"AES/GCM/NoPadding"` and generate a fresh 12-byte IV per message using `SecureRandom`. The IV must be transmitted alongside the ciphertext so the recipient can decrypt. Prepend the IV to the ciphertext before Base64 encoding.

### File: EcbDefaultCipher.java

```java
package evalcases;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EcbDefaultCipher
{
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12;

    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Fixed: Use AES/GCM/NoPadding with a fresh IV per message
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Generate a fresh 12-byte IV for GCM
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        random.nextBytes(iv);
        
        // Initialize cipher with GCM parameters (128-bit tag)
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        // Prepend IV to ciphertext so it can be transmitted and used for decryption
        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(encryptedData));
    }
}
```

## Explanation

The fix replaces ECB with AES-GCM, an authenticated encryption mode that prevents pattern leakage. Each encryption generates a cryptographically random 12-byte IV using `SecureRandom`, which is required for GCM security. The `GCMParameterSpec(128, iv)` configures GCM with a 128-bit authentication tag. The IV is prepended to the ciphertext before transmission because GCM requires it for decryption; the recipient can extract the first 12 bytes as the IV and the remainder as the authenticated ciphertext. All names (`SecureRandom`, `GCMParameterSpec`, `System.arraycopy`) are from the standard library.

## Behaviour changes

- Ciphertext format changed: prepend IV (12 bytes) plus GCM tag (16 bytes) versus ECB's PKCS5Padding overhead. The total output is slightly larger but gains authenticated encryption.
- Encryption is now non-deterministic: identical plaintexts produce different ciphertexts (due to fresh IV per message), preventing plaintext pattern leakage.
- Decryption must extract the IV from the first 12 bytes before calling `cipher.doFinal()` to authenticate and decrypt the remainder.
- IV reuse is detected by SunJCE's undocumented check and throws `InvalidAlgorithmParameterException`, but this is not guaranteed and should not be relied on; never reuse an IV with the same key.
