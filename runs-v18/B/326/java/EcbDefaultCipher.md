## Verdict

CONFIRMED - Inadequate Encryption Strength (CWE-326). The bare `Cipher.getInstance("AES")` defaults to ECB mode, which is unauthenticated and non-randomized. Identical plaintext blocks encrypt identically, enabling pattern analysis on sensitive data (SSN).

## Source

Line 13: `String ssn = request.getParameter("ssn");` - untrusted user input

## Fix

Replace the ECB-defaulting cipher with authenticated encryption using AES-GCM mode. Generate a random IV per encryption and prepend it to the ciphertext for transmission.

### File: EcbDefaultCipher.java

```java
package evalcases;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;

public class EcbDefaultCipher
{
    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Use authenticated encryption: AES/GCM instead of ECB
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Generate a random 12-byte IV for GCM
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        // Initialize cipher with GCM mode (128-bit tag length)
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));
        
        // Prepend IV to ciphertext for transmission (receiver needs it for decryption)
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(result));
    }
}
```

## Explanation

The fix replaces the insecure ECB cipher with AES-GCM, an authenticated encryption mode. ECB is vulnerable because it produces identical ciphertext for identical plaintext blocks; GCM adds a random IV per message and includes a 128-bit authentication tag, preventing both pattern analysis and ciphertext tampering. The IV is generated fresh for each encryption using `SecureRandom` and prepended to the ciphertext so the receiver can extract it during decryption. The GCMParameterSpec supplies both the IV and specifies a 128-bit tag length, which is the maximum and recommended value per JDK documentation.

## Behaviour changes

- Ciphertext output size increases by 12 bytes (IV) plus 16 bytes (GCM authentication tag), compared to the original ECB mode.
- Each encryption produces a different ciphertext for the same plaintext, due to the random IV.
- The receiver must extract the first 12 bytes as the IV before decrypting.
- Decryption will fail if the ciphertext is tampered with, due to GCM authentication.
- The method now imports `GCMParameterSpec` from `javax.crypto.spec` and `SecureRandom` from `java.security`.
