## Verdict

CONFIRMED. The code uses `Cipher.getInstance("AES")` without specifying a cipher mode. This defaults to ECB (Electronic Codebook) mode, which is cryptographically weak and violates CWE-326. ECB encrypts each plaintext block independently to the same ciphertext block, leaking patterns in the encrypted data.

## Source

Line 21 in `EcbDefaultCipher.java`:
```java
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
```

The default mode for this call is "AES/ECB/PKCS5Padding", which is inadequate for securing sensitive data like SSN (Social Security Number).

## Fix

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

        // Use GCM mode with a randomly generated IV for secure authenticated encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Generate a random 96-bit (12-byte) IV
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Initialize cipher with GCM parameters (128-bit authentication tag)
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));
        
        // Prepend IV to ciphertext for decryption: receiver needs IV to decrypt
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(ivAndCiphertext));
    }
}
```

## Explanation

The fix addresses CWE-326 by replacing ECB mode with GCM (Galois/Counter Mode):

1. **Explicit cipher specification**: Changed from `Cipher.getInstance("AES")` (which defaults to ECB) to `Cipher.getInstance("AES/GCM/NoPadding")`, explicitly requesting a secure authenticated encryption mode.

2. **Random IV generation**: Each encryption now uses a unique, randomly generated 96-bit initialization vector via `SecureRandom`. This ensures identical plaintexts produce different ciphertexts, preventing pattern leakage.

3. **GCMParameterSpec initialization**: The cipher is initialized with `GCMParameterSpec(128, iv)`, which specifies a 128-bit authentication tag. GCM provides both confidentiality and authenticity, protecting against tampering.

4. **IV transmission**: The IV is prepended to the ciphertext and transmitted together. The receiver extracts the IV (first 12 bytes) and uses it to decrypt. The IV does not need to be kept secret; what matters is that it is unique per encryption.

GCM is a modern, standard cipher mode recommended by NIST and cryptographic best practices for symmetric encryption of sensitive data like SSNs.
