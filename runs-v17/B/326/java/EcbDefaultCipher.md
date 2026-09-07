## Verdict
exploitable

## Source
`request.getParameter("ssn")` at line 13, attacker-controlled HTTP request parameter.

## Fix

### File: EcbDefaultCipher.java

```java
package evalcases;

import java.util.Base64;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

        // Fixed: Use AES/GCM/NoPadding instead of ECB mode for authenticated encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Generate a fresh 12-byte IV for this message
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Initialize with GCMParameterSpec: 128-bit tag length, fresh IV
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        // Prepend the IV to the ciphertext for transmission to decryption side
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(result));
    }
}
```

## Explanation
The original code used `Cipher.getInstance("AES")` which, per Oracle's JDK documentation, defaults to ECB mode with PKCS5 padding when no explicit mode is specified by the SunJCE provider. ECB mode is cryptographically weak because identical plaintext blocks encrypt to identical ciphertext blocks, creating detectable patterns that leak information about the plaintext. The fix replaces this with AES-GCM (Galois/Counter Mode), which provides both confidentiality and authenticated encryption. Each message receives a fresh 12-byte IV generated via `SecureRandom`, ensuring that identical plaintexts produce different ciphertexts. The IV is prepended to the encrypted output so the decryption side can extract and use it; GCM's built-in authentication tag (128 bits) is appended by the cipher automatically. This prevents both pattern leakage and ciphertext tampering.

## Behaviour changes
- **Output format**: The ciphertext output now includes the 12-byte IV prepended to the encrypted data (previously only the ECB-mode ciphertext was output).
- **Output size**: The result is larger—adds 12 bytes for the IV plus 16 bytes for GCM's authentication tag. The cipher.doFinal() output for GCM includes the tag automatically.
- **Non-deterministic encryption**: The same plaintext input now produces different ciphertext on each invocation due to the random IV; the original ECB mode was deterministic (same plaintext → same ciphertext).
- **Authentication**: GCM mode provides authenticated encryption; the original ECB mode provided only confidentiality with no integrity protection.
- **Decryption-side change required**: Code decrypting this output must now extract the first 12 bytes as the IV, pass it via GCMParameterSpec to the decryption Cipher, and the remaining bytes as the authenticated ciphertext.

## Verification
Compiled via `javac` and executed a test program that:
1. Generated a 256-bit AES key using SecureRandom
2. Created a Cipher with transformation "AES/GCM/NoPadding"
3. Generated a fresh 12-byte IV
4. Initialized the Cipher with GCMParameterSpec(128, iv)
5. Encrypted sample data and prepended the IV to the result
6. Base64-encoded the output

Result: Compilation succeeded with no errors; runtime test completed successfully with non-deterministic output confirming IV randomization. All required imports (`GCMParameterSpec`, `SecureRandom`) are available in the standard Java Cryptography Architecture (JCA).
