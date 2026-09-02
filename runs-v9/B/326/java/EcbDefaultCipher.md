## Verdict

Exploitable. Confidence: high.

## Source

`request.getParameter("ssn")` in `EcbDefaultCipher.handle` (`EcbDefaultCipher.java:13`) - a caller-supplied HTTP request parameter, treated as sensitive data (an SSN) by the surrounding code.

## Fix

Sink contract established before changing it: `Cipher.getInstance("AES")` (line 21) resolves via the SunJCE/SunPKCS11 default to `AES/ECB/PKCS5Padding`. `cipher.doFinal` returns raw encrypted bytes with no authentication tag; the caller discards nothing extra; the mode/padding argument is left implicit (defaulted) rather than passed explicitly; on failure `doFinal` throws (`IllegalBlockSizeException`/`BadPaddingException`), uncaught here and propagated via the method's `throws Exception`. ECB encrypts each block independently with no IV, so identical plaintext blocks produce identical ciphertext blocks - it leaks structure in the encrypted SSN and has no integrity check, so a modified ciphertext still decrypts.

Vulnerable code:

```java
// SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(ciphertext));
```

Fixed code:

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

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(ivAndCiphertext));
    }
}
```

## Explanation

The transformation string changes from the implicit `AES` (ECB/PKCS5Padding default) to the explicit authenticated mode `AES/GCM/NoPadding`, per the Java guidance's rule to name the full transformation rather than rely on the provider default. GCM requires a unique, unpredictable IV per encryption under the same key, so a fresh 12-byte IV is generated with `SecureRandom` for every call and passed via `GCMParameterSpec(128, iv)` with a 128-bit authentication tag. Because GCM is not deterministic and carries its own integrity tag, encrypting the same SSN twice now produces different ciphertexts, and any tampering with the returned bytes causes decryption to fail authentication instead of silently succeeding - closing both the pattern-leakage and the missing-integrity aspects of the ECB finding.

## Behaviour changes

- The IV is generated and prepended to the returned bytes (`ivAndCiphertext = iv || ciphertext`) before Base64 encoding. This is not optional: GCM decryption cannot proceed without the same IV used to encrypt, and the sink previously carried no IV at all (ECB uses none), so a transport mechanism for it has to be added. The decrypting side must be updated to read the first 12 bytes as the IV and the remainder as the GCM ciphertext+tag.
- The output is longer by 12 bytes (IV) + 16 bytes (GCM authentication tag) than the original ECB/PKCS5Padding ciphertext. This is inherent to moving from an unauthenticated, IV-less mode to AEAD and cannot be avoided while fixing the finding.
- Encrypting the same SSN value on two different requests now yields two different Base64 outputs (previously identical under ECB with a fixed key). This is the intended effect of the fix, not a side effect.
- No change to the HTTP status handling, content type, or error propagation (`doFinal` still throws on failure, uncaught, exactly as before).
