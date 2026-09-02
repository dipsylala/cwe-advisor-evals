## Verdict

Confirmed. `Cipher.getInstance("AES")` requests the algorithm without specifying a mode or padding. In the default Java (Oracle/OpenJDK) JCE provider, the transformation string `"AES"` resolves to `AES/ECB/PKCS5Padding`. ECB mode encrypts each 16-byte block independently with no chaining and no randomization (no IV/nonce), so identical plaintext blocks always produce identical ciphertext blocks. This leaks structural information about the plaintext (patterns, repetition) directly from the ciphertext and provides no integrity protection, which is inadequate encryption strength for sensitive data such as an SSN.

## Source

`ssn` — obtained from `request.getParameter("ssn")` (line 13), an HTTP request parameter, then encrypted and returned to the client.

## Fix

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
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        // Prepend the IV so the recipient can decrypt; GCM's tag is appended to ciphertext already.
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(ivAndCiphertext));
    }
}
```

## Explanation

The transformation string is changed from the bare algorithm name `"AES"` (which the default provider resolves to `AES/ECB/PKCS5Padding`) to the explicit `"AES/GCM/NoPadding"`. GCM is an authenticated encryption mode: it chains blocks using a unique per-message nonce (the IV) so that identical plaintexts never produce identical ciphertexts, and it appends a 128-bit authentication tag that lets the decrypting party detect tampering or corruption — properties ECB has neither of.

A fresh, cryptographically random 12-byte IV is generated per encryption with `SecureRandom.getInstanceStrong()` and passed via `GCMParameterSpec`. Reusing an IV/key pair in GCM catastrophically breaks confidentiality and authenticity, so the IV must be regenerated for every call rather than hard-coded or reused across requests. Because the decrypting side needs the same IV to reconstruct the `GCMParameterSpec`, the IV is prepended to the ciphertext before Base64 encoding (a standard, widely used convention); the corresponding decryption routine must strip the first 12 bytes back off as the IV and feed the remainder (which already includes GCM's trailing tag) to the cipher.

`GCMParameterSpec`'s tag length is set to 128 bits, the maximum and recommended strength for `AES/GCM`, giving the strongest tamper-detection guarantee the mode supports. No padding is specified (`NoPadding`) because GCM is a stream-like mode operating on ciphertext of the same length as the plaintext plus the tag, so PKCS5 padding is unnecessary and unsupported for this transformation.

To verify: encrypt the same `ssn` value twice and confirm the two Base64 outputs differ (proving IV randomization defeats the deterministic-ciphertext weakness that ECB exhibited), and confirm that decrypting with a corrupted or truncated ciphertext throws `AEADBadTagException` rather than silently returning wrong plaintext, demonstrating the added integrity check.
