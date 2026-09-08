## Verdict
Confirmed. `Cipher.getInstance("AES")` resolves to the JCE default mode, which for AES is ECB (`AES/ECB/PKCS5Padding`). ECB encrypts identical 16-byte plaintext blocks to identical ciphertext blocks and provides no diffusion between blocks, so it leaks structural/repetition information about the plaintext (here, an SSN) and is classified as inadequate encryption strength (CWE-326).

## Source
`request.getParameter("ssn")` (line 13) flows unmodified into `cipher.doFinal(ssn.getBytes("UTF-8"))` (line 23), which is encrypted with the ECB-mode cipher instantiated on line 21 and returned to the client.

## Fix

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

        // Prepend the IV so the recipient can decrypt; GCM's tag is already
        // appended to ciphertext by doFinal().
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(ivAndCiphertext));
    }
}
```

## Explanation
`Cipher.getInstance("AES")` requests only the algorithm name, which the JCE resolves to a provider-default mode/padding (`AES/ECB/PKCS5Padding` on the standard SunJCE provider). ECB is deterministic per block and has no mechanism for randomization, so encrypting the same or related plaintext (e.g., SSNs sharing common prefixes, or the same SSN submitted twice) produces identical or comparable ciphertext blocks, letting an observer infer plaintext structure or equality without breaking the key.

The fix replaces ECB with AES-GCM (`AES/GCM/NoPadding`), an authenticated mode that requires a nonce (IV). The IV must never be reused with the same key, so it is generated fresh per encryption with `SecureRandom.getInstanceStrong()` at the standard 12-byte (96-bit) GCM nonce length, and a 128-bit authentication tag is used (GCM's maximum, appended by `doFinal()` to the returned ciphertext automatically). Because the IV is required for decryption and is not secret, it is prepended to the ciphertext before base64 encoding - the conventional layout for wire-format GCM output - rather than reusing a fixed or predictable value. This also gives the ciphertext integrity protection (tamper detection) that ECB/CBC without a MAC do not provide, at no extra dependency: `AES/GCM/NoPadding` is available in the JDK's built-in SunJCE provider (Java 8+), so no third-party library or version check is needed.

The `SecretKey key` parameter is unchanged; only the cipher's mode of operation and the framing of the output (IV + ciphertext instead of raw ciphertext) changed, since GCM requires the IV to be transmitted alongside the ciphertext.
