## Verdict

Exploitable. `Cipher.getInstance("AES")` resolves to `AES/ECB/PKCS5Padding` (SunJCE's documented default mode/padding for a bare algorithm name), and ECB is used directly to encrypt an attacker-supplied SSN with no IV and no authentication tag.

## Source

`request.getParameter("ssn")` (`HttpServletRequest`, line 13) - untrusted, attacker-controlled input from the HTTP request.

## Fix

Location: `EcbDefaultCipher.java` line 21, `Cipher.getInstance("AES")`.

Data flow: `ssn` is read from the request, UTF-8 encoded, and passed straight into `cipher.doFinal(...)` with no validation or transformation in between - the source reaches the sink unmodified.

Sink contract (`Cipher.getInstance("AES")` / `cipher.init` / `cipher.doFinal`):
- **Returns**: the ciphertext byte array, which the caller base64-encodes and writes as the entire HTTP response body.
- **Discards**: nothing from the current call chain; the caller uses the full return value.
- **Arguments left implicit**: mode and padding (defaulting to ECB/PKCS5Padding), and no IV/parameter spec is supplied at all - ECB needs none, which is itself the weakness.
- **Failure behaviour**: `doFinal` throws on a bad block size or algorithm mismatch; the method's `throws Exception` propagates any such failure to the servlet container's default error handling. This is unchanged by the fix.

Because the response carries only the raw ciphertext, and GCM decryption requires the same IV used to encrypt, the fix carries the IV alongside the ciphertext (prepended, before base64 encoding) rather than inventing a side channel not present in the original code.

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

The vulnerable code called `Cipher.getInstance("AES")` with no mode or padding named, which SunJCE resolves to ECB - a mode with no IV that encrypts identical plaintext blocks to identical ciphertext blocks and provides no integrity check, letting an attacker who can observe multiple ciphertexts infer repeated or related SSNs and undetectably tamper with the ciphertext. The fix names the full transformation `AES/GCM/NoPadding`, generates a fresh random 12-byte IV per encryption with `SecureRandom` (required because GCM's confidentiality and integrity guarantees both depend on IV uniqueness per key), and supplies it via `GCMParameterSpec(128, iv)` for a full 128-bit authentication tag. GCM is an AEAD mode, so the output additionally authenticates the ciphertext: any tampering causes `doFinal` on the decrypting side to throw rather than silently returning altered plaintext. Because the decrypting side needs the same IV, it is prepended to the ciphertext before base64 encoding, matching the one output channel the original code already used.

## Behaviour changes

- **Response body format changed**: the base64 output now decodes to `IV (12 bytes) || ciphertext+tag`, rather than raw ciphertext. Reason: GCM decryption is impossible without the IV, and the original code provided no other channel to carry it; this is required for the fixed output to be decryptable at all, not an optional addition.
- **Response body length increased**: by 12 bytes (IV) plus 16 bytes (GCM authentication tag) before base64 encoding. Reason: intrinsic to switching from an unauthenticated, IV-less mode to an AEAD mode - GCM's tag is what makes ciphertext tampering detectable, which is part of the fix, not incidental.
- **Any existing consumer of this endpoint's output must be updated** to strip the leading 12-byte IV and use `AES/GCM/NoPadding` with `GCMParameterSpec(128, iv)` on decrypt, since the ciphertext is no longer decryptable as bare ECB. No dual-read/legacy-format path is provided because the sink was outputting freshly computed data on every call (not reading back previously stored ciphertext), so there is nothing already at rest to remain compatible with.
- All other behaviour is unchanged: the null-`ssn` guard, the `SC_BAD_REQUEST` short-circuit, the response content type, and exception propagation via the method's `throws Exception` are untouched.

Assumptions: none requiring a mode choice - GCM is the guidance's stated AEAD replacement for ECB and matches the "encryption" classification in `cwe/326/java/INDEX.md`.

Verification: compiled the fixed file with `javac` (JDK 26) against minimal local stub interfaces for `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` (the servlet API is not on this JDK's classpath and is unrelated to the change under test); `javax.crypto.Cipher`, `SecretKey`, and `GCMParameterSpec` resolved from the JDK standard library. Compilation succeeded with no errors or warnings.
