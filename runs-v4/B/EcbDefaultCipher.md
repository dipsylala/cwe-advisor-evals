## Verdict

exploitable - confidence: high

- **CWE:** CWE-326 (Inadequate Encryption Strength)
- **Location:** `e:/Github/cwe-advisor/evals/cases/326/java/EcbDefaultCipher/EcbDefaultCipher.java`, lines 21-23 (sink at line 21)
- **Library recommendation:** none. The fix uses only the JDK's built-in JCA/JCE (`javax.crypto`); no dependency is added or upgraded.

`Cipher.getInstance("AES")` names an algorithm with no mode and no padding, so the provider supplies its defaults. On SunJCE that resolves to `AES/ECB/PKCS5Padding`. ECB is deterministic and block-independent: identical 16-byte plaintext blocks encrypt to identical ciphertext blocks under the same key, so the ciphertext leaks plaintext structure and equality. It is also unauthenticated, so a ciphertext can be truncated, reordered by block, or spliced with another ciphertext produced under the same key without detection.

The exposure here is concrete rather than theoretical. The plaintext is a caller-supplied SSN - a short, low-entropy, fixed-format value that fits in one or two AES blocks. An attacker who can call the endpoint can submit candidate SSNs and compare the returned Base64 against a captured ciphertext, recovering the plaintext by dictionary attack without ever attacking AES itself. Repeated submissions of the same SSN also produce byte-identical output, which reveals equality across users and requests.

## Source

- **Source:** `request.getParameter("ssn")` (line 13) - untrusted request parameter, reachable by any caller of `handle`.
- **Path:** `ssn` is null-checked (line 14) and otherwise passed through unmodified; no validation, canonicalisation, or transformation is applied. It is encoded with `ssn.getBytes("UTF-8")` (line 23) and passed straight into the cipher.
- **Sink:** the `Cipher` configured at line 21 and used at line 23. The resulting ciphertext is Base64-encoded and written to the response body (line 26), so the attacker observes the sink's output directly.

Sink contract established before fixing:

- **Returns:** `doFinal` returns the raw ciphertext bytes; the caller Base64-encodes them and writes them as the `text/plain` response body.
- **Discards:** nothing. There is no IV, no authentication tag, and no other output the current code drops.
- **Arguments left implicit:** the mode and padding omitted from the transformation string (provider default `ECB/PKCS5Padding`), and the `AlgorithmParameterSpec` omitted from `init` (no IV, because ECB takes none). Both of those defaults are exactly what makes this weak. The `SecretKey` is supplied by the caller and its length is outside this method's control.
- **Failure behaviour:** every checked exception propagates - the method declares `throws Exception` and does not catch. Nothing depends on a particular exception type.

## Fix

Vulnerable code:

```java
// Provider default resolves to AES/ECB/PKCS5Padding: deterministic and unauthenticated.
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

response.setContentType("text/plain");
response.getWriter().write(Base64.getEncoder().encodeToString(ciphertext));
```

Fixed file:

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
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] iv = new byte[GCM_IV_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        byte[] output = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(output));
    }
}
```

The decryption side must be updated to match: split the first 12 bytes off the decoded payload as the IV, build the same `GCMParameterSpec(128, iv)`, and call `doFinal` on the remainder. An `AEADBadTagException` on decrypt means the ciphertext was altered and must be rejected, not retried.

## Explanation

The transformation string now names mode and padding explicitly - `AES/GCM/NoPadding` - so no provider default decides the mode, and GCM replaces ECB with an authenticated stream mode. Each call draws a fresh 12-byte IV from `SecureRandom` and passes it via `GCMParameterSpec(128, iv)`, which is what removes the determinism: the same SSN encrypted twice under the same key now yields different ciphertext, so the guess-and-compare attack against a short, low-entropy plaintext no longer works and equality across users is no longer observable. The 128-bit authentication tag that GCM appends means any modification, truncation, or block splicing of the ciphertext is detected at decryption instead of silently producing altered plaintext. The IV is not secret but is required to decrypt, so it is prepended to the ciphertext before Base64 encoding, keeping the response a single self-contained token as before. Two constraints stay outside this method: GCM is catastrophically broken if an IV is ever reused under one key, which the per-call `SecureRandom` draw addresses here but which also requires that `key` is not shared with another component using a counter-based or fixed IV; and the key's strength is the caller's, so `key` should be 256-bit AES material generated via `KeyGenerator.getInstance("AES")` with `init(256)`.

## Behaviour changes

- **Response body format changed.** The output is now Base64 of `IV || ciphertext || tag` rather than Base64 of ciphertext alone. Required: GCM cannot decrypt without the IV, and the tag is what provides integrity. Any existing decryptor or stored value must be migrated - ciphertext produced by the old code is not readable by the new path, and vice versa.
- **Response body length changed.** GCM is a stream mode with `NoPadding`, so the ciphertext is exactly the plaintext length instead of being padded up to a 16-byte boundary, but 12 bytes of IV and 16 bytes of tag are added. Net effect for a 9-11 character SSN: the Base64 string grows from 24 characters to 48. Required by the mode change; relevant if any column width or response-size assumption exists downstream.
- **New `SecureRandom` field and two new constants added to the class.** Required to generate a unique IV per call; a static final `SecureRandom` is thread-safe and avoids reseeding on every request. No other class member is touched.
- **`cipher.init` now takes a third argument.** The original omitted the `AlgorithmParameterSpec` because ECB has no IV; GCM requires one. This is the omitted default being made explicit rather than a widening of behaviour.
- **New failure mode on this path.** `init` can now throw `InvalidAlgorithmParameterException`. It is already covered by the method's `throws Exception` and propagates identically to the existing `NoSuchAlgorithmException` / `NoSuchPaddingException` / `InvalidKeyException`, so there is no caller-visible change in error handling. On the decryption side, a new `AEADBadTagException` on tampered input replaces the old code's silent acceptance of garbage plaintext.
- **Unchanged:** the null check and its 400 response, the `UTF-8` encoding of the plaintext, the `text/plain` content type, the method signature, and the fact that nothing produced by the cipher is discarded.
- **Not changed, and flagged rather than fixed:** the key size. `key` is a method parameter, so this method cannot enforce AES-256; verify at the key's generation site that `KeyGenerator.getInstance("AES").init(256)` is used. Separately, this endpoint returns an encrypted SSN to whoever supplied it, which is an access-control question outside the scope of this weakness.

## Assumptions

- The finding names line 21, and the file is self-contained with no other source in the case directory, so the trace is complete within this file. `key` is treated as valid AES key material supplied by a caller not shown; its length could not be verified from here, which is why the key-size point is flagged rather than changed.
- No decryption counterpart exists in the provided code, so the wire-format change is stated as a migration requirement rather than applied to a second site.
