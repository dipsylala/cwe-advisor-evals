## Verdict

Confirmed. `Cipher.getInstance("AES")` at line 21 names an algorithm with no mode and no
padding. The JDK resolves that bare form through the provider's defaults, and for SunJCE the
result is `AES/ECB/PKCS5Padding`. The application therefore encrypts a Social Security number
under ECB, which is a deterministic, unauthenticated block-by-block transform: identical
plaintext blocks produce identical ciphertext blocks under the same key, so the Base64 value
returned at line 26 leaks equality between submissions and reveals structure within any input
longer than one 16-byte block. There is no IV and no integrity tag, so the ciphertext is also
malleable - an attacker who can modify it can flip plaintext bits or reorder, drop, and replay
whole blocks without detection.

The second half of the weakness is that the strength of this operation is never asserted. The
`SecretKey` arrives as a parameter, so this method encrypts under whatever the caller supplied,
including an AES-128 key or a short key derived elsewhere, with no floor enforced at the point
of use.

## Source

- Source: `request.getParameter("ssn")` (line 13) - untrusted request parameter, and PII.
- Sink: `Cipher.getInstance("AES")` then `cipher.init(...)` and `cipher.doFinal(...)`
  (lines 21-23).
- Exit: the Base64-encoded ciphertext is written back to the requester at line 26, so the
  attacker observes the output of the weak cipher for plaintext they chose. That is the
  strongest possible position from which to exploit ECB - it turns the endpoint into a
  chosen-plaintext oracle, letting an attacker build a codebook of block-to-ciphertext mappings
  under the server's key and then recognise those blocks in any other ciphertext produced with
  the same key.

## Fix

Name the full transformation explicitly, use an authenticated mode with a per-message random
IV, and assert the key strength at the point of use.

```java
package evalcases;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EcbDefaultCipher
{
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MIN_KEY_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] encoded = key.getEncoded();
        if (!"AES".equalsIgnoreCase(key.getAlgorithm())
            || (encoded != null && encoded.length < MIN_KEY_BYTES))
        {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        byte[] iv = new byte[GCM_IV_BYTES];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(ssn.getBytes(StandardCharsets.UTF_8));

        byte[] output = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(output));
    }
}
```

The key itself should be generated at AES-256 wherever it is created, which is outside this
method:

```java
KeyGenerator generator = KeyGenerator.getInstance("AES");
generator.init(256);
SecretKey key = generator.generateKey();
```

## Explanation

**Never pass a bare algorithm name to `Cipher.getInstance`.** `"AES"`, `"DES"`, and `"RSA"` all
resolve to a provider-chosen default mode, and on the reference JDK provider that default is
ECB. Because the resolution happens inside the provider, the source reads as though no mode was
chosen at all, which is exactly why this class of finding survives review. Always pass the
three-part `algorithm/mode/padding` form so the mode is a decision visible in the code and
stable across providers and JDK versions.

**AES-GCM replaces ECB, and it also replaces the separate MAC you would otherwise need.** GCM
is an AEAD mode: one pass produces both the ciphertext and a 128-bit authentication tag, and
`doFinal` on the decrypt side throws `AEADBadTagException` if either has been altered. That
matters here because the ciphertext is handed to the client and may come back later - without a
tag, any modification a client makes is accepted silently. Encrypt-then-MAC with a second key
is the alternative if GCM is unavailable, but GCM has been in the JDK since Java 7, so that is
rarely necessary. Do not substitute `AES/CBC/PKCS5Padding` as the fix: it removes the ECB
pattern leak but is still unauthenticated, and padding-oracle attacks against unauthenticated
CBC over an HTTP endpoint that reports decryption errors are well established.

**The IV must be fresh and random for every message, and must never repeat under one key.**
GCM's security collapses entirely on nonce reuse - two messages encrypted under the same key
and IV allow an attacker to recover the XOR of the plaintexts and, worse, to recover the GCM
authentication subkey, forging tags for arbitrary messages from then on. This is why the fix
draws 12 fresh bytes from `SecureRandom` per call rather than using a constant or a shared
counter. 12 bytes is the correct length: GCM uses 96-bit nonces directly, while other lengths
are compressed through GHASH first, which is slower and gains nothing.

**The IV is not a secret and must travel with the ciphertext.** Decryption needs it, so the fix
prepends the 12 raw bytes before Base64-encoding. The decrypt side takes the first 12 bytes as
the IV, builds the same `GCMParameterSpec`, and passes the remainder to `doFinal`. Storing the
IV separately from the data it belongs to, or deriving it from the plaintext, are the two
common ways this goes wrong.

**Assert key strength where the key is used, not only where it is created.** The `SecretKey`
here is a parameter, so this method cannot see how it was generated. The added guard rejects a
non-AES key and any raw key under 128 bits before it reaches `init`. `getEncoded()` returns
`null` for keys held in an HSM or PKCS#11 token whose material is not extractable, so the
length check is skipped in that case rather than rejecting a valid hardware key. The real floor
still belongs at generation: `KeyGenerator.getInstance("AES").init(256)`. AES-256 needs no
special configuration on any currently supported JDK - the unlimited-strength policy files were
a Java 8 concern before update 161 and are not a consideration now.

**Two points beyond the reported finding.** First, this endpoint encrypts an SSN supplied by
the requester and returns the ciphertext to that same requester, which is the chosen-plaintext
oracle described above; consider whether the ciphertext needs to be returned at all, and set
`Cache-Control: no-store` if it does. Second, a long-lived key protecting stored PII should be
rotatable - prefixing stored ciphertext with a key identifier alongside the IV costs little now
and makes rotation possible later.
