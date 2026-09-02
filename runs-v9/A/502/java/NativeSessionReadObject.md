## Verdict

Confirmed. `SessionDecoder.decode` passes attacker-controlled bytes directly into `ObjectInputStream.readObject()`, Java's native deserialization mechanism. Any caller that can supply the `encodedSession` string that reaches `SessionRestoreController.restore` (a session/cart token is a classic externally-supplied value, typically arriving via a cookie or request parameter) controls the byte stream that `readObject()` will deserialize. Native Java deserialization resolves classes and invokes their `readObject`/`readResolve`/constructor logic during the call, before the caller gets a chance to validate anything about the result, so a crafted payload built from gadget classes already present on the classpath (or any library dependency) can achieve remote code execution, denial of service, or arbitrary object-graph construction, independent of what `RestoredSession` itself looks like.

## Source

`SessionRestoreController.restore(String encodedSession)` (`SessionRestoreController.java:12`) receives `encodedSession` from its caller with no indication it has been validated or signed, Base64-decodes it, and passes the resulting bytes to `SessionDecoder.decode` (`SessionRestoreController.java:14`), which feeds them straight into `new ObjectInputStream(...).readObject()` (`SessionDecoder.java:9-10`) — the CWE-502 sink. There is no allowlist, filter, signature check, or encryption anywhere on this path.

## Fix

Stop using native Java serialization for this data entirely. `RestoredSession` is two plain strings, so there is no need for `ObjectInputStream` at all — replace it with an explicit, integrity-checked encoding that cannot instantiate arbitrary classes.

```java
package cases.deserialize;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SessionDecoder {

    private static final String HMAC_ALGO = "HmacSHA256";
    private final SecretKeySpec macKey;

    public SessionDecoder(byte[] sessionSigningKey) {
        this.macKey = new SecretKeySpec(sessionSigningKey, HMAC_ALGO);
    }

    /**
     * payload format: "<userId>|<cartId>|<base64(hmac)>"
     * userId/cartId must not themselves contain '|'; reject if they do.
     */
    public RestoredSession decode(byte[] payload) {
        String raw = new String(payload, StandardCharsets.UTF_8);
        int lastSep = raw.lastIndexOf('|');
        if (lastSep < 0) {
            throw new IllegalArgumentException("invalid session");
        }

        String body = raw.substring(0, lastSep);
        String suppliedMacB64 = raw.substring(lastSep + 1);

        String[] parts = body.split("\\|", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid session");
        }

        byte[] expectedMac = computeMac(body);
        byte[] suppliedMac;
        try {
            suppliedMac = Base64.getDecoder().decode(suppliedMacB64);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }

        if (!MessageDigest.isEqual(expectedMac, suppliedMac)) {
            throw new IllegalArgumentException("invalid session");
        }

        return new RestoredSession(parts[0], parts[1]);
    }

    private byte[] computeMac(String body) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(macKey);
            return mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("mac computation failed", ex);
        }
    }
}
```

`SessionRestoreController` needs no change beyond construction, since `SessionDecoder`'s public signature (`decode(byte[]) -> RestoredSession`) is unchanged; the encoder that originally produced `encodedSession` must be updated in parallel to emit `userId|cartId|hmac` instead of Java-serialized bytes, and `SessionDecoder` must be constructed with the server-held signing key (from configuration/secret storage, never derived from the request).

If native Java serialization cannot be removed for this class in the short term (for example, `RestoredSession` is shared with another system that requires it), the minimum viable mitigation is to install a strict `ObjectInputFilter` on the stream before calling `readObject()`, allowlisting only `cases.deserialize.RestoredSession` and `java.lang.String`, and rejecting everything else (`input.setObjectInputFilter(filter)` with a filter built via `ObjectInputFilter.Config.createFilter("cases.deserialize.RestoredSession;java.lang.String;!*")`). This is a fallback, not the primary fix: an allowlist filter still trusts the JVM's own class-resolution and constructor path for the allowed classes and must be re-audited whenever the allowlist changes, whereas removing `ObjectInputStream` from the untrusted path removes the vulnerability class outright.

## Explanation

The root problem is not any specific gadget chain — it is that `ObjectInputStream.readObject()` was invoked at all on bytes that originate outside the trust boundary. `readObject()` reconstructs objects by resolving class names embedded in the stream and running their deserialization constructors/methods, so the set of "dangerous" classes is effectively every class on the application's runtime classpath, including transitive dependencies the application authors never intended to expose this way. Because `RestoredSession` only carries two `String` fields, there is no genuine need for Java's general-purpose object graph reconstruction; a minimal, explicit text format that the decoder parses itself (never invoking a class's own deserialization logic) and that carries a server-side HMAC to detect tampering closes the vulnerability completely rather than narrowing it. The HMAC is essential and distinct from the format change: without it, an attacker who cannot execute code via gadgets could still forge arbitrary `userId`/`cartId` values (e.g., to impersonate another user's session or cart), which is a separate, equally serious flaw that a bare format swap would not address. The `ObjectInputFilter` fallback is included only because some environments have a hard, unavoidable dependency on Java-serialized wire format; it should not be treated as equivalent in strength to eliminating `ObjectInputStream` from the untrusted path, since filter allowlists have historically been bypassed when overly broad or misconfigured.
