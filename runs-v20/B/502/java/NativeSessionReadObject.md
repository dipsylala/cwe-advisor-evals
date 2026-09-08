## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Location**: `SessionDecoder.java:10`, `input.readObject()`
- **Source**: `SessionRestoreController.restore(String encodedSession)` - `encodedSession` is an externally supplied, Base64-encoded session token (a client-facing "restore session" entry point); it is Base64-decoded into `payload` with no other validation.
- **Sink**: `SessionDecoder.decode(byte[] payload)` passes `payload` straight into `new ObjectInputStream(...).readObject()` with no `ObjectInputFilter` attached.

## Source

`SessionRestoreController.restore(String encodedSession)`:

```
byte[] payload = Base64.getDecoder().decode(encodedSession);
return decoder.decode(payload);
```

`encodedSession` is attacker-controlled and reaches the sink unchanged except for Base64 decoding, which does not constrain or validate the decoded bytes in any way. No integrity check (HMAC or signature) and no type restriction is applied before the bytes are handed to native Java deserialization. Because `ObjectInputStream.readObject()` resolves and instantiates whatever class the stream's embedded class descriptor names - invoking that class's `readObject()`/`readResolve()` during reconstruction - the attacker can substitute a gadget-chain class for the expected `RestoredSession` and trigger code execution before any cast or type check in `SessionDecoder` ever runs. The `catch (IOException | ClassNotFoundException)` block does not stop this: those exceptions are only reached after deserialization has already run.

## Fix

### File: SessionDecoder.java

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class SessionDecoder {
    private static final ObjectInputFilter SESSION_FILTER = ObjectInputFilter.Config.createFilter(
            "cases.deserialize.RestoredSession;java.lang.String;maxdepth=5;maxarray=100;maxrefs=50;maxbytes=10000;!*");

    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            input.setObjectInputFilter(SESSION_FILTER);
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation

The call chain only shows the consumer (`SessionRestoreController` / `SessionDecoder`); no producer of the serialized bytes is in scope, so a format swap to JSON cannot be verified as safe for every existing producer of these tokens (per the CWE-502 root and Java guidance, a decoder-only format change would silently reject or corrupt any session token already issued under the current format). The fix therefore keeps `ObjectInputStream` and closes the weakness at the sink instead: an `ObjectInputFilter`, built with `ObjectInputFilter.Config.createFilter(String)`, is attached to the stream via `input.setObjectInputFilter(...)` before `readObject()` runs. The filter pattern allowlists only `cases.deserialize.RestoredSession` and `java.lang.String` (the class and its component type actually needed to reconstruct a session), rejects every other class with the trailing `!*`, and caps stream depth/array size/reference count/byte count to bound resource use during reconstruction. Because the filter runs during class resolution, a gadget-chain class substituted for `RestoredSession` is rejected before its `readObject()`/`readResolve()` can execute, eliminating the arbitrary-object-construction path while leaving legitimate `RestoredSession` payloads unaffected. A disallowed class causes `ObjectInputStream` to throw `InvalidClassException` (a subtype of `IOException`), which the existing `catch (IOException | ClassNotFoundException)` block already converts to `IllegalArgumentException("invalid session", ex)` - the same failure contract callers already observe for a malformed payload, so no caller-visible exception type changes.

## Behaviour changes

- Malformed/disallowed payloads that previously might have partially deserialized (or worse, executed gadget code) before failing now fail earlier, during class resolution - but they still surface as the same `IllegalArgumentException("invalid session", ex)` the caller already handles. No new checked or unchecked exception type is introduced.
- A legitimate `RestoredSession` payload deserializes exactly as before; return type, return value, and the `decode` method signature are unchanged.
- No change to `SessionRestoreController` or its `restore` method.
- Adds one new static field (`SESSION_FILTER`) and one new import (`java.io.ObjectInputFilter`, JDK standard library, part of `java.base` since JDK 9 / backported to 8u121); no third-party dependency introduced.

**Verification**: Compiled the fixed `SessionDecoder.java` together with the unmodified `SessionRestoreController.java` (same package, `RestoredSession` record) using `javac 26` - no errors or warnings. Additionally ran the filter at runtime in a scratch harness: `ObjectInputFilter.Config.createFilter(...)` parsed the pattern string without throwing `IllegalArgumentException`; deserializing a disallowed top-level class (`java.util.HashMap`) through `decode()` was rejected with `InvalidClassException: filter status: REJECTED`, wrapped as `IllegalArgumentException("invalid session", ...)` as expected; deserializing an allowed record shape (matching `RestoredSession`'s class name and `String` components) through the same filter succeeded and returned the expected values, confirming the allowlist does not block the intended payload shape.

**Assumption**: The producer of the serialized session bytes is outside the two-file call chain available for this finding, so the fix follows the guidance's non-breaking path (keep native serialization, allowlist via `ObjectInputFilter`) rather than assuming the producer can move to JSON in the same change. If the token-issuing code is in fact owned by the same team and can be changed together, replacing native serialization with a data-only format (e.g. Jackson to/from `RestoredSession`) is the stronger long-term fix per the loaded guidance, but that is a separate, coordinated change rather than a safe default here.
