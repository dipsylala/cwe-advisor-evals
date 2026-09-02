## Verdict

CWE-502 (Deserialization of Untrusted Data), exploitable, high confidence.

## Source

`SessionRestoreController.restore(String encodedSession)` (`SessionRestoreController.java:12`) takes `encodedSession` as a caller-supplied string with no indication it is validated or signed before this point. It is Base64-decoded to raw bytes (`SessionRestoreController.java:13`) and passed unchanged to `SessionDecoder.decode(byte[] payload)` (`SessionRestoreController.java:14`), which feeds it straight into `new ObjectInputStream(new ByteArrayInputStream(payload))` and calls `input.readObject()` at `SessionDecoder.java:10`. Nothing in the chain restricts which classes `readObject()` is allowed to instantiate, and nothing verifies the payload's integrity before deserialization begins. A caller who controls `encodedSession` therefore controls the bytes handed to native Java deserialization, which is enough to drive arbitrary class instantiation and, via gadget classes on the classpath, arbitrary code execution during `readObject()`.

## Fix

Library recommendation: replace `ObjectInputStream`/`readObject()` with Jackson's `ObjectMapper` (`com.fasterxml.jackson.core:jackson-databind`). The loaded guidance gives no minimum-safe-version floor for this library, so confirm the resolved version against SCA/dependency-check tooling before merging; do not enable `ObjectMapper.enableDefaultTyping()`/`activateDefaultTyping()`, which would reintroduce the same class-instantiation risk this fix removes. `RestoredSession` is a two-field `String` record, so no schema beyond the existing record definition is needed.

Vulnerable code (`SessionDecoder.java`):

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            // VULNERABLE: readObject() on attacker-controlled bytes with no class
            // allowlist and no integrity check - drives arbitrary class instantiation.
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

Fixed code (`SessionDecoder.java`):

```java
package cases.deserialize;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class SessionDecoder {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public RestoredSession decode(byte[] payload) {
        try {
            return MAPPER.readValue(payload, RestoredSession.class);
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

`SessionRestoreController.java` is unchanged - it still Base64-decodes `encodedSession` and forwards the bytes to `decoder.decode(payload)`.

## Explanation

The fix removes native Java deserialization from the decode path entirely and replaces it with Jackson JSON binding targeted at the specific `RestoredSession` type. `ObjectInputStream.readObject()` lets the byte stream itself dictate which class gets constructed and can invoke arbitrary code through `readObject()`/`readResolve()` on gadget classes reachable on the classpath; `ObjectMapper.readValue(payload, RestoredSession.class)` only ever populates the two declared `String` components of `RestoredSession` and, with default typing left disabled, cannot be steered into instantiating a different class. This is the primary defence the loaded CWE-502 guidance leads with for Java (prefer data-only formats over native serialization) rather than the fallback `ObjectInputFilter` allowlist, which is appropriate when native serialization can't be replaced - here it can, since the payload is a plain two-field DTO.

## Behaviour changes

- Wire format: the bytes `SessionDecoder.decode()` accepts must now be UTF-8 JSON matching `{"userId": "...", "cartId": "..."}` instead of a Java serialization stream. This is a breaking format change for any existing encoded session tokens or for an encoder elsewhere in the system that still produces Java-serialized bytes; that encoder (not present in this call chain) needs a corresponding update to emit JSON instead, and this fix should not be deployed independently of it.
- Failure behaviour: preserved. The original caught `IOException | ClassNotFoundException` and rethrew `IllegalArgumentException("invalid session", ex)`; Jackson's parse/mapping failures (`JsonProcessingException` and its subtypes) are all `IOException` subtypes, so the same single `catch (IOException ex)` still wraps every decode failure into the same `IllegalArgumentException("invalid session", ex)` the caller already handles. `ClassNotFoundException` is no longer thrown or caught because JSON binding never resolves a class name from the payload - there is nothing for that catch clause to do.
- New dependency: `com.fasterxml.jackson.core:jackson-databind` is added to the module. Confirm its resolved version via SCA/dependency-check tooling before merging, per the library recommendation above.
- No HMAC/signature check was added ahead of deserialization. The loaded general guidance recommends cryptographic integrity checks on serialized data as defence-in-depth, but implementing one requires key-management infrastructure (a signing secret and its distribution) that is not present anywhere in this two-file call chain; adding it here would mean inventing infrastructure outside the fix's actual scope. This is flagged as a follow-up for whichever component owns session-token issuance, not folded into this fix.
