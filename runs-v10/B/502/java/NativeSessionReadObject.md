## Verdict

**CWE-502 confirmed and remediable.** The code uses Java's native `ObjectInputStream.readObject()` to deserialize untrusted user input (Base64-encoded session data) without class allowlisting. An attacker can craft a malicious serialized object containing a gadget chain to execute arbitrary code during deserialization.

## Source

The vulnerability originates from untrusted user input:
- `SessionRestoreController.restore(String encodedSession)` receives Base64-encoded data from an external caller
- The string is decoded to binary and passed to `SessionDecoder.decode(byte[])`
- `SessionDecoder` calls `ObjectInputStream.readObject()` on the untrusted binary payload (line 10)

The sink accepts any serializable class without validation, creating an exploitable deserialization path.

## Fix

Replace Java's native serialization with JSON using Jackson's `ObjectMapper`:

```java
package cases.deserialize;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class SessionDecoder {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public RestoredSession decode(byte[] payload) {
        try {
            return objectMapper.readValue(payload, RestoredSession.class);
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Dependency required:** Add `com.fasterxml.jackson.core:jackson-databind` to your build manifest. Confirm the resolved version against SCA/dependency-check tooling before merging.

## Explanation

Jackson's `ObjectMapper.readValue()` is safe by default for data-only formats because it:
1. Does not execute arbitrary code during deserialization - it only constructs objects from the JSON data structure
2. Accepts only the specified type (`RestoredSession.class`), rejecting any attempt to instantiate other classes
3. Validates against the schema of the target class (two string fields: `userId` and `cartId`)

This eliminates the gadget-chain attack surface entirely by replacing serialization with a data-format incapable of code execution. The `RestoredSession` record remains unchanged; only the deserialization mechanism is replaced.

## Behaviour changes

The serialized session format changes from Java object serialization to JSON. Any existing serialized sessions in Java binary format will fail to deserialize and must be re-created or migrated to JSON format. Application restarts will require users to re-authenticate and re-establish sessions.

The error handling is identical: invalid input (whether malformed JSON or decode errors) throws `IllegalArgumentException` with the original message and causation chain preserved.
