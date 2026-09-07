## Verdict

Exploitable. The `decode()` method in `SessionDecoder` deserializes untrusted user-supplied data without any validation or filtering, allowing arbitrary object instantiation and potential code execution via gadget chains.

## Source

The vulnerability originates in `SessionRestoreController.restore()` which accepts an `encodedSession` parameter (untrusted user input). This Base64-encoded payload is decoded and passed to `SessionDecoder.decode()` without integrity verification. The deserialization sink is reached by:

1. `SessionRestoreController.restore(String encodedSession)` receives the user input
2. `Base64.getDecoder().decode(encodedSession)` decodes the payload to bytes
3. `SessionDecoder.decode(byte[] payload)` creates an `ObjectInputStream` with untrusted bytes
4. `ObjectInputStream.readObject()` at line 10 deserializes the bytes into arbitrary objects

## Fix

### File: SessionDecoder.java

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            // Allowlist only the expected class and safe Java types
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "cases.deserialize.RestoredSession;java.base/*;!*"
            );
            input.setObjectInputFilter(filter);
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation

An `ObjectInputFilter` allowlist is attached to the `ObjectInputStream` before calling `readObject()`. The filter permits only the `RestoredSession` class (the expected deserialization target) and classes from the `java.base` module (which includes `String`, primitive wrappers, and core types). All other classes are rejected with the final `!*` pattern. This prevents arbitrary class instantiation and gadget chain exploitation while preserving the legitimate deserialization of `RestoredSession` objects. The filter is applied per-stream using `setObjectInputFilter()`, which executes before the first `readObject()` call and is the correct pattern for per-request handlers (avoiding the `IllegalStateException` that would occur if using the process-wide `Config.setSerialFilter()` in a handler context).

## Behaviour changes

- Added import: `java.io.ObjectInputFilter`
- Added filter configuration and installation before `readObject()`
- No change to the return value, exception handling, or method signature
- The method now rejects serialized payloads containing classes outside the allowlist, causing `readObject()` to throw `IOException` with message indicating the class was filtered

