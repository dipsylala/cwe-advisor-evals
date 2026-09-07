## Verdict

Exploitable. The code uses `ObjectInputStream.readObject()` at line 10 without any class allowlist, permitting deserialization of arbitrary classes controlled by untrusted input. An attacker providing malicious serialized objects can trigger object instantiation and method execution during deserialization, leading to arbitrary code execution.

## Source

The attack surface originates in `SessionRestoreController.restore(String encodedSession)`, which accepts an untrusted Base64-encoded string from external input (HTTP request, message queue, etc.). This string is decoded and passed to `SessionDecoder.decode()`, where the bytes are deserialized without validation.

Call chain:
- `SessionRestoreController.restore()` line 13: `decoder.decode(payload)` receives attacker-controlled bytes
- `SessionDecoder.decode()` line 10: `input.readObject()` instantiates the object

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

The fix adds an `ObjectInputFilter` allowlist to the `ObjectInputStream` before calling `readObject()`. The filter uses a string-based pattern specification that:

1. Allows only `cases.deserialize.RestoredSession` — the specific class expected to be deserialized
2. Allows `java.base/*` — base Java classes (String, basic types) needed by RestoredSession fields
3. Rejects all other classes with `!*` — the final pattern blocks anything not explicitly allowed

The filter is attached per-stream via `setObjectInputFilter(filter)` before the first `readObject()` call. This ensures any attempt to deserialize a class outside the allowlist is rejected, preventing gadget-chain exploitation and code execution. The allowlist approach is appropriate here because both the serializer and deserializer are under the application's control and can be kept in sync.

## Behaviour changes

None. The fix adds filter setup but does not alter the method's return type, argument handling, or error contract. The `IllegalArgumentException` is still thrown on serialization errors. The filter rejection behaves like a deserialization failure (caught by the existing exception handler and re-wrapped), so no new exception types are exposed to callers.

Verification: Fixed code compiled successfully with `javac 26` without errors or warnings.
