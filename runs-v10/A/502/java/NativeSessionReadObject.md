## Verdict
VULNERABLE

## Source
`SessionRestoreController.restore()` receives a Base64-encoded string from an external caller (untrusted input), decodes it to bytes, and passes it to `SessionDecoder.decode()`.

## Fix
Replace unsafe deserialization with an ObjectInputFilter that restricts deserialization to the expected `RestoredSession` class:

```java
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "cases.deserialize.RestoredSession"
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
The original code uses `ObjectInputStream.readObject()` without validation, allowing deserialization of arbitrary classes. An attacker can craft a malicious serialized object using gadget chains from common libraries (e.g., Apache Commons Collections, Spring Framework) to achieve remote code execution.

The fix uses `ObjectInputFilter` (available in Java 9+) to create a whitelist that permits deserialization only of the `RestoredSession` class. This prevents gadget-chain attacks while preserving the intended functionality of restoring sessions from trusted data. The filter is set before calling `readObject()` to ensure all class checks pass through it.
