## Verdict

Exploitable. Untrusted data from `SessionRestoreController.restore()` flows directly to `ObjectInputStream.readObject()` at line 10 of SessionDecoder.java without validation, allowing attackers to instantiate arbitrary classes and achieve remote code execution through deserialization gadget chains.

## Source

`SessionRestoreController.restore(String encodedSession)` receives a Base64-encoded string from an HTTP request (untrusted input). The string is decoded to bytes and passed to `SessionDecoder.decode(byte[] payload)`, which uses it directly as the source for Java object deserialization.

## Fix

**Vulnerable code (SessionDecoder.java, line 10):**
```java
public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            return (RestoredSession) input.readObject();  // Unsafe deserialization
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Fixed code:**
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class SessionDecoder {
    private final ObjectMapper mapper = new ObjectMapper();
    
    public RestoredSession decode(byte[] payload) {
        try {
            return mapper.readValue(payload, RestoredSession.class);
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Library recommendation:** Jackson (com.fasterxml.jackson.core:jackson-databind). The version must be confirmed against your dependency-check or SCA tooling; do not supply a version from recall. Use a current stable release.

## Explanation

The fix replaces Java's native `ObjectInputStream.readObject()` with Jackson's `ObjectMapper.readValue()`. Jackson is safe by default: it only deserializes data into the declared type (`RestoredSession`), never instantiates arbitrary classes. This eliminates the attack surface for deserialization gadget chains. The fixed code retains the same contract: it accepts untrusted bytes and returns a `RestoredSession` object, or throws an `IllegalArgumentException` on invalid input, matching the original failure behavior.

## Behaviour changes

1. **Data format change:** The payload must now be JSON text (e.g., `{"userId":"123","cartId":"456"}`) instead of Java-serialized binary. This requires `SessionRestoreController` to be updated to pass the Base64-decoded bytes as JSON-encoded text, or to receive JSON directly without Base64 encoding.

2. **No arbitrary class instantiation:** The original code could deserialize any class present in the classpath; the fixed code instantiates only `RestoredSession`, preventing polymorphic type confusion attacks.

3. **Exception granularity:** `ObjectMapper.readValue()` throws `IOException` for all serialization errors, while the original code distinguished `IOException` and `ClassNotFoundException`. The fix maps both to the same `IllegalArgumentException`, which is acceptable since both represent invalid input.

4. **Dependency addition:** Requires Jackson as a new runtime dependency. Verify it is not already present and that the version does not introduce other vulnerabilities.
