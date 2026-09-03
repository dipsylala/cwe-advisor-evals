## Verdict

Exploitable. The code deserializes untrusted data (Base64-encoded session bytes from user input) using Java's `ObjectInputStream.readObject()` without any validation, type filtering, or allowlisting. This enables gadget chain attacks where an attacker crafts a malicious serialized object to execute arbitrary code during deserialization.

**Location:** `evals/cases/502/java/NativeSessionReadObject/SessionDecoder.java:10`

**Data Flow:** User-controlled `encodedSession` string → Base64 decode → untrusted byte array → `SessionDecoder.decode()` → `ObjectInputStream.readObject()` (no validation) → arbitrary class instantiation and method invocation.

## Source

Entry point: `SessionRestoreController.restore(String encodedSession)` accepts user-controlled input, Base64-decodes it, and passes the resulting byte array to `SessionDecoder.decode()` without validation.

Sink: `ObjectInputStream.readObject()` at line 10 of `SessionDecoder.java` deserializes the untrusted payload with no restrictions on which classes can be instantiated.

## Fix

Replace Java's native serialization (which executes code during deserialization) with JSON deserialization using Jackson's `ObjectMapper`, which treats input as data only.

**Vulnerable code:**
```java
// SessionDecoder.java
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            return (RestoredSession) input.readObject();  // UNSAFE: Arbitrary class instantiation
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Fixed code:**
```java
// SessionDecoder.java
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

public class SessionDecoder {
    private static final ObjectMapper mapper = new ObjectMapper();

    public RestoredSession decode(byte[] payload) {
        try {
            return mapper.readValue(payload, RestoredSession.class);
        } catch (IOException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**SessionRestoreController.java** remains unchanged - it continues to Base64-decode the session string and pass bytes to `SessionDecoder.decode()`, now deserializing JSON instead of Java objects:

```java
// SessionRestoreController.java (unchanged interface)
import java.util.Base64;

public class SessionRestoreController {
    private final SessionDecoder decoder;

    public SessionRestoreController(SessionDecoder decoder) {
        this.decoder = decoder;
    }

    public RestoredSession restore(String encodedSession) {
        byte[] payload = Base64.getDecoder().decode(encodedSession);
        return decoder.decode(payload);  // Now safe: deserializes JSON data only
    }
}

record RestoredSession(String userId, String cartId) {}
```

Add Jackson dependency (e.g., in `pom.xml` for Maven):
```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
</dependency>
```

## Explanation

Java's native serialization invokes arbitrary class constructors, factory methods, and `readObject()` callbacks during deserialization - any of these can be exploited via gadget chains to execute attacker-controlled code. Replacing it with Jackson's `ObjectMapper.readValue()` eliminates this risk entirely by treating the input as data only, instantiating only the specified target class (`RestoredSession`) with no code execution during reconstruction.

Jackson's `ObjectMapper` is secure by default (no automatic type mapping or polymorphic type information). The `readValue(byte[], Class)` call ensures strict type safety: only the named class and its fields are accepted, rejecting any attempt to instantiate other classes.

## Behaviour changes

- **Serialization format**: Changes from Java binary serialization to JSON. Client code that serializes sessions must use `ObjectMapper.writeValueAsBytes(restoredSession)` or equivalent JSON encoding instead of Java serialization.
- **Exception handling**: Throws `IOException` (same as before) wrapped in `IllegalArgumentException`, preserving the existing error contract.
- **Return type and method signature**: Unchanged.
- **Dependency addition**: Jackson must be added as a compile/runtime dependency.
- **Casting**: Removed - the fixed code does not cast the result, as `mapper.readValue()` returns the correct type directly.

No other code behavior changes. The Base64 encoding step in the controller is preserved - it simply becomes the transport encoding for JSON data rather than serialized Java objects.
