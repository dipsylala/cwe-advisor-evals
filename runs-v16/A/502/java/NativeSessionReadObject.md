## Verdict

CWE-502 confirmed. The `SessionDecoder.decode()` method at line 10 calls `ObjectInputStream.readObject()` on untrusted payload without restricting which classes can be deserialized, exposing the application to arbitrary code execution through gadget chains.

## Source

```java
public RestoredSession decode(byte[] payload) {
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
        return (RestoredSession) input.readObject();  // Line 10: no filter
    } catch (IOException | ClassNotFoundException ex) {
        throw new IllegalArgumentException("invalid session", ex);
    }
}
```

The untrusted payload flows from `SessionRestoreController.restore()` which Base64-decodes user input and passes it to this decoder.

## Fix

```java
import java.io.ObjectInputFilter;

public RestoredSession decode(byte[] payload) {
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
        input.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
            "cases.deserialize.RestoredSession"));
        return (RestoredSession) input.readObject();
    } catch (IOException | ClassNotFoundException ex) {
        throw new IllegalArgumentException("invalid session", ex);
    }
}
```

## Explanation

Java's `ObjectInputFilter` (JEP 290, introduced in Java 9) restricts deserialization to a whitelist of allowed classes. By calling `setObjectInputFilter()` with a filter pattern naming only `RestoredSession`, the stream rejects any attempt to instantiate other classes, blocking gadget chain exploitation. The filter pattern is processed per-stream after construction, blocking deserialization before any object code runs. This preserves the native serialization wire format (required for compatibility with existing serialized sessions) while closing the gadget chain vector.
