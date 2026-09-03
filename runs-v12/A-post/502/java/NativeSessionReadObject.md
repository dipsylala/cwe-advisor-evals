## Verdict

**CWE-502 is present and remediated.**

The original code deserializes untrusted session data using `ObjectInputStream.readObject()` without validation, allowing arbitrary code execution via crafted serialized objects. The fix applies an object input filter to restrict deserialization to the safe `RestoredSession` class only.

## Source

**SessionDecoder.java, line 10:**

```java
return (RestoredSession) input.readObject();
```

The `readObject()` call processes untrusted data (the `payload` byte array) received via the `SessionRestoreController.restore()` method, which decodes a Base64-encoded session string. An attacker can craft a malicious serialized object to execute arbitrary code during deserialization.

## Fix

Replace the `SessionDecoder` class with an object input filter that restricts deserialization to `RestoredSession`:

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            input.setObjectInputFilter(ObjectInputFilter.Config.createFilter("cases.deserialize.RestoredSession"));
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation

Java's `ObjectInputFilter` (available since Java 9) restricts which classes can be deserialized from an input stream. By calling `setObjectInputFilter()` with a filter pattern that names only `RestoredSession`, the code ensures that only instances of that class—and no gadget chains or arbitrary objects—can be reconstructed from the serialized data.

The filter pattern `"cases.deserialize.RestoredSession"` explicitly allows deserialization of the `RestoredSession` record while rejecting all other classes, preventing exploitation of deserialization gadget chains that could lead to code execution.

