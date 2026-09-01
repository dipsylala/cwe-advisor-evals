## Verdict

Confirmed. The code deserializes untrusted data from a user-supplied Base64-encoded string without restricting which classes can be instantiated, enabling arbitrary code execution through a gadget chain during deserialization.

## Source

`SessionDecoder.decode()` at line 10 calls `ObjectInputStream.readObject()` on payload bytes derived directly from user input. The `ObjectInputStream` is created without any `ObjectInputFilter` to validate the classes being deserialized. An attacker can provide a malicious serialized object that includes a gadget chain to achieve remote code execution.

## Fix

Add an `ObjectInputFilter` when creating the `ObjectInputStream` to allowlist only safe classes. Update `SessionDecoder.java`:

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            input.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "cases.deserialize.RestoredSession;!*"
            ));
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

The filter pattern `"cases.deserialize.RestoredSession;!*"` explicitly allows only the `RestoredSession` class and rejects all other classes (the `!*` wildcard).

## Explanation

`ObjectInputStream.readObject()` deserializes an object graph from a byte stream. Without restrictions, it can instantiate any class on the classpath, including dangerous gadget classes from common libraries. During instantiation, attacker-controlled gadget objects can invoke arbitrary methods through `readObject()` or `readResolve()` hooks, leading to code execution.

The fix uses `ObjectInputFilter`, available since Java 9, to validate each class being deserialized against an allowlist. The filter is applied to the stream before calling `readObject()`, ensuring only the expected `RestoredSession` class (and the primitive types it contains) can be reconstructed. Any attempt to deserialize other classes is rejected with an exception, preventing gadget chain exploitation.

For Java 8 or earlier, use the global filter via system property or `ObjectInputFilter.Config.setObjectInputFilter()`, though per-stream filtering via `setObjectInputFilter()` is preferred for defense in depth.
