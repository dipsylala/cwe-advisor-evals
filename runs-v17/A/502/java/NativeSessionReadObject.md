## Verdict
Confirmed CWE-502 vulnerability. The `SessionDecoder.decode()` method deserializes untrusted user-supplied data without validation, allowing gadget-chain attacks that execute arbitrary code at deserialization time.

## Source
The vulnerability is in `SessionDecoder.java` line 10, where `ObjectInputStream.readObject()` is called on a payload derived entirely from user input (Base64-decoded in `SessionRestoreController`). The absence of an ObjectInputFilter allows instantiation of any serializable class on the classpath during deserialization.

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
                "cases.deserialize.RestoredSession;java.lang.String"
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
The fix adds an `ObjectInputFilter` that whitelists only the classes required for deserializing a valid `RestoredSession` object: the `RestoredSession` class itself and `String` (for its two fields). When `readObject()` attempts to instantiate any other class during deserialization, the filter rejects it and throws an exception, preventing gadget-chain attacks.

The filter is set immediately after creating the `ObjectInputStream` and before calling `readObject()`, ensuring all deserialization is protected. The filter pattern uses a semicolon-separated list of fully qualified class names; Java's serialization infrastructure will reject any attempt to deserialize classes not in this whitelist, blocking exploitation even if untrusted data reaches the stream.
