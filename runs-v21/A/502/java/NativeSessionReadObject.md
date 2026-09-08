## Verdict
CONFIRMED: CWE-502 Deserialization of Untrusted Data on line 10 of SessionDecoder.java

## Source
The vulnerability occurs in `SessionDecoder.decode()` when deserializing untrusted session data using `ObjectInputStream.readObject()` without an `ObjectInputFilter`. An attacker can craft a malicious serialized object that executes arbitrary code during deserialization.

Data flow: The `restore()` method in SessionRestoreController receives Base64-encoded user input, decodes it, and passes it to `SessionDecoder.decode()`, which directly deserializes it to a RestoredSession object.

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
            input.setObjectInputFilter(info -> {
                if (info.getClassName().equals("cases.deserialize.RestoredSession")) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                return ObjectInputFilter.Status.REJECTED;
            });
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation
The fix introduces an `ObjectInputFilter` that restricts deserialization to only the `RestoredSession` class. Before `readObject()` is called, the filter checks the class name against a whitelist of allowed classes. Any attempt to deserialize a different class (including gadget chains used for remote code execution) is rejected.

The filter returns `ALLOWED` only for `RestoredSession` and `REJECTED` for all other classes, preventing deserialization of untrusted object types. This is the standard Java CWE-502 mitigation starting with Java 9.
