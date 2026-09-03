## Verdict
Confirmed. The code deserializes untrusted data without validation, allowing an attacker to instantiate arbitrary classes through gadget chain exploitation.

## Source
`SessionDecoder.java` line 10: `return (RestoredSession) input.readObject();`

The `payload` parameter originates from Base64-decoded user input (via `SessionRestoreController.restore()`), which is completely untrusted. Calling `readObject()` on an `ObjectInputStream` without an input filter permits deserialization of any class available on the classpath, enabling arbitrary code execution.

## Fix
Add an `ObjectInputFilter` to restrict which classes can be deserialized:

```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            // Set a filter to restrict deserialization to safe classes only
            input.setObjectInputFilter(filterInfo -> {
                Class<?> clazz = filterInfo.resolvedClass();
                
                // Allow only RestoredSession and essential Java base classes
                if (clazz == null) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                
                if (clazz == RestoredSession.class ||
                    clazz == String.class) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                
                // Reject any other class
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
The fix uses `ObjectInputStream.setObjectInputFilter()` (available since Java 9) to implement a whitelist-based validation. The filter inspects each class before deserialization:

- If the class is `RestoredSession` (the only expected type) or `String` (which may be used in record fields), it is allowed.
- Any other class is rejected, blocking gadget chain attacks that rely on deserializing dangerous library classes like those in commons-collections.
- The filter runs before object instantiation, preventing exploitation even if hostile code reaches the classpath.

This approach is the standard defense for untrusted deserialization in Java and requires no external dependencies.
