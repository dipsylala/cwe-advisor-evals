## Verdict

EXPLOITABLE

## Source

`encodedSession` parameter in `SessionRestoreController.restore()` (line 12) - untrusted input from external caller, Base64-decoded and passed to `SessionDecoder.decode()`

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
                "cases.deserialize.RestoredSession;java.lang.String;[L*;!*"
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

The original code deserializes untrusted serialized data with `ObjectInputStream.readObject()` without any class instantiation restrictions. An attacker can craft a malicious payload to instantiate arbitrary classes during deserialization, leading to gadget-chain code execution or denial of service attacks.

The fix attaches an `ObjectInputFilter` to the stream before any deserialization occurs. The filter uses a string-based allowlist pattern that explicitly permits only:
- `cases.deserialize.RestoredSession` - the expected session class
- `java.lang.String` - safe type for String fields in the record
- `[L*;` - object arrays that may appear during serialization
- `!*` - rejects all other classes

The filter is attached per-stream with `setObjectInputFilter(filter)` before the first `readObject()` call, preventing instantiation of any class not on the allowlist. This approach preserves the existing serialization format while eliminating the code execution risk, making it suitable when external producers cannot be changed to a safer format.

## Behaviour changes

The deserialization will now reject any serialized payload containing classes outside the allowlist, raising an exception if an attacker attempts to inject gadget classes. This is the intended security-hardening behaviour and does not affect legitimate sessions containing only the expected RestoredSession class and String values.
