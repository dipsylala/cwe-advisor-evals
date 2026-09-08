## Verdict
Confirmed. `SessionDecoder.decode()` calls `ObjectInputStream.readObject()` on a byte array that originates from `SessionRestoreController.restore()`, which Base64-decodes an externally supplied `encodedSession` string with no restriction on what classes may be instantiated during deserialization. An attacker who controls `encodedSession` can supply a serialized gadget-chain payload instead of a `RestoredSession`, and `readObject()` will instantiate and initialize arbitrary classes present on the classpath before the code ever gets a chance to validate the result, enabling remote code execution.

## Source
`SessionRestoreController.restore(String encodedSession)` - the `encodedSession` parameter is attacker-controlled input (session data submitted by a client), Base64-decoded and passed as `payload` into `SessionDecoder.decode(byte[] payload)`, which reaches the sink at `SessionDecoder.java:10`, `input.readObject()`.

## Fix

### File: SessionDecoder.java
```java
package cases.deserialize;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class SessionDecoder {

    private static final ObjectInputFilter SESSION_FILTER = ObjectInputFilter.Config.createFilter(
        "maxdepth=5;maxarray=100;maxrefs=50;maxbytes=100000;"
            + "cases.deserialize.RestoredSession;java.lang.String;!*"
    );

    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            input.setObjectInputFilter(SESSION_FILTER);
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation
The wire format and API stay native Java serialization, since `SessionRestoreController` and whatever produced the original `encodedSession` payload both already speak that format and nothing in this diff can migrate every producer to a different one. The fix instead constrains what `ObjectInputStream` is willing to construct.

`ObjectInputFilter.Config.createFilter()` builds a pattern-based filter that is installed on the stream via `setObjectInputFilter()` before `readObject()` runs. The pattern is evaluated left to right: it allows only `cases.deserialize.RestoredSession` and `java.lang.String` (the two class types actually needed to reconstruct the record), and `!*` rejects every other class by default - so a gadget-chain payload built from any other class on the classpath is rejected during resolution, before the attacker's class is ever instantiated, and `readObject()` throws `InvalidClassException`, which is caught by the existing `catch (IOException | ClassNotFoundException ex)` block (`InvalidClassException` extends `ObjectStreamException`, a subclass of `IOException`) and surfaces as the existing `IllegalArgumentException("invalid session", ex)`. The `maxdepth`, `maxarray`, `maxrefs`, and `maxbytes` limits additionally bound object-graph depth, array size, back-reference count, and stream size, closing off denial-of-service payloads (e.g. deeply nested or huge arrays) that stay within the allowed classes.

This preserves the existing method signature, return type, and exception contract, so `SessionRestoreController` requires no change. Verify by decoding a legitimately-produced `RestoredSession` payload (still succeeds) and by decoding a payload built from any other serializable class, such as `java.util.HashMap` or a known gadget type (now throws `IllegalArgumentException` instead of instantiating it).
