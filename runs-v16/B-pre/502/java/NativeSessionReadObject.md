## Verdict

Exploitable. The `ObjectInputStream.readObject()` at line 10 deserializes untrusted data (Base64-decoded from HTTP) without class filtering, enabling instantiation of arbitrary gadget classes during deserialization.

## Source

Entry point: `SessionRestoreController.restore(String encodedSession)` receives untrusted Base64-encoded session string from HTTP request parameter. Flow: Base64 decode → `SessionDecoder.decode(byte[])` → `ObjectInputStream.readObject()`.

## Fix

**Vulnerable Code:**

```java
public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            return (RestoredSession) input.readObject();  // Line 10: No class validation
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Fixed Code:**

```java
import java.io.ObjectInputFilter;

public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "cases.deserialize.RestoredSession;java.base/*;!*"
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

The fix attaches an `ObjectInputFilter` allowlist to the stream before deserialization. The filter pattern `cases.deserialize.RestoredSession;java.base/*;!*` allows only the expected `RestoredSession` class and safe base Java classes (String, primitives, standard containers), then rejects all other classes with `!*`. This prevents gadget-chain attacks while preserving the intended functionality: legitimate serialized RestoredSession objects deserialize normally, while payloads attempting to instantiate gadget classes are rejected at the stream level. The filter is attached per-stream with `setObjectInputFilter()` before `readObject()` per JDK 8u121+.

## Behaviour changes

None. The filter validates during deserialization and either allows the expected object type to construct (returning the same result as before) or rejects and raises an exception (improving security). Exception handling remains identical—filter rejections typically surface as `IOException` or variants caught by the existing `IOException` handler. The method signature, return type, and legitimate session restoration path are unchanged.
