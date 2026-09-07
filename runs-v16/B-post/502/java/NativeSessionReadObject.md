## Verdict
exploitable

## Source
`encodedSession` (String parameter) in `SessionRestoreController.restore()`, which is attacker-controlled untrusted input from an external caller

## Fix

**Vulnerable code:**
```java
public class SessionDecoder {
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            return (RestoredSession) input.readObject();  // Line 10: no validation before deserialization
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

**Fixed code:**
```java
public class SessionDecoder {
    private static final ObjectInputFilter ALLOWLIST = ObjectInputFilter.Config.createFilter(
        "cases.deserialize.RestoredSession;java.base/*;!*"
    );
    
    public RestoredSession decode(byte[] payload) {
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
            input.setObjectInputFilter(ALLOWLIST);
            return (RestoredSession) input.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw new IllegalArgumentException("invalid session", ex);
        }
    }
}
```

## Explanation

The fix adds an ObjectInputFilter allowlist that restricts deserialization to safe classes only. The filter pattern `cases.deserialize.RestoredSession;java.base/*;!*` allows the expected `RestoredSession` class and standard library classes from `java.base`, then rejects all other classes with `!*`. This prevents gadget-chain attacks where a malicious serialized object could cause arbitrary code execution by requesting instantiation of dangerous library classes during deserialization. The filter is attached to the ObjectInputStream with `setObjectInputFilter()` before any `readObject()` call, which is the required attachment point per stream.

## Behaviour changes

None. The fix preserves the existing contract: it still deserializes a single RestoredSession object from the payload and returns it, still throws the same exception types, and does not alter the caller's behavior. The filter silently rejects invalid serialized data by throwing an exception during `readObject()`, which matches the current error handling path.
