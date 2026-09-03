## Verdict

exploitable

## Source

The vulnerability originates in `SessionRestoreController.restore(String encodedSession)` where user-supplied `encodedSession` is Base64-decoded to a byte array that flows directly into the deserialization sink without validation.

## Fix

**Vulnerable Code (SessionDecoder.java, lines 8-14):**

```java
public RestoredSession decode(byte[] payload) {
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
        return (RestoredSession) input.readObject();  // CWE-502: No allowlist
    } catch (IOException | ClassNotFoundException ex) {
        throw new IllegalArgumentException("invalid session", ex);
    }
}
```

**Fixed Code:**

```java
public RestoredSession decode(byte[] payload) {
    try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload))) {
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "cases.deserialize.RestoredSession;java.lang.String;!*"
        );
        input.setObjectInputFilter(filter);
        return (RestoredSession) input.readObject();
    } catch (IOException | ClassNotFoundException ex) {
        throw new IllegalArgumentException("invalid session", ex);
    }
}
```

## Explanation

The fix adds an explicit class allowlist using `ObjectInputFilter` before deserializing untrusted session data. The filter pattern permits only `RestoredSession` and `String` classes, rejecting all others. This prevents attackers from supplying malicious serialized objects that could instantiate arbitrary classes and execute gadget-chain code during deserialization. The filter is attached per-stream with `setObjectInputFilter()` (not the process-wide `Config.setSerialFilter()`, which cannot be called in a handler), ensuring each deserialization request is independently validated. The allowlist must remain minimal and match only the legitimate message types this decoder expects; any legitimate container types the payload uses must also be explicitly listed.

## Behaviour changes

The filter will reject deserialization of any class not in the allowlist with an `InvalidClassException`, causing the catch block to rethrow as `IllegalArgumentException`. This is the intended security improvement: valid traffic deserializing only `RestoredSession` and `String` continues normally, while malicious payloads are rejected. No change to normal return values or exception semantics for legitimate input.
