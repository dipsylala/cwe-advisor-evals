## Verdict

Exploitable. The `ObjectInputStream.readObject()` call at line 33 deserializes untrusted data from a message queue without validation. A malicious serialized object crafted by an attacker can trigger gadget chains to execute arbitrary code during deserialization.

## Source

The `message` parameter received by `onMessage()` comes from an untrusted JMS message queue publisher ("partner integrations through a B2B gateway"). The message body is extracted as raw bytes and passed directly to ObjectInputStream without integrity validation or class restrictions.

## Fix

Replace lines 30-33 with:

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// Attach an ObjectInputFilter allowlist before deserialization
ObjectInputFilter filter = info -> {
    if (info.serialClass() != null) {
        Class<?> clazz = info.serialClass();
        // Allow only OrderEvent and safe collection/primitive wrapper types
        if (clazz == OrderEvent.class ||
            clazz == java.util.ArrayList.class ||
            clazz == java.util.HashMap.class ||
            clazz == java.util.HashSet.class ||
            clazz == java.util.LinkedList.class ||
            clazz == String.class ||
            clazz == Integer.class ||
            clazz == Long.class ||
            clazz == Double.class ||
            clazz == Float.class ||
            clazz == Boolean.class ||
            clazz == Byte.class ||
            clazz.isArray()) {  // Allow array types needed for collections
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    }
    // For stream metadata (array length, depth limits) return UNDECIDED
    return ObjectInputFilter.Status.UNDECIDED;
};

ois.setObjectInputFilter(filter);
OrderEvent event = (OrderEvent) ois.readObject();
```

## Explanation

Java's `ObjectInputStream` can instantiate arbitrary classes during deserialization, enabling attackers to trigger gadget chains from libraries on the classpath. The `ObjectInputFilter` API (available since Java 8u121) restricts object reconstruction to an explicit allowlist of safe classes. By attaching the filter to the stream before any `readObject()` call and allowing only `OrderEvent` plus common collection and wrapper types that `OrderEvent` may legitimately contain, the fix eliminates the gadget chain attack surface while preserving legitimate message processing. The filter returns `UNDECIDED` for stream metadata (non-class info) to let deserialization continue for valid messages. Array types are permitted because collections use object arrays internally.

## Behaviour changes

- Malicious serialized objects attempting to instantiate classes not on the allowlist are rejected, raising an exception during `readObject()`.
- The existing exception handler catches and wraps this as a RuntimeException, so error handling behavior is preserved.
- Legitimate OrderEvent messages containing only allowed types continue to deserialize successfully.
- If OrderEvent contains fields of types not in the allowlist, those messages will fail deserialization; the allowlist must be extended to include all types that legitimate OrderEvent instances contain (additional collection types, custom inner classes, etc.). Audit a sample of real messages to confirm the allowlist is complete.
