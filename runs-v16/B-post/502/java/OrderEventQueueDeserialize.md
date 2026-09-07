## Verdict

exploitable

## Source

Untrusted serialized data received from a JMS message queue published by external partner integrations, deserialized via `ObjectInputStream.readObject()` on line 33 without validation or filtering. The absence of producer-side changes (stated in the code comment) makes a format migration infeasible; the fix must protect the consumer's deserialization boundary.

## Fix

**Vulnerable code (lines 30-33):**
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
OrderEvent event = (OrderEvent) ois.readObject();
```

**Fixed code:**
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// Attach an ObjectInputFilter to allowlist only safe, known classes
ObjectInputFilter filter = (info) -> {
    Class<?> clazz = info.serialClass();
    
    if (clazz == null) {
        // Allow array length and stream limit checks
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    // Allowlist OrderEvent and safe container/primitive types that may appear in the payload
    if (clazz == OrderEvent.class ||
        clazz == java.util.ArrayList.class ||
        clazz == java.util.HashMap.class ||
        clazz == java.util.LinkedList.class ||
        clazz == java.util.HashSet.class ||
        clazz == java.lang.String.class ||
        clazz == java.lang.Integer.class ||
        clazz == java.lang.Long.class ||
        clazz == java.lang.Double.class ||
        clazz == java.lang.Float.class ||
        clazz == java.lang.Boolean.class ||
        clazz.isArray()) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    // Reject all other classes
    return ObjectInputFilter.Status.REJECTED;
};

ois.setObjectInputFilter(filter);
OrderEvent event = (OrderEvent) ois.readObject();
```

**Required import to add:**
```java
import java.io.ObjectInputFilter;
```

## Explanation

The original code deserializes untrusted data from an external message queue without any validation, allowing an attacker to craft malicious serialized objects that exploit gadget chains or trigger arbitrary class instantiation. Because the producers (partner integrations) cannot be changed and still emit native Java serialization, switching to a safer format like JSON would silently reject all legitimate traffic — the guidance for CWE-502 Java specifies this is a breaking change and not the primary fix.

Instead, the fix attaches an `ObjectInputFilter` callback to the `ObjectInputStream` before the first `readObject()` call. The filter explicitly allowlists only the classes expected in legitimate payloads: `OrderEvent`, common safe container types (`ArrayList`, `HashMap`, etc.), primitive wrappers (`String`, `Integer`, `Long`, etc.), and arrays. Any attempt to deserialize an object of an unlisted class causes the filter to reject it, preventing gadget-chain exploitation. The `setObjectInputFilter()` call is per-stream (not the process-wide `Config.setSerialFilter()`, which throws on a second invocation), making it safe for a handler that may be called multiple times.

## Behaviour changes

- **Added filter instantiation and attachment**: The filter callback is created and attached before deserialization. Legitimate payloads containing only allowlisted types proceed unchanged. Payloads containing any non-allowlisted class are rejected with an exception (default `ObjectInputStream` behavior when a filter rejects).
- **New import**: `java.io.ObjectInputFilter` is added (standard library, available from Java 8u121 and later; 9 and later out of the box).
- **Possible new exception path**: If an external producer somehow sends a serialized object that references a non-allowlisted class (e.g., a custom helper class), the filter will reject it and raise an exception. This is intentional—it is the attack boundary—but requires verification that all allowlisted container types match what the actual `OrderEvent` implementation uses. If additional container types are needed, expand the filter's allowlist (e.g., `java.util.TreeMap`, `java.util.LinkedHashSet`, `java.util.Collections$UnmodifiableList`).
