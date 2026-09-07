## Verdict

Real issue. Untrusted serialized data from a B2B gateway is deserialized without class restriction, allowing arbitrary object instantiation and potential code execution via gadget chains.

## Source

JMS queue message from external B2B gateway partner, deserialized at line 33 without validation.

## Fix

Add an `ObjectInputFilter` allowlist before calling `readObject()`. The format cannot change (publishing side is external), so restrict what classes the existing deserializer may instantiate.

**Import to add:**
```
import java.io.ObjectInputFilter;
```

**Code change at line 30-33 (before readObject):**

Replace:
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
OrderEvent event = (OrderEvent) ois.readObject();
```

With:
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// Attach an allowlist filter to restrict deserialization to safe classes only
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    
    // Handle stream metadata and array-length checks (clazz is null)
    if (clazz == null) {
        return ObjectInputFilter.Status.UNDECIDED;
    }
    
    String className = clazz.getName();
    
    // Allow OrderEvent and common safe container classes
    if (className.equals("evalcases.OrderEvent") ||
        className.startsWith("java.util.") ||
        className.startsWith("java.lang.") ||
        className.startsWith("java.io.") ||
        clazz.isPrimitive() ||
        clazz.isArray()) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    return ObjectInputFilter.Status.REJECTED;
});

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
OrderEvent event = (OrderEvent) ois.readObject();
```

## Explanation

ObjectInputFilter (available from JDK 8u121+) intercepts every class during deserialization. The allowlist permits only OrderEvent, container classes (ArrayList, HashMap, etc.), and core Java types, rejecting any others. This blocks gadget-chain attacks that attempt to instantiate arbitrary classes during reconstruction.

The filter returns `UNDECIDED` when `clazz` is null (stream metadata) to allow the stream to proceed, and `REJECTED` for any class not in the allowlist. The filter is attached to the stream before `readObject()` and applies to that stream only—no process-wide impact.

The serialization format remains unchanged, preserving compatibility with the external B2B partner's serialized messages.

## Behaviour changes

**Normal path**: OrderEvent messages deserialize as before; only their class type is validated.

**Attack path blocked**: Any attempt to serialize a gadget class (e.g., Commons Collections exploits) is rejected during reconstruction, preventing code execution.

**Side effects**: If OrderEvent uses container types not in the allowlist (e.g., custom collections), deserialization fails with FilterInvoker exception. Verify the actual OrderEvent class includes only standard container types or add them to the allowlist.
