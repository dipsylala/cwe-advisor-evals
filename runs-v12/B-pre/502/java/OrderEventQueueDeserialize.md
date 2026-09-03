## Verdict

Exploitable. The code deserializes untrusted data from JMS messages published by partner integrations via a B2B gateway using Java's native `ObjectInputStream.readObject()`, which has no restrictions on which classes can be instantiated. This permits gadget chain attacks to execute arbitrary code.

## Source

Untrusted JMS `BytesMessage` objects published by partner integrations through the B2B gateway, received as the `message` parameter to `onMessage()` at line 22.

## Fix

**Vulnerable code:**
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
OrderEvent event = (OrderEvent) ois.readObject();
```

**Fixed code:**
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// Create an ObjectInputFilter to restrict deserialization to a safe set of classes,
// preventing gadget chain deserialization attacks.
ObjectInputFilter filter = info -> {
    String className = info.className();
    
    // Allow implicit class (null) for array sizing and stream constraints
    if (className == null) {
        return ObjectInputFilter.Status.UNDECIDED;
    }
    
    // Allowlist only the expected event class and safe container/primitive types
    if (className.equals("evalcases.OrderEvent") ||
        className.equals("java.util.ArrayList") ||
        className.equals("java.util.HashMap") ||
        className.equals("java.util.LinkedList") ||
        className.equals("[Ljava.lang.Object;") ||
        className.equals("java.lang.String") ||
        className.equals("java.lang.Integer") ||
        className.equals("java.lang.Long") ||
        className.equals("java.lang.Double") ||
        className.equals("java.lang.Boolean")) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    
    // Reject all other classes
    return ObjectInputFilter.Status.REJECTED;
};

ObjectInputFilter.Config.setSerialFilter(filter);

OrderEvent event = (OrderEvent) ois.readObject();
```

## Explanation

The fix adds an `ObjectInputFilter` that establishes an explicit allowlist of classes permitted during deserialization. The filter callback examines each class being deserialized and rejects any class not on the allowlist (OrderEvent, common Java container types like ArrayList and HashMap, and primitive wrapper types). The filter handles the implicit `null` class correctly, which is used by the serialization framework to communicate array sizing and stream constraints. By preventing instantiation of arbitrary classes, the fix closes the gadget chain attack vector that CWE-502 exploits. This approach preserves Java serialization (required because the publishing partner has not migrated to JSON) while enforcing type safety at the deserialization boundary. The guidance floor is Java 8u121 or later (when ObjectInputFilter was backported via JEP 290); older versions would require `ValidatingObjectInputStream` from Apache Commons IO instead.

## Behaviour changes

The filter adds a per-class validation check before each deserialization, incurring minimal memory and CPU overhead. The OrderEvent payload must now contain only classes in the allowlist; if the OrderEvent structure uses additional types not listed (custom nested objects, alternative collection types), those must be added to the allowlist to avoid deserialization rejection. The original code had no such restriction, so valid payloads containing unlisted types will now be rejected as a security boundary—this is an intentional trade-off that trades robustness for safety. Return type, arguments, and error behaviour remain unchanged.
