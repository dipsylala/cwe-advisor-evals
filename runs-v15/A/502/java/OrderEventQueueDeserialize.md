## Verdict
Confirmed CWE-502: Unsafe deserialization via `ObjectInputStream.readObject()` on untrusted message data without input filtering.

## Source
The vulnerability is at line 33 in `OrderEventQueueDeserialize.java`:
```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
OrderEvent event = (OrderEvent) ois.readObject();
```

An `ObjectInputStream` without an `ObjectInputFilter` can deserialize arbitrary Java objects, enabling gadget chain attacks when processing messages from partner integrations through the B2B gateway.

## Fix
Add an `ObjectInputFilter` to restrict deserialization to only the `OrderEvent` class and safe Java types:

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("evalcases.OrderEvent;java.lang.*;java.util.*;!*"));
OrderEvent event = (OrderEvent) ois.readObject();
```

The filter pattern:
- `evalcases.OrderEvent` — allows the application's OrderEvent class
- `java.lang.*` — allows safe primitive wrapper types and common classes
- `java.util.*` — allows standard collection classes if used within OrderEvent
- `!*` — rejects everything else by default

Adjust the allowlist to match the actual class hierarchy used in OrderEvent fields. Use `maxbytes` and `maxdepth` parameters to constrain resource consumption if needed:
```java
ois.setObjectInputFilter(
    ObjectInputFilter.Config.createFilter(
        "evalcases.OrderEvent;java.lang.*;java.util.*;maxbytes=1000000;maxdepth=20;!*"
    )
);
```

## Explanation
The code processes untrusted JMS message data from external partners. While the protocol cannot change (partners still send native Java serialization), an `ObjectInputFilter` prevents deserialization of gadget chain classes without changing the wire format or breaking compatibility.

`ObjectInputFilter` (Java 9+) is the standard defense: it validates each class before instantiation during deserialization, rejecting malicious objects while allowing legitimate OrderEvent instances. The filter is stateless per stream and does not require changes to the producer side or the serialized format.

This fix follows the OWASP and OpenJDK guidance for safe deserialization: keep the format, disable unsafe object construction in the decoder.
