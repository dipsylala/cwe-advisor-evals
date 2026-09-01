## Verdict

Real issue. Untrusted serialized data from external message queue is deserialized without any validation, allowing remote code execution via gadget chain attacks.

## Source

Line 33: `OrderEvent event = (OrderEvent) ois.readObject();`

The `ObjectInputStream` reads and deserializes arbitrary classes from untrusted message queue data published by "partner integrations through a B2B gateway". No deserialization filter is applied to restrict which classes may be instantiated.

## Fix

Apply `ObjectInputFilter` with a whitelist to the `ObjectInputStream` before calling `readObject()`. Only permit classes necessary for the `OrderEvent` deserialization:

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "java.lang.*;java.util.*;evalcases.OrderEvent"
));
OrderEvent event = (OrderEvent) ois.readObject();
```

Replace `evalcases.OrderEvent` and `java.util.*` with the actual packages containing the classes your `OrderEvent` type and its transitive dependencies require. Use fully qualified class names or package patterns; the filter rejects any class not in the whitelist.

## Explanation

`ObjectInputStream.readObject()` instantiates classes during deserialization based on data in the byte stream. An attacker controlling the serialized payload can specify gadget classes from the classpath to trigger code execution chains, even if those classes were not intended to be deserialized by the application.

`ObjectInputFilter`, available since Java 9, restricts which classes the stream is permitted to deserialize. When a disallowed class appears in the serialized data, the filter raises an exception before the class is instantiated, blocking the attack. Whitelist filters—permitting only known-safe classes—are more secure than blacklist approaches because they fail closed: only explicitly approved classes deserialize, not "anything except known bad classes."

The comment indicates the message payload must remain in native Java-serialized format because the publishing partner has not migrated. Until both sides can coordinate a safer format (JSON, Protocol Buffers), the filter mitigates the risk of gadget-chain instantiation while preserving compatibility.
