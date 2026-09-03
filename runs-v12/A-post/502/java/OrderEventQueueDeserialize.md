## Verdict

VULNERABLE. Line 33 deserializes untrusted data from an external B2B gateway using `ObjectInputStream.readObject()` without any validation, allowing an attacker to instantiate arbitrary classes and potentially execute code through deserialization gadget chains.

## Source

The vulnerable code receives byte-serialized Java objects from partner integrations through a JMS queue. On line 33, `ois.readObject()` is called to deserialize the payload into an `OrderEvent` object without filtering which classes are permitted during deserialization.

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
OrderEvent event = (OrderEvent) ois.readObject();  // Line 33: CWE-502
```

The source of untrusted data is the JMS message body, which originates from external partner systems via a B2B gateway.

## Fix

Use `ObjectInputFilter` to restrict deserialization to only safe, expected classes. Set the filter on the `ObjectInputStream` to allow only `OrderEvent` and its required supporting classes:

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "maxbytes=10000;maxdepth=10;maxarraylength=1000;" +
    "allowlist=java.lang.Object," +
    "java.util.ArrayList,java.util.HashMap,java.util.HashSet," +
    "java.time.LocalDate,java.time.LocalDateTime," +
    "evalcases.OrderEvent"
));
OrderEvent event = (OrderEvent) ois.readObject();
```

For Java 8 compatibility, implement a custom deserialization check:

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload)) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        Set<String> allowedClasses = new HashSet<>(Arrays.asList(
            "evalcases.OrderEvent",
            "java.util.ArrayList",
            "java.util.HashMap"
            // Add other safe classes as needed
        ));
        if (!allowedClasses.contains(desc.getName())) {
            throw new InvalidClassException("Class not permitted: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
};
OrderEvent event = (OrderEvent) ois.readObject();
```

## Explanation

`ObjectInputStream.readObject()` instantiates any class found in the serialized stream, including classes from gadget chains that can execute arbitrary code during construction or field initialization. Since the data originates from an external B2B gateway, it cannot be trusted.

Using `ObjectInputFilter` (Java 9+) or a custom `resolveClass()` override (all versions) restricts which classes are permitted during deserialization. Only classes explicitly listed in the allowlist can be instantiated. The bytecode and depth limits (`maxbytes`, `maxdepth`, `maxarraylength`) add defense-in-depth against resource exhaustion.

This approach maintains compatibility with the existing serialized message format from partner integrations while eliminating the gadget chain attack vector.
