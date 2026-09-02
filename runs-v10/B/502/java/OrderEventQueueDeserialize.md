## Verdict

Exploitable: Untrusted JMS messages are deserialized without class allowlisting, permitting arbitrary code execution through gadget chains.

## Source

`BytesMessage message` parameter in `onMessage()` receives untrusted data from a B2B gateway partner integration queue. The byte payload is extracted and passed directly to `ObjectInputStream.readObject()` with no integrity verification or class restrictions.

## Fix

Replace the `ObjectInputStream` deserialization with an `ObjectInputFilter` that allowlists only known-safe classes:

```java
@Override
public void onMessage(Message message)
{
    try
    {
        BytesMessage bytesMessage = (BytesMessage) message;
        byte[] payload = new byte[(int) bytesMessage.getBodyLength()];
        bytesMessage.readBytes(payload);

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        
        // Allowlist classes permitted for deserialization
        ObjectInputFilter filter = new ObjectInputFilter() {
            @Override
            public Status checkInput(FilterInformation filterInfo) {
                Class<?> clazz = filterInfo.serialClass();
                
                // Null class signals array length, depth, or stream size limits
                if (clazz == null) {
                    return Status.UNDECIDED;
                }
                
                // Allow only OrderEvent and safe container types
                if (clazz == OrderEvent.class ||
                    clazz == ArrayList.class ||
                    clazz == HashMap.class ||
                    clazz == String.class ||
                    clazz.isPrimitive() ||
                    clazz.isArray()) {
                    return Status.ALLOWED;
                }
                
                // Reject all other classes
                return Status.REJECTED;
            }
        };
        
        ObjectInputStream.setObjectInputFilter(ois, filter);

        OrderEvent event = (OrderEvent) ois.readObject();

        processor.handle(event);
    }
    catch (Exception e)
    {
        throw new RuntimeException("Failed to process order event", e);
    }
}
```

Required imports:
```java
import java.io.ObjectInputFilter;
```

## Explanation

The fix adds a class-level allowlist using `ObjectInputFilter` (available in JDK 8u121+ via JEP 290 backport). The filter's `checkInput()` callback intercepts every class instantiation attempt during deserialization and allows only `OrderEvent` and necessary container types (`ArrayList`, `HashMap`, `String`, primitives, and arrays). Any attempt to instantiate an unlisted class—including gadget-chain attack vectors—is rejected before object construction occurs.

The container types are included to support OrderEvent fields that may use common collection types. If OrderEvent uses different container types, add them to the allowlist. The `clazz == null` case handles stream metadata (array length limits, depth limits, stream size) which must return `UNDECIDED` rather than rejecting, per JEP 290 semantics.

## Behaviour changes

- Deserialization now rejects any class not in the allowlist, including any gadget-chain exploit payload
- Valid OrderEvent messages from the B2B gateway continue to deserialize normally
- Malformed or attack payloads that reference unlisted classes throw an exception during `readObject()` instead of instantiating dangerous objects
- No change to the public API or return types; error handling remains the same
