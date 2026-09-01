## Verdict

Exploitable. Untrusted serialized data from a JMS message is deserialized without validation or type restrictions, allowing an attacker to instantiate arbitrary classes and execute code during object reconstruction.

## Source

JMS BytesMessage payload from a B2B gateway partner integration (upstream source remains Java-serialized). Data enters through `MessageListener.onMessage()` parameter, passes through BytesMessage cast and byte extraction, and reaches ObjectInputStream without integrity verification or allowlisting.

## Fix

Replace `ObjectInputStream.readObject()` with an `ObjectInputFilter` that explicitly allowlists only the classes permitted to be deserialized. Since the upstream publisher ships Java serialization and cannot be modified immediately, use a type-based allowlist rather than switching to JSON.

```java
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;
import javax.jms.BytesMessage;
import javax.jms.Message;
import javax.jms.MessageListener;

public class OrderEventQueueDeserialize implements MessageListener
{
    private final OrderProcessor processor;
    
    // Allowlist for deserialization - permits OrderEvent and minimal container types
    private static final ObjectInputFilter OBJECT_INPUT_FILTER =
        ObjectInputFilter.merge(
            ObjectInputFilter.allowFilter(
                "evalcases.OrderEvent",
                "java.lang.String",
                "java.util.ArrayList",
                "java.util.HashMap",
                "[Ljava.lang.Object;",
                "[Ljava.lang.String;"
            ),
            ObjectInputFilter.rejectUndecidedClass()
        );

    public OrderEventQueueDeserialize(OrderProcessor processor)
    {
        this.processor = processor;
    }

    @Override
    public void onMessage(Message message)
    {
        try
        {
            BytesMessage bytesMessage = (BytesMessage) message;
            byte[] payload = new byte[(int) bytesMessage.getBodyLength()];
            bytesMessage.readBytes(payload);

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
            ois.setObjectInputFilter(OBJECT_INPUT_FILTER);

            OrderEvent event = (OrderEvent) ois.readObject();

            processor.handle(event);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to process order event", e);
        }
    }
}
```

## Explanation

The fix introduces an `ObjectInputFilter` that explicitly allows only `OrderEvent` and the minimal set of container types (`ArrayList`, `HashMap`, `String`, primitive arrays) that OrderEvent may contain. When `readObject()` attempts to deserialize, any class outside this allowlist is rejected before instantiation, preventing gadget-chain attacks and arbitrary code execution.

`ObjectInputFilter.allowFilter()` is available from JDK 8u121 and later (when JEP 290 was backported). The filter is configured statically to minimize overhead and consistency. `rejectUndecidedClass()` ensures any class the filter cannot recognize is rejected rather than allowed by default.

The upstream publisher's Java serialization format remains supported without modification, and the integrity of the OrderEvent contract—its type, fields, and processor handling—is preserved.

## Behaviour changes

**What changes:**
- Deserialization now rejects any class not explicitly in the allowlist, including gadget chains and unexpected types.

**What stays the same:**
- OrderEvent objects are deserialized and processed identically to before.
- The method signature, exception contract, and processor.handle() call remain unchanged.
- BytesMessage extraction and stream wrapping are unmodified.

**Testing:**
- Verify that valid OrderEvent objects from the publisher are still accepted.
- Confirm that attempted injection of unauthorized classes (e.g., gadget chains, unexpected types) is rejected and logged.
- Check that exceptions during deserialization still route through the catch block as before.
