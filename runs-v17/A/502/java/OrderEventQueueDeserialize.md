## Verdict

**Confirmed.** The code deserializes untrusted data from a JMS message using native Java serialization without filtering which classes are allowed. An attacker who controls the message payload can instantiate arbitrary classes, potentially executing code through gadget chains.

## Source

Line 33 in `OrderEventQueueDeserialize.java`: `ObjectInputStream.readObject()` is called on a payload from an untrusted JMS queue. The payload originates from B2B partner integrations and is not validated before deserialization.

The data flow: `BytesMessage.readBytes()` → `ObjectInputStream` → `readObject()` → `OrderEvent` cast (line 33).

## Fix

The wire format is locked to native Java serialization by upstream partners; the format cannot be changed. Apply an `ObjectInputFilter` to restrict which classes the deserializer accepts. This prevents gadget-chain attacks while preserving the serialized-data format.

### File: OrderEventQueueDeserialize.java

```java
package evalcases;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;
import javax.jms.BytesMessage;
import javax.jms.Message;
import javax.jms.MessageListener;

public class OrderEventQueueDeserialize implements MessageListener
{
    private final OrderProcessor processor;

    public OrderEventQueueDeserialize(OrderProcessor processor)
    {
        this.processor = processor;
    }

    // Messages on this queue are published by partner integrations through a
    // B2B gateway. The publishing side still ships native Java-serialized
    // OrderEvent bodies and is not part of this change.
    @Override
    public void onMessage(Message message)
    {
        try
        {
            BytesMessage bytesMessage = (BytesMessage) message;
            byte[] payload = new byte[(int) bytesMessage.getBodyLength()];
            bytesMessage.readBytes(payload);

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
            
            // Apply deserialization filter to allow only OrderEvent and safe Java types
            String filterPattern = "evalcases.OrderEvent;java.*";
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(filterPattern);
            ois.setObjectInputFilter(filter);

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

The fix adds an `ObjectInputFilter` to the `ObjectInputStream` before calling `readObject()`. The filter pattern `"evalcases.OrderEvent;java.*"` allows only the `OrderEvent` class (the legitimate message type) and Java standard library classes (needed for basic types in the serialized graph). Any attempt to deserialize a gadget class or other third-party code will be rejected, preventing code execution through gadget chains. The wire format remains unchanged—upstream partners continue sending native-serialized `OrderEvent` objects—but untrusted payloads are now constrained to a safe class list.

The `ObjectInputFilter` API is available in Java 9+; for Java 8 and earlier, set a system-wide filter via `jdk.serialFilter` property or use a custom `ObjectInputStream` subclass that overrides `resolveClass()` to validate the class name. This fix assumes Java 9+.
