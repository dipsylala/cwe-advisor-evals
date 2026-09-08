## Verdict

CONFIRMED. The code deserializes untrusted data from a JMS queue without restricting which classes can be instantiated, allowing arbitrary object instantiation during deserialization.

## Source

The vulnerability is at line 33 where `ObjectInputStream.readObject()` is called on data from an external queue without an `ObjectInputFilter` to restrict deserialization to safe classes.

## Fix

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
            
            // Restrict deserialization to OrderEvent and Java standard classes only
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("evalcases.OrderEvent;java.**");
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

The fix applies an `ObjectInputFilter` to the `ObjectInputStream` before calling `readObject()`. The filter uses a pattern allowlist that permits only:

- `evalcases.OrderEvent` — the expected message class
- `java.**` — Java standard library classes that may be required for serialization infrastructure (String, ArrayList, etc.)

This prevents deserialization of arbitrary attacker-controlled classes while preserving the existing native serialization wire format that partner integrations depend on. The filter is set immediately after stream construction, before any data is read, so all deserialization goes through the restriction.

If deserialization attempts a forbidden class, the filter raises an exception, which is caught and wrapped by the existing exception handler.
