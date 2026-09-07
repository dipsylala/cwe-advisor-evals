## Verdict

Exploitable

## Source

JMS BytesMessage from partner integrations published through a B2B gateway. The message payload contains native Java-serialized OrderEvent objects. The source is untrusted external data from partners outside the application's control.

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

            // Attach an ObjectInputFilter allowlist before deserialization to restrict instantiable classes
            String filterPattern = "evalcases.OrderEvent;java.base/*;java.util.*;!*";
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(filterPattern);
            ois.setObjectInputFilter(filter);

            // CWE-502 FIXED: ObjectInputFilter restricts deserialization to allowed classes
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

The vulnerability occurs at line 33 where `ObjectInputStream.readObject()` deserializes untrusted data from external partner integrations without any class restrictions. An attacker controlling the serialized payload could craft a malicious object that instantiates arbitrary gadget chain classes during deserialization, leading to remote code execution.

The fix attaches an `ObjectInputFilter` allowlist to the `ObjectInputStream` before calling `readObject()`. The filter pattern `"evalcases.OrderEvent;java.base/*;java.util.*;!*"` restricts deserialization to:
- The `OrderEvent` class (the intended application class)
- All classes in `java.base` (primitive wrappers, strings, and core types)
- All classes in `java.util` (legitimate container types like ArrayList, HashMap)
- Rejects everything else with `!*`

This prevents gadget chain attacks by ensuring only known-safe classes can be instantiated during deserialization. The filter is applied per-stream using `ois.setObjectInputFilter()` before the first `readObject()` call, as required by the Java specification. Since the producer (partner integrations) cannot be changed to use JSON in this case, keeping native serialization with a filter is the appropriate defence-in-depth control.

## Behaviour changes

None. The filter maintains the same deserialization behavior for legitimate `OrderEvent` objects that match the allowlist, while preventing instantiation of arbitrary classes during untrusted deserialization. Valid application traffic is unaffected. Malformed or malicious payloads that attempt to deserialize non-allowed classes are rejected with an exception, which is caught by the existing try-catch block.
