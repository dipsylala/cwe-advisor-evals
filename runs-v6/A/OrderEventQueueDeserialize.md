## Verdict

Confirmed. `onMessage` reads a JMS `BytesMessage` body that originates from an external B2B partner gateway over the network, then feeds those attacker-influenced bytes directly into `ObjectInputStream.readObject()` with no class or content restriction. Native Java deserialization walks arbitrary classes on the classpath during `readObject`, so a crafted payload (a standard ysoserial-style gadget chain, if any suitable gadget class is present on the classpath) can trigger remote code execution, denial of service, or other side effects before the cast to `OrderEvent` ever runs. This is CWE-502.

## Source

`javax.jms.BytesMessage` payload delivered to `onMessage(Message message)` (`OrderEventQueueDeserialize.java:26-28`) — a message published onto the queue by an external partner integration through a B2B gateway, i.e. untrusted network input.

## Fix

```java
package evalcases;

import java.io.ByteArrayInputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;
import javax.jms.BytesMessage;
import javax.jms.Message;
import javax.jms.MessageListener;

public class OrderEventQueueDeserialize implements MessageListener
{
    // Only OrderEvent (and JDK types it legitimately needs, e.g. arrays/String/
    // enums it declares) may be materialized. Everything else is rejected before
    // any gadget class can be instantiated, and depth/array/reference limits
    // bound the resource cost of a hostile payload.
    private static final ObjectInputFilter ORDER_EVENT_FILTER =
        ObjectInputFilter.Config.createFilter(
            "evalcases.OrderEvent;java.lang.*;java.util.*;maxdepth=5;maxarray=10000;maxrefs=1000;!*");

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
            ois.setObjectInputFilter(ORDER_EVENT_FILTER);

            OrderEvent event = (OrderEvent) ois.readObject();

            processor.handle(event);
        }
        catch (InvalidClassException e)
        {
            // Rejected by the filter: a payload attempted to deserialize a
            // class outside the OrderEvent allowlist.
            throw new RuntimeException("Rejected untrusted order event payload", e);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to process order event", e);
        }
    }
}
```

## Explanation

The publishing side is out of scope and still ships native Java serialization, so the receiving side cannot simply switch to a safe wire format such as JSON — the fix has to constrain the existing `ObjectInputStream` rather than replace it. `ObjectInputFilter` (JEP 290, standard since Java 9) is installed with `setObjectInputFilter` immediately after the stream is constructed and before `readObject()` is called, so every class the stream would otherwise resolve is checked first. The filter pattern is a positive allowlist — `evalcases.OrderEvent` plus the narrow set of JDK types the class legitimately needs — terminated with `!*`, which rejects any class not explicitly permitted. This means a gadget-chain class (e.g. from a library on the classpath used for some unrelated purpose) can never be instantiated: the filter throws `InvalidClassException` the moment such a class is encountered, well before any of its `readObject`/`readResolve`/constructor logic runs. The `maxdepth`, `maxarray`, and `maxrefs` entries additionally bound object-graph depth, array size, and back-reference count, which blocks resource-exhaustion payloads (e.g. deeply nested or huge arrays) that a class-only allowlist would not catch. `InvalidClassException` is caught separately purely to make a filter rejection observable/loggable as a distinct failure mode from other deserialization errors; the broad `catch (Exception e)` below it preserves the original behavior for all other failures. If `OrderEvent` is later extended to reference additional types (e.g. a nested value object or enum), those classes must be added to the allowlist pattern or deserialization will start failing closed, which is the intended behavior for any class not anticipated by the filter.
