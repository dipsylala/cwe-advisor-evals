## Verdict
Confirmed. `onMessage` deserializes an untrusted, network-delivered byte payload with a bare `ObjectInputStream.readObject()` call and no class filter, allowing a crafted JMS message body to trigger arbitrary gadget-chain execution during deserialization.

## Source
`BytesMessage` payload read from the queue at line 27-28 (`bytesMessage.readBytes(payload)`). The message body originates from partner B2B gateway integrations outside this application's trust boundary, so `payload` is attacker-influenceable input.

## Fix
```java
package evalcases;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.jms.BytesMessage;
import javax.jms.Message;
import javax.jms.MessageListener;

public class OrderEventQueueDeserialize implements MessageListener
{
    // Allowlist: only the expected order-event graph may be materialized.
    // Reject everything else, cap object graph depth/breadth/size to blunt
    // resource-exhaustion payloads even for allowed classes.
    private static final ObjectInputFilter ORDER_EVENT_FILTER =
        ObjectInputFilter.Config.createFilter(
            "evalcases.OrderEvent;"
            + "evalcases.OrderEvent$*;"
            + "java.lang.String;java.lang.Number;java.lang.Integer;java.lang.Long;"
            + "java.math.BigDecimal;java.time.Instant;"
            + "maxdepth=5;maxarray=1000;maxrefs=1000;maxbytes=1000000;!*");

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
        catch (Exception e)
        {
            throw new RuntimeException("Failed to process order event", e);
        }
    }
}
```

## Explanation
The publishing side is out of scope and still ships native Java serialization, so the sink cannot be replaced with a non-Java format (e.g. JSON) in this change; the mitigation is to constrain what `ObjectInputStream` is willing to instantiate. `ObjectInputFilter` (JEP 290, standard since Java 9) is installed on the stream via `setObjectInputFilter` before `readObject()` runs, so every class encountered during the entire object graph resolution — not just the top-level cast target — is checked against the filter before the JVM instantiates it. The filter pattern is an explicit allowlist: it names `OrderEvent` (plus any nested/inner classes it may serialize) and the specific value types it legitimately carries, then `!*` rejects every other class by class name before any of its bytecode-defined `readObject`/`readResolve`/finalizer logic can run — this is what stops known gadget chains (`InvocationHandler` proxies, collection/Set gadgets, template classes, etc.), since none of those classes are on the allowlist. The `maxdepth`, `maxarray`, `maxrefs`, and `maxbytes` limits are a defense-in-depth backstop against billion-laughs-style object graphs or oversized arrays that could exhaust memory/CPU even if an attacker somehow crafted a payload built only from allowlisted types. A filter rejection makes `readObject()` throw `InvalidClassException`, which is already caught by the existing broad `catch (Exception e)` and surfaced as a `RuntimeException`, so no additional error-handling path is needed. If `OrderEvent`'s field set changes over time, the allowlist's type list must be kept in sync; consider centralizing it as a constant shared with any other listener on the same queue rather than duplicating the pattern string.
