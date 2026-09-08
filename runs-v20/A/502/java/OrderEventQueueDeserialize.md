## Verdict

Confirmed. `onMessage` builds an `ObjectInputStream` directly over the raw JMS message body and calls `readObject()` with no filter in place. The queue is fed by external B2B partner integrations through a gateway, so the byte payload is attacker-influenceable network input; native Java deserialization of it can be driven through arbitrary classes on the classpath to build a gadget chain before the code ever gets to cast the result to `OrderEvent`, giving an attacker code execution or denial of service purely by placing a crafted message on the queue.

## Source

`javax.jms.BytesMessage` payload read via `bytesMessage.readBytes(payload)` in `OrderEventQueueDeserialize.onMessage` (`OrderEventQueueDeserialize.java:27-28`) — bytes originate from partner-published queue messages, i.e. untrusted network input.

## Fix

The publishing side is explicitly out of scope and still emits native Java-serialized `OrderEvent` bodies, so the wire format has to stay `ObjectInputStream`-based; the fix is to constrain what that stream is allowed to construct rather than to swap formats. `ObjectInputStream.setObjectInputFilter` (Java 9+, `java.io.ObjectInputFilter`) lets the stream reject any class outside an explicit allowlist before it is instantiated, closing the gadget-chain path while leaving the legitimate `OrderEvent` payload readable unchanged.

### File: OrderEventQueueDeserialize.java
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
            // Restrict the stream to the expected message type (plus core JDK
            // classes it is built from, e.g. String, boxed numbers, collections)
            // and reject everything else, so a crafted payload cannot drive
            // construction of an unrelated gadget class.
            ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "evalcases.OrderEvent;java.base/*;!*"));

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

`ObjectInputFilter.Config.createFilter` builds a filter from a semicolon-separated pattern list evaluated left to right, first match wins: `evalcases.OrderEvent` explicitly permits the expected message class, `java.base/*` permits the JDK core classes (`String`, boxed primitives, arrays, standard collections) that `OrderEvent`'s fields are typically built from, and the trailing `!*` rejects any class that reaches neither preceding pattern. The filter is installed on the stream with `setObjectInputStream.setObjectInputFilter(...)` before `readObject()` is called, so the JVM checks every class in the incoming object graph against it during deserialization and throws `InvalidClassException` the moment a disallowed class is encountered, before that class's constructor or `readObject`/`readResolve` logic can run - which is what a gadget chain depends on. Because `OrderEvent` itself is still allowed, legitimate partner-published messages deserialize exactly as before; only object graphs built from classes outside the allowlist are refused. If `OrderEvent` has fields typed to other in-repo classes, add each such class (or its package) to the pattern list; if the object graph needs classes from a specific third-party library, add that library's package explicitly rather than widening `java.base/*` or dropping the trailing `!*`.
