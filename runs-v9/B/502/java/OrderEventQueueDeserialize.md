## Verdict

Exploitable. `onMessage` deserializes the full byte body of an incoming JMS message with a plain `ObjectInputStream`, with no `ObjectInputFilter` and no integrity check on the bytes. Confidence: medium-high (lowered from high because the `OrderEvent` class and the queue's ACL/network exposure aren't in the provided call chain - see Assumptions).

## Source

`javax.jms.BytesMessage` body delivered to `OrderEventQueueDeserialize.onMessage(Message)` (line 22-28). The class comment states the queue is fed by partner integrations through a B2B gateway - a cross-trust-boundary source: any party able to place a message on that queue (a compromised or malicious partner, or anyone who can reach the broker with publish rights) controls the byte stream that reaches the sink. Java's native serialization format lets that stream name the concrete class(es) to instantiate during reconstruction, not just the field values of an expected type.

## Fix

Vulnerable code (line 30-33 of the original):

```java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
OrderEvent event = (OrderEvent) ois.readObject();
```

Fixed code:

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

    // Allowlist for the incoming stream: only OrderEvent and the plain value
    // types it is expected to be built from may be instantiated. Extend this
    // set to match OrderEvent's actual field types (verify against its real
    // definition - it was not part of this change's call chain).
    private static final ObjectInputFilter ORDER_EVENT_FILTER = filterInfo ->
    {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null)
        {
            // Array-length / depth / stream-size probes carry no class;
            // defer to the built-in stream limits rather than deciding here.
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (clazz == OrderEvent.class
                || clazz == String.class
                || clazz == Long.class
                || clazz == Integer.class
                || clazz == Boolean.class
                || clazz == java.math.BigDecimal.class
                || clazz == java.util.Date.class)
        {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    };

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

The class comment rules out replacing the wire format with JSON: the partner-side publisher is explicitly out of scope and still emits native Java-serialized `OrderEvent` bodies, so the format itself has to stay `ObjectInputStream`. With that constraint, the knowledge base's fallback for "Java serialization is required" applies: install an `ObjectInputFilter` on the stream before calling `readObject()` so the JVM checks every class named in the byte stream against an explicit allowlist as it reconstructs the object graph, instead of trusting whatever class name the sender wrote. The filter returns `REJECTED` for anything not on the allowlist, which makes the stream throw before an attacker-chosen gadget class can be instantiated or have its `readObject()`/`readResolve()` run. The `serialClass() == null` branch is handled separately and deferred to `UNDECIDED` rather than folded into the reject path, because that null case is how the stream's own array-length/depth/byte-count probes arrive, not a class-instantiation attempt - rejecting it outright would break the built-in stream limits instead of the attacker's payload.

## Behaviour changes

- Added `ois.setObjectInputFilter(ORDER_EVENT_FILTER)` and the filter definition: this is the fix itself, not incidental. No arguments, return value, or existing control flow of `onMessage` were changed.
- A payload whose stream contains any class outside the allowlist now fails with `InvalidClassException` where it previously would have succeeded (if the class was on the classpath) or failed only later at the `(OrderEvent)` cast or inside `processor.handle`. That exception is caught by the existing `catch (Exception e)` and wrapped in the same `RuntimeException("Failed to process order event", e)` as every other failure path, so the caller-visible failure behaviour is unchanged - only the point and reason for failure moves earlier, before any attacker-controlled class is instantiated.
- Assumption: `OrderEvent`'s field types were not part of the provided call chain, so the allowlist above covers the class itself plus common order-domain value types (`String`, `Long`, `Integer`, `Boolean`, `BigDecimal`, `Date`). This must be verified and extended against `OrderEvent`'s real definition - in particular any collection types (e.g. `ArrayList`, array types) it uses - or legitimate messages will be rejected alongside malicious ones.
