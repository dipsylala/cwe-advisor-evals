## Verdict

Confirmed. CWE-502 (Deserialization of Untrusted Data) at `OrderEventQueueDeserialize.onMessage`, line 33.

## Source

The JMS `BytesMessage` body delivered to `onMessage(Message message)`. The class comment records that this queue is fed by external partner integrations through a B2B gateway, so the byte payload is attacker-influenceable network input, not internally generated data. It is copied into a `byte[]` (lines 26-28) and wrapped directly in an `ObjectInputStream` with no integrity check or class restriction in between.

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
    // Explicit per-class allowlist (JEP 290 / backported to 8u121+). Only
    // OrderEvent and ordinary JDK value types it may reference are permitted;
    // everything else - including known gadget-chain classes - is rejected
    // before any object graph is constructed. Limits bound the size and
    // shape of the incoming object graph regardless of class.
    private static final ObjectInputFilter ORDER_EVENT_FILTER =
        ObjectInputFilter.Config.createFilter(
            "evalcases.OrderEvent;java.lang.*;java.util.*;"
            + "maxdepth=10;maxarray=10000;maxrefs=1000;maxbytes=1000000;!*");

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

The class comment states the publishing side still emits native Java-serialized `OrderEvent` bodies and that the wire format is out of scope for this change, which rules out the guidance's preferred fix (replace `ObjectInputStream` with a data-only format like JSON) - it would require a coordinated change on a partner integration this fix cannot touch. With native Java serialization staying in place, the applicable safe pattern from `cwe/502/java/INDEX.md` is an `ObjectInputFilter` allowlist (available since 8u121 via JEP 290's backport), applied to the stream before `readObject()` is called.

The filter is built once with `ObjectInputFilter.Config.createFilter()` from an explicit pattern: `evalcases.OrderEvent` is allowed by name, `java.lang.*` and `java.util.*` are allowed by package (the ordinary value and container types a plain data-carrier class like `OrderEvent` is expected to reference), numeric limits (`maxdepth`, `maxarray`, `maxrefs`, `maxbytes`) bound the size and shape of the object graph the stream will construct, and the trailing `!*` rejects every class that does not match an earlier pattern - including any gadget-chain class from a library on the classpath, since those live outside `evalcases`, `java.lang`, and `java.util`. `ois.setObjectInputFilter(ORDER_EVENT_FILTER)` attaches this to the specific stream instance before `readObject()` runs, so the filter is consulted for every class resolved during deserialization, not just the top-level `OrderEvent` type.

## Behaviour changes

- A legitimate `OrderEvent` payload whose fields resolve only to `evalcases.OrderEvent`, `java.lang.*`, and `java.util.*` types, within the configured depth/array/ref/byte limits, deserializes and reaches `processor.handle(event)` exactly as before - no change to the success path.
- A payload that names any class outside that allowlist (any known or future gadget-chain class, or any legitimate field type this fix did not anticipate) now causes `ois.readObject()` to throw `java.io.InvalidClassException` instead of constructing the object. That exception is caught by the existing `catch (Exception e)` and rethrown as `RuntimeException("Failed to process order event", e)`, the same externally observable failure this method already produces for any other deserialization error - no new exception type escapes `onMessage`.
- `OrderEvent`'s own source is not part of this call chain, so its exact field types could not be inspected. If it references a type outside `java.lang.*`/`java.util.*` (for example a `java.time` field, or a nested custom class), previously-accepted payloads using that field will start failing until the allowlist pattern is extended to name that type explicitly - this should be verified against `OrderEvent`'s actual field set before deployment.
- The wire format and the publishing side are unchanged, consistent with the existing code comment that partner integrations still ship native Java-serialized bodies.
