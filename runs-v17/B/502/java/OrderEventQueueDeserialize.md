## Verdict

The finding is valid. Untrusted serialized data from a B2B gateway is deserialized without type validation, exposing the application to arbitrary code execution via gadget chains.

## Source

**Vulnerable sink:** `ObjectInputStream.readObject()` at line 33 of `OrderEventQueueDeserialize.java`

**Data flow:**
1. Untrusted data arrives via JMS BytesMessage (from partner integrations through B2B gateway)
2. Raw bytes extracted via `bytesMessage.readBytes(payload)`
3. ObjectInputStream created from untrusted bytes
4. `readObject()` deserializes without validation, allowing arbitrary class instantiation

**Why it's exploitable:** Native Java serialization can invoke methods during object reconstruction. Gadget chains in common libraries can be exploited to execute arbitrary code during deserialization. No allowlist or integrity checks constrain what classes may be instantiated.

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

            // Attach an ObjectInputFilter allowlist before deserialization
            ObjectInputFilter filter = info -> {
                Class<?> cls = info.serialClass();
                if (cls == null) {
                    // Stream metadata (limits, depth, etc.)
                    return ObjectInputFilter.Status.ALLOWED;
                }

                // Allow the expected event type
                if (cls == OrderEvent.class) {
                    return ObjectInputFilter.Status.ALLOWED;
                }

                // Allow java.base classes (java.lang, java.util, java.io, java.time, etc.)
                String className = cls.getName();
                if (className.startsWith("java.lang.") ||
                    className.startsWith("java.util.") ||
                    className.startsWith("java.time.") ||
                    className.startsWith("java.io.")) {
                    return ObjectInputFilter.Status.ALLOWED;
                }

                // Reject all other classes
                return ObjectInputFilter.Status.REJECTED;
            };

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

The fix attaches an `ObjectInputFilter` to the `ObjectInputStream` before calling `readObject()`. This allowlist-based filter enforces strict type constraints:

1. **Metadata calls** (cls == null) are allowed to permit stream size and depth limits to be enforced by the JVM
2. **OrderEvent** instances are allowed since that is the expected type
3. **java.base classes** (java.lang, java.util, java.io, java.time) are allowed to support container types and utility objects that OrderEvent may legitimately use (ArrayList, HashMap, String, Long, etc.)
4. **All other classes are rejected**, preventing instantiation of gadget chains or arbitrary attacker-supplied classes

The filter is attached per-stream with `setObjectInputFilter(ois)` rather than as a process-wide filter, avoiding the `IllegalStateException` that would occur on subsequent invocations if `ObjectInputFilter.Config.setSerialFilter()` were used in a message handler.

This approach preserves the existing wire format (native Java serialization) and application contract while restricting deserialization to a safe, bounded set of known types. Because producers (B2B gateway partners) remain outside this change, format conversion to JSON or Protocol Buffers is not feasible here—the filter-based constraint is the appropriate remedy for legacy serialized streams.

**Requires:** Java 8u121 or later (when JEP 290 was backported) or Java 9+. The ObjectInputFilter API is part of java.io in the standard library.

## Behaviour changes

**Before fix:** Any serialized class could be instantiated during deserialization, permitting gadget-chain exploitation.

**After fix:** Only OrderEvent and java.base utility classes are instantiated. Attempts to deserialize any other class result in rejection and an exception in the deserialization handler.

**Impact on valid traffic:** Valid OrderEvent messages containing only OrderEvent and java.base container/utility types deserialize normally. Messages containing custom application classes outside the allowlist will fail to deserialize—evaluate whether OrderEvent or its fields reference any application classes outside java.base, and add their specific classes to the allowlist if needed (e.g., if a custom DTO is embedded, add `className.equals("your.app.CustomDTO")`).

**Exception flow:** Rejected classes throw `InvalidClassException` wrapped by the JMS message handler's catch block, producing a `RuntimeException` with the message "Failed to process order event". This is the existing exception behavior and requires no change to error handling.
