## Verdict

**Confirmed.** Line 33 deserializes untrusted serialized data from an external JMS queue without type validation or integrity checks, allowing an attacker to instantiate arbitrary classes and potentially execute arbitrary code during object reconstruction.

## Source

**Location:** evals/cases/502/java/OrderEventQueueDeserialize/OrderEventQueueDeserialize.java, line 33

**Data flow:**
1. Untrusted message arrives from external JMS queue (published by partner integrations through B2B gateway)
2. Serialized byte payload extracted from BytesMessage
3. ObjectInputStream created from payload bytes
4. Sink: `ObjectInputStream.readObject()` at line 33 deserializes arbitrary classes without validation

**Assumption:** OrderEvent is in the `evalcases` package; adjust the filter pattern if it belongs to a different package.

## Fix

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

    @Override
    public void onMessage(Message message)
    {
        try
        {
            BytesMessage bytesMessage = (BytesMessage) message;
            byte[] payload = new byte[(int) bytesMessage.getBodyLength()];
            bytesMessage.readBytes(payload);

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
            
            // Apply class allowlist filter before deserialization
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                "evalcases.OrderEvent;java.base/*;java.util.*;!*"
            );
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

The fix adds an `ObjectInputFilter` allowlist before calling `readObject()`. The filter uses a string-based pattern that:

1. **Allows OrderEvent:** `evalcases.OrderEvent` - the only application class that should be deserialized
2. **Allows JDK types:** `java.base/*` and `java.util.*` - necessary container types (ArrayList, HashMap, String, etc.) that OrderEvent may hold as fields
3. **Rejects everything else:** `!*` - denies all other classes, preventing gadget-chain attacks

The filter is attached per-stream using `ois.setObjectInputFilter(filter)` before the first `readObject()` call. This preserves the native serialization format (required because external producers cannot be changed) while restricting what classes the deserializer may instantiate.

The filter works in JDK 8u121+ and requires no additional dependencies. If the environment is JDK 9+, `ObjectInputFilter` is part of the standard library; for JDK 8u121-8u383, it is available via a backport.

## Behaviour changes

- **Same format preserved:** Messages remain Java-serialized; no breaking change to wire format
- **Rejection of untrusted classes:** Any attempt to deserialize a class not in the allowlist (gadget chains, injected classes, etc.) throws `java.io.InvalidClassException` and fails fast
- **Legitimate traffic passes:** OrderEvent instances and their expected field types (primitives, Strings, collections of JDK types) deserialize normally
- **No signature verification:** This fix addresses class instantiation control only; it does not verify message integrity. Combine with HMAC signing in production if the threat model includes active message tampering
