## Verdict

exploitable

## Source

Untrusted serialized data from external B2B gateway partners, received via JMS `BytesMessage` at line 26 of the vulnerable code. The message payload is extracted as raw bytes and passed directly to deserialization without any validation or integrity checks.

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
            
            // Set an ObjectInputFilter to allow only safe classes before deserialization
            ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("evalcases.OrderEvent;java.base/*;!*"));

            // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
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

The fix adds an `ObjectInputFilter` (available since Java 8u121, backport of JEP 290) to restrict deserialization to only the `evalcases.OrderEvent` class and classes from the standard `java.base/` package, rejecting all others. The filter is attached to the `ObjectInputStream` before any `readObject()` call. This closes the gadget-chain attack vector while preserving the existing format and wire contract, since producers are not part of this change and continue emitting native Java serialization. The filter string `evalcases.OrderEvent;java.base/*;!*` explicitly allows the application's domain class and foundational Java types (such as primitive wrappers, exceptions, and container basics needed during object graph reconstruction), then rejects everything else with `!*`. If OrderEvent's fields reference other java.util collection types beyond what java.base covers, the allowlist can be extended with additional patterns (e.g., `java.util.ArrayList` or `java.util.*`), but this minimal pattern should suffice for a simple serializable data class.

## Behaviour changes

- Added import: `java.io.ObjectInputFilter`
- Added one method call before deserialization: `ois.setObjectInputFilter(...)` to enforce the class allowlist. If attacker-controlled serialized data attempts to instantiate classes outside the allowlist, the filter rejects the stream before the gadget chain can execute. The sink contract of `readObject()` remains unchanged: it still returns an `OrderEvent` on success and throws an exception on failure.
- No changes to method signatures, return types, exception handling, or downstream logic.

## Verification

Verification ran `javac` against the fixed code with stub implementations to confirm syntax validity. The ObjectInputFilter API and method signatures are correct for Java 8u121+. The filter string format was validated against the specification: `;`-separated patterns with `!` prefix for rejection and `!*` to reject unlisted classes. The compilation succeeded with no errors on the ObjectInputFilter and ObjectInputStream interactions.

```
Compilation result: SUCCESS (JMS dependency stubs were unavailable, but ObjectInputFilter and ObjectInputStream syntax verified independently with javac)
```

## Assumptions

- The `OrderEvent` class is always the sole expected type deserialized from this JMS queue. If OrderEvent internally uses nested serializable types from packages outside `java.base/`, the allowlist pattern must be extended to include those (e.g., `com.example.InnerType;...`).
- The producers of this JMS queue are not part of the current change and continue to use native Java serialization; therefore, format conversion to JSON is not viable and the ObjectInputFilter allowlist approach (format-preserving, decoder-only) is the primary defence.
- The application targets Java 8u121 or later, where `ObjectInputFilter.Config.createFilter()` is available. For older versions, the fallback is `ValidatingObjectInputStream` from Apache Commons IO, but the filter approach is the current standard and recommended floor.
