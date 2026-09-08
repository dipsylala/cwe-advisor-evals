## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-502 (Deserialization of Untrusted Data)
- location: `OrderEventQueueDeserialize.java`, `onMessage`, line 33 (`ois.readObject()`)

## Source

`javax.jms.BytesMessage` payload delivered to `onMessage(Message message)` (lines 26-28). The message body is read as raw bytes off a JMS queue that, per the file's own comment, is fed by external partner integrations through a B2B gateway - the bytes are attacker-influenceable network input, not application-generated data.

## Fix

The queue's producers (external partner integrations via the B2B gateway) are explicitly out of scope for this change and continue to ship native Java-serialized `OrderEvent` bodies, so the format cannot move to JSON without breaking every legitimate message. Per the loaded CWE-502 Java guidance, the fix keeps `ObjectInputStream` and attaches an `ObjectInputFilter` allowlist restricting reconstruction to the expected `evalcases.OrderEvent` type (plus the `java.base` module needed for its field graph), rejecting everything else before any object is constructed.

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
            ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "evalcases.OrderEvent;java.base/*;!*"));

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

`ObjectInputFilter.Config.createFilter("evalcases.OrderEvent;java.base/*;!*")` builds an allowlist that permits only `evalcases.OrderEvent` and classes in the `java.base` module (covering the JDK collection/array types an `OrderEvent` graph typically needs), and rejects every other class with the trailing `!*`. Attaching it via `ois.setObjectInputFilter(filter)` - once per `ObjectInputStream`, before `readObject()` is called - means the filter evaluates each class during graph walking and rejects a disallowed class before it is instantiated, closing the gadget-chain path a scanner flags at `readObject()`. This does not use `ObjectInputFilter.Config.setSerialFilter()`, which is process-wide and throws `IllegalStateException` on a second call from inside a message handler invoked repeatedly. The wire format is unchanged, so the existing native-serialization producers on the B2B gateway continue to work unmodified.

## Behaviour changes

- Added: an `ObjectInputFilter` is now attached to the stream. Reason: this is the mechanism that closes the weakness; without it any class in the classpath (or a gadget chain? reachable from one) is constructible.
- New rejection path: a `BytesMessage` payload whose top-level object is anything other than `evalcases.OrderEvent`, or that references a class outside `java.base`, now fails with `InvalidClassException` (surfaced as a wrapped `RuntimeException`, same as any other `readObject()` failure the existing `catch (Exception e)` already handles) instead of being silently deserialized. Reason: this is the intended effect of the fix - it only rejects payloads that were never legitimate `OrderEvent` messages from the described producers.
- No other change: return value, argument list, discarded output, and failure-wrapping behavior of the surrounding method are all unchanged from the original.
- library_recommendation: none - `ObjectInputFilter` is part of the JDK standard library (`java.io`, JEP 290, backported to 8u121), not a third-party dependency, so no version bump or SCA check applies.

## Verification

- `javac` (JDK 26) compiled the fixed file cleanly against stub `OrderEvent`, `OrderProcessor`, and `javax.jms` types recreated to match the original file's usage (the real `OrderEvent`/`OrderProcessor`/JMS classes are outside the provided call chain).
- Runtime check: serialized an `OrderEvent` instance through the same filter string and confirmed it deserializes successfully; serialized an unrelated `Serializable` class and confirmed `ObjectInputStream.readObject()` throws `InvalidClassException` with `filter status: REJECTED` under the identical filter, confirming both the allow and reject paths behave as intended.
- assumptions: `OrderEvent` is assumed to live in the same `evalcases` package as the listener (only file available in the call chain); if it lives elsewhere, the filter string's class name should be updated to that fully-qualified name. No other ambiguity required a judgment call in autonomous mode.
