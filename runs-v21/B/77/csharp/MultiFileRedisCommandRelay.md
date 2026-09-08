## Verdict

Command injection via Redis protocol. The vulnerability is confirmed and exploitable.

## Source

- `AnnotationsController.AddAnnotation()` receives untrusted HTTP POST parameters: `documentId` and `noteText`
- These values flow through `AnnotationService.SaveAnnotation()` and `AnnotationCacheClient.StoreAnnotation()`
- They reach `RedisWireWriter.SendSetCommand()` where they are concatenated into a plain-text Redis command string

## Fix

### File: RedisWireWriter.cs

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Uses StackExchange.Redis's parameterized API instead of hand-building commands
    // over a raw socket, preventing command injection via the RESP protocol's
    // explicit length-prefix framing for each argument.
    public class RedisWireWriter
    {
        private readonly IDatabase _db;

        public RedisWireWriter(IDatabase db)
        {
            _db = db;
        }

        public void SendSetCommand(string key, string value)
        {
            // Use StackExchange.Redis's typed StringSet API instead of concatenating
            // a raw command string. RESP encodes each argument with an explicit length
            // prefix, so embedded \r\n or spaces in the value cannot split it into
            // a separate command.
            _db.StringSet(key, value);
        }
    }
}
```

## Explanation

The original code bypassed StackExchange.Redis's safety mechanisms by hand-building a plain-text inline-protocol command string (`"SET " + key + " " + value + "\r\n"`) and writing it directly to a raw `NetworkStream`. The plain-text protocol interprets `\r\n` as a command separator, so an attacker-supplied value containing `\r\nFLUSHALL\r\n` executes as two commands.

The fix replaces the raw socket code with StackExchange.Redis's parameterized `IDatabase.StringSet()` method, which uses RESP (Redis Serialization Protocol) framing. RESP encodes each argument with an explicit byte-length prefix before the value, making it impossible for embedded delimiters in the value to be interpreted as command structure. The fix eliminates the injection point entirely by using the library's structured command API instead of string concatenation.

The constructor signature changes from accepting a `TcpClient` to accepting an `IDatabase` instance, which is obtained from a `ConnectionMultiplexer` via dependency injection. The method signature `SendSetCommand(string, string)` and behavior remain unchanged—legitimate callers pass key and value as before, but the command is now framed safely.

## Behaviour changes

- The wire protocol changes from plain-text inline protocol to RESP. Embedded newlines, spaces, and other delimiters in the key and value are now transmitted as literal bytes with length prefixes instead of being interpreted as command structure.
- The constructor no longer accepts a raw `TcpClient`; it requires an `IDatabase` instance from StackExchange.Redis's `ConnectionMultiplexer`. This decouples the code from low-level socket management and enables connection pooling, TLS encryption, and cluster support.
- Return value unchanged: `StringSet()` returns a `bool` indicating success (the original code did not return or check the result, so existing callers are unaffected if they also ignore the return value, or can now check it for robustness).
- Error handling changes: `StringSet()` throws `RedisConnectionException` on network failure or `RedisServerException` for protocol errors from the server. The original code would have thrown `IOException` on network issues. Callers can now distinguish connection failures from invalid commands.
