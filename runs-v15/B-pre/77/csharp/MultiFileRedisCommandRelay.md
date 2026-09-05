## Verdict

**Confirmed**: CWE-77 (Improper Neutralization of Special Elements used in a Command) at line 24 of RedisWireWriter.cs is a real vulnerability. Untrusted user input (documentId and noteText) flows through the call chain without sanitization and is concatenated directly into a Redis inline-protocol command string, allowing injection of arbitrary Redis commands via CRLF sequences.

## Source

The vulnerability originates from user-supplied HTTP input:
- `AnnotationsController.AddAnnotation()` receives untrusted `documentId` (route parameter) and `noteText` (form data)
- Both values flow through `AnnotationService.SaveAnnotation()` → `AnnotationCacheClient.StoreAnnotation()` → `RedisWireWriter.SendSetCommand()`
- In `AnnotationCacheClient.StoreAnnotation()`, these values are incorporated into the Redis key and value:
  - `key = "annotation:" + record.DocumentId` (contains untrusted documentId)
  - `value = record.SavedAtUtc.ToString("O") + "|" + record.Text` (contains untrusted noteText)
- These untrusted key and value are passed to `RedisWireWriter.SendSetCommand(key, value)`

The unsafe sink is at line 19 of RedisWireWriter.cs where the command string is built, and line 24 where it is sent to Redis via `stream.Write()`.

## Fix

**Replace RedisWireWriter.cs with this implementation:**

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using StackExchange.Redis's parameterized API,
    // which uses RESP (Redis Serialization Protocol) framing to safely encode arguments.
    public class RedisWireWriter
    {
        private readonly IConnectionMultiplexer _connectionMultiplexer;

        public RedisWireWriter(IConnectionMultiplexer connectionMultiplexer)
        {
            _connectionMultiplexer = connectionMultiplexer;
        }

        public void SendSetCommand(string key, string value)
        {
            IDatabase db = _connectionMultiplexer.GetDatabase();
            // FIXED: Use StringSet() parameterized method instead of hand-built command string.
            // RESP framing ensures key and value are encoded with explicit length prefixes,
            // so embedded CRLF or command syntax cannot inject additional commands.
            db.StringSet(key, value);
        }
    }
}
```

**Also update AnnotationCacheClient.cs to inject the connection multiplexer:**

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Turns an AnnotationRecord into the key/value pair the cache layer will store.
    public class AnnotationCacheClient
    {
        private readonly RedisWireWriter _wireWriter;

        // Accept IConnectionMultiplexer via constructor for dependency injection.
        public AnnotationCacheClient(RedisWireWriter wireWriter)
        {
            _wireWriter = wireWriter;
        }

        public void StoreAnnotation(AnnotationRecord record)
        {
            string key = "annotation:" + record.DocumentId;
            string value = record.SavedAtUtc.ToString("O") + "|" + record.Text;

            _wireWriter.SendSetCommand(key, value);
        }
    }
}
```

## Explanation

The original code built Redis commands by concatenating untrusted user input into an inline-protocol command string. The Redis inline protocol treats CRLF (`\r\n`) as a command terminator, so an attacker can inject additional commands. For example, if `noteText` contained `"\r\nFLUSHALL\r\n"`, the command string would become:

```
SET annotation:docid 2026-09-03T12:00:00|
FLUSHALL
```

And Redis would execute both commands.

The fix replaces hand-built command strings with StackExchange.Redis's `StringSet()` parameterized API. This client library uses RESP (Redis Serialization Protocol), which encodes each argument with an explicit length prefix rather than relying on delimiters. With RESP framing, the value `"\r\nFLUSHALL\r\n"` is safely encoded as a single data block and stored as literal text, not interpreted as a new command.

This eliminates the injection vector while maintaining the same functional behaviour: the key and value are still stored in Redis exactly as provided.

## Behaviour changes

**Functional behaviour**: Unchanged. Both implementations store the same key-value pair in Redis.

**Observable differences**:
- Constructor now requires an `IConnectionMultiplexer` instead of `TcpClient`. This is a breaking change for callers, but the parameterized API is the only safe way to send Redis commands.
- The method no longer opens its own socket or manages the network stream; the connection multiplexer handles connection pooling and reuse.
- The method may throw `RedisConnectionException` or `TimeoutException` on connection failure, where the original threw `IOException`. The calling code should handle these exceptions appropriately.

**Security impact**: Command injection is eliminated. Untrusted input in the key and value parameters cannot be interpreted as Redis command syntax or delimiters.
