## Verdict

**CWE-77 Confirmed and Exploitable**

The code hand-builds a Redis inline protocol command via string concatenation without any framing or escaping. An attacker supplies untrusted values for `documentId` and `noteText` through the HTTP API, which reach `RedisWireWriter.SendSetCommand()` and are concatenated directly into a raw command string. A payload containing `\r\n` (e.g., `"foo\r\nDEL annotation:*\r\n"`) splits into multiple Redis commands at the protocol level, bypassing the intended semantics and allowing arbitrary command injection.

## Source

**Entry point**: `AnnotationsController.AddAnnotation(string documentId, [FromForm] string noteText)` receives untrusted HTTP form input.

**Call chain**:
1. AnnotationsController.AddAnnotation() → AnnotationService.SaveAnnotation(documentId, noteText)
2. AnnotationService.SaveAnnotation() → AnnotationCacheClient.StoreAnnotation(record) where record.DocumentId = documentId, record.Text = noteText
3. AnnotationCacheClient.StoreAnnotation() → RedisWireWriter.SendSetCommand(key, value) where key = "annotation:" + record.DocumentId, value = record.SavedAtUtc.ToString("O") + "|" + record.Text
4. RedisWireWriter.SendSetCommand() builds `"SET " + key + " " + value + "\r\n"` (line 19)
5. Sink: `NetworkStream.Write()` at line 24 sends the unframed command bytes to Redis

Both `documentId` (in the key) and `noteText` (in the value) are attacker-controlled and carry no validation or escaping before reaching the wire.

## Fix

Replace the raw Socket/NetworkStream approach with StackExchange.Redis, which uses RESP protocol framing. Each argument is encoded with an explicit length prefix, so embedded delimiters cannot split the command.

### File: RedisWireWriter.cs

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Uses StackExchange.Redis to send commands with RESP framing, preventing
    // delimiter injection by encoding each argument with an explicit length prefix.
    public class RedisWireWriter
    {
        private readonly IConnectionMultiplexer _redis;

        public RedisWireWriter(IConnectionMultiplexer redis)
        {
            _redis = redis;
        }

        public void SendSetCommand(string key, string value)
        {
            IDatabase db = _redis.GetDatabase();
            db.StringSet(key, value);
        }
    }
}
```

## Explanation

The original code called `NetworkStream.Write()` with a raw inline protocol command built by string concatenation. Redis's plain-text inline protocol delimits arguments with spaces and terminates commands with `\r\n`. A value containing `\r\n` (or even just spaces, for position) is not quoted or escaped; the protocol treats it as the end of one command and the start of another.

StackExchange.Redis instead uses the RESP (Redis Serialization Protocol), which encodes each argument with an explicit byte-length prefix. This framing makes it impossible for embedded delimiters to split the command: an argument containing `\r\n` or spaces is transmitted as `$<length>\r\n<bytes>\r\n`, and the server reads exactly `<length>` bytes regardless of their content.

The fix removes the vulnerable string concatenation and substitutes `IDatabase.StringSet()`, StackExchange.Redis's typed method for SET operations. The `key` and `value` arguments are passed directly to the client library, which frames them using RESP before transmission.

**Constructor change**: The dependency is now an `IConnectionMultiplexer` instead of a `TcpClient`. This decouples the command-building logic from the transport layer. In a dependency-injection setup, `IConnectionMultiplexer` would typically be a singleton configured at application startup.

## Behaviour changes

- **Wire protocol**: Changes from plain-text inline protocol to RESP binary framing. Redis accepts both, so the server responds identically; the change is transparent at the application level.
- **Command transport**: Arguments are now length-prefixed rather than space-delimited. Payloads containing spaces, newlines, or Redis keywords are stored as literal data without reinterpretation.
- **Error handling**: StackExchange.Redis.StringSet() may throw `RedisConnectionException` on transport failure, whereas raw `NetworkStream.Write()` throws `IOException`. Calling code should handle these appropriately (both are connection-level errors).
- **Response availability**: The original sink discarded the Redis server's response. StackExchange.Redis.StringSet() returns `bool` (true if the key was set, false if it already existed and was not overwritten with `KEEPTTL` or similar). Calling code that needs the response can now use it; code that ignores it is unaffected.
- **Dependency injection**: The constructor signature changes from `TcpClient` to `IConnectionMultiplexer`, requiring updates to any code that constructs RedisWireWriter.

The fix eliminates the command injection by delegating command framing to the RESP protocol's length-prefix encoding, which is immune to delimiter injection.
