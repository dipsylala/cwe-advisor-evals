## Verdict

**Exploitable command injection via Redis inline protocol.**

User-controlled data (`noteText`) flows from the HTTP controller through the service layers to `RedisWireWriter.SendSetCommand()`, where it is concatenated into a raw Redis command string without escaping. The inline protocol uses CRLF as a command terminator, so an attacker can inject `\r\n` followed by arbitrary Redis commands to execute operations beyond the intended SET.

## Source

- **Input source:** `AnnotationsController.AddAnnotation()` receives `noteText` from HTTP POST form data (line 18 of AnnotationsController.cs)
- **Data flow:** 
  1. `noteText` → `AnnotationService.SaveAnnotation(documentId, noteText)` (line 25)
  2. Wrapped in `AnnotationRecord.Text = noteText` (line 20 of AnnotationService.cs)
  3. `AnnotationCacheClient.StoreAnnotation(record)` (line 24 of AnnotationService.cs)
  4. Value built as `record.SavedAtUtc.ToString("O") + "|" + record.Text` (line 16 of AnnotationCacheClient.cs)
  5. Both key and value passed to `RedisWireWriter.SendSetCommand(key, value)` (line 18 of AnnotationCacheClient.cs)
- **Sink:** `stream.Write(payload, 0, payload.Length)` at line 24 of RedisWireWriter.cs, after concatenating the hand-built command string at line 19

## Fix

**Replace hand-built inline protocol with StackExchange.Redis parameterized API.**

The `RedisWireWriter` class should use StackExchange.Redis's `IDatabase.StringSet()` method, which frames each argument with explicit length prefixes (RESP protocol) so embedded CRLF cannot be interpreted as command delimiters.

**Fixed RedisWireWriter.cs:**

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using StackExchange.Redis,
    // which handles proper RESP framing to prevent command injection.
    public class RedisWireWriter
    {
        private readonly IDatabase _database;

        public RedisWireWriter(IConnectionMultiplexer redis)
        {
            _database = redis.GetDatabase();
        }

        public void SendSetCommand(string key, string value)
        {
            _database.StringSet(key, value);
        }
    }
}
```

**Dependency change:** Add NuGet package `StackExchange.Redis` (use the latest stable version; no specific CVE floor applies - see dependency management tooling for current safe release).

## Explanation

The original code bypassed the Redis client library entirely, writing raw bytes in the plain-text inline protocol directly to a `NetworkStream`. The inline protocol is vulnerable to injection because it uses only CRLF (`\r\n`) to delimit commands and newline-containing values will split across multiple commands.

The fixed code uses StackExchange.Redis's `IDatabase.StringSet()` method, which:

1. **Encodes each argument with RESP framing** - StackExchange.Redis uses the Redis Serialization Protocol (RESP), which prefixes each argument with its length (`$<length>\r\n<data>\r\n`). Embedded CRLF becomes literal data within the length-delimited block and cannot create new commands.
2. **Eliminates string concatenation** - the typed API accepts the key and value as separate parameters, removing the concatenation point where injection occurs.
3. **Validates the connection** - StackExchange.Redis handles connection pooling, retry logic, and protocol compliance automatically.

The `IConnectionMultiplexer` parameter replaces the raw `TcpClient`. Initialization outside this class should create it once and share it across the application (StackExchange.Redis is designed for reuse and thread-safe).

## Behaviour changes

- **RedisWireWriter constructor changes:** now accepts `IConnectionMultiplexer redis` instead of `TcpClient client`
- **Network protocol changes:** commands now use RESP framing instead of plain-text inline protocol
- **Return value unchanged:** method remains `void`
- **Exception behaviour changes:** `StringSet()` may throw `RedisConnectionException` on network failure (instead of `IOException` from `stream.Write()`) and `RedisServerException` on server-side errors; calling code should handle these as appropriate for its error handling policy
- **Performance note:** StackExchange.Redis maintains a connection pool and can multiplex concurrent commands; raw socket-per-command may have different throughput characteristics - measure if latency-sensitive
- **Upstream callers unaffected:** `AnnotationCacheClient.StoreAnnotation()` does not change; the fix is internal to `RedisWireWriter`
