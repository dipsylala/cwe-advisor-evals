## Verdict

Exploitable. Untrusted user input (documentId and noteText from HTTP request) flows unsanitized into a hand-built Redis inline protocol command string, allowing an attacker to inject arbitrary Redis commands via embedded CRLF sequences.

## Source

User-supplied `documentId` (route parameter) and `noteText` (form body) in `AnnotationsController.AddAnnotation()` method.

**Data flow path:**
1. `AnnotationsController.AddAnnotation()` receives `documentId` and `noteText` as untrusted HTTP input
2. Passed to `AnnotationService.SaveAnnotation(documentId, noteText)`
3. Stored in `AnnotationRecord` and passed to `AnnotationCacheClient.StoreAnnotation(record)`
4. `AnnotationCacheClient.StoreAnnotation()` constructs `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`
5. Passed to `RedisWireWriter.SendSetCommand(key, value)` at line 18
6. `RedisWireWriter.SendSetCommand()` builds command string by concatenation at line 19: `string command = "SET " + key + " " + value + "\r\n"`
7. Sink: command written to Redis via `NetworkStream.Write()` at line 24

**Attack example:**
- Input: `documentId = "mykey\r\nFLUSHALL\r\n"`
- Resulting command: `SET annotation:mykey\r\nFLUSHALL\r\n {timestamp}|{text}\r\n`
- Redis inline protocol parser treats embedded CRLF as command separators, executing both SET and FLUSHALL commands
- Impact: Data loss, cache cleared, denial of service

## Fix

**Vulnerable code (RedisWireWriter.cs lines 17-25):**

```csharp
public void SendSetCommand(string key, string value)
{
    string command = "SET " + key + " " + value + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    NetworkStream stream = _client.GetStream();
    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    stream.Write(payload, 0, payload.Length);
}
```

**Fixed code:**

Replace the `TcpClient`-based approach with StackExchange.Redis's typed API. Update `RedisWireWriter` to use the library's parameterized `StringSet` method instead of hand-building command strings:

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    public class RedisWireWriter
    {
        private readonly IDatabase _db;

        public RedisWireWriter(IConnectionMultiplexer redis)
        {
            _db = redis.GetDatabase();
        }

        public void SendSetCommand(string key, string value)
        {
            // FIXED: Use StackExchange.Redis's typed StringSet method.
            // Arguments are framed with explicit length prefixes (RESP protocol),
            // preventing embedded CRLF, spaces, or command syntax from being interpreted as separate commands.
            _db.StringSet(key, value);
        }
    }
}
```

Additionally, update the dependency injection chain to pass `IConnectionMultiplexer` instead of `TcpClient` through the constructor:

- `AnnotationsController` and `AnnotationService` remain unchanged
- `AnnotationCacheClient` remains unchanged (still calls `SendSetCommand`)
- Composition root (dependency injection setup, not shown in case files) creates the `IConnectionMultiplexer` and injects it into `RedisWireWriter`

**Library dependency:**
- Add NuGet package: `StackExchange.Redis`
- No minimum version specified in guidance; consult your security advisory process for the recommended version

## Explanation

The vulnerability exists because the inline Redis protocol is space-and-CRLF-delimited at the command level. Hand-building the command string as `"SET " + key + " " + value + "\r\n"` allows an attacker who controls `key` or `value` to inject embedded CRLF sequences that the Redis server's inline protocol parser interprets as command separators, enabling execution of arbitrary commands like `FLUSHALL`, `DEL`, or `CONFIG SET`.

The fix replaces the unsafe string concatenation with StackExchange.Redis's `StringSet()` API, which uses the RESP (Redis Serialization Protocol) instead of the plain-text inline protocol. RESP encodes each argument with an explicit byte-length prefix (e.g., `$5\r\nhello\r\n` for the string "hello"), making it impossible for embedded CRLF or spaces to split commands. The key and value are sent as separate, length-delimited arguments, so the entire value—including any CRLF sequences—is treated as literal data.

This change closes the command injection vulnerability by ensuring the protocol layer, not user input, controls command structure. It also shifts from manual protocol handling to a well-maintained client library, eliminating risk from subtle protocol implementation errors.

## Behaviour changes

- **Constructor change**: `RedisWireWriter` now accepts `IConnectionMultiplexer redis` instead of `TcpClient client`. This is a necessary dependency-injection change to enable use of StackExchange.Redis's type-safe APIs.
- **No manual protocol handling**: Removed ASCII encoding and manual byte array construction. The library handles all protocol framing internally.
- **Implicit protocol layer**: The underlying protocol shifts from Redis inline (plain-text, CRLF-delimited) to RESP (binary, length-prefixed). This is transparent to callers; both approaches produce the same server-side result—the key-value pair is stored—but RESP prevents injection attacks.
- **Error handling differs**: `StringSet()` is a synchronous API that may throw `RedisConnectionException` or `RedisServerException` on connection or command errors, whereas the original `NetworkStream.Write()` would throw `IOException` on network errors. Calling code should be reviewed to ensure error handling covers both cases appropriately.

