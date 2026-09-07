## Verdict

CONFIRMED: CWE-77 command injection vulnerability in RedisWireWriter.cs line 24.

User-controlled `documentId` and `noteText` from the HTTP endpoint are concatenated into a Redis command string without sanitization, then written to the wire using the plain-text inline protocol. An attacker can embed `\r\n` (CRLF) to inject arbitrary Redis commands.

Example attack: `noteText = "data\r\nFLUSHALL"` becomes the command `SET annotation:docid data\r\nFLUSHALL\r\n`, executing both SET and FLUSHALL.

## Source

The vulnerability spans a 4-file call chain:

1. **AnnotationsController.cs:18** - Entry point receives user input:
   - `documentId` (route parameter, untrusted)
   - `noteText` (form body, untrusted)

2. **AnnotationService.cs:15-24** - Wraps untrusted values in an AnnotationRecord and forwards to cache layer

3. **AnnotationCacheClient.cs:13-19** - Builds cache key and value by concatenating untrusted data:
   - `key = "annotation:" + record.DocumentId`
   - `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`
   - Calls `SendSetCommand(key, value)` with concatenated untrusted data

4. **RedisWireWriter.cs:17-24** - SINK (line 24):
   - Line 19 concatenates key and value into a raw command string: `"SET " + key + " " + value + "\r\n"`
   - Line 20 encodes to bytes: `Encoding.ASCII.GetBytes(command)`
   - Line 24 writes to wire: `stream.Write(payload, 0, payload.Length)` using the plain-text inline protocol

The inline protocol treats `\r\n` as a command terminator, so embedded newlines split one malicious string into multiple commands. The raw `NetworkStream.Write()` sends bytes without framing, allowing the injection.

## Fix

### File: RedisWireWriter.cs

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using StackExchange.Redis's RESP protocol,
    // which automatically frames each argument so delimiters cannot be read as commands.
    public class RedisWireWriter
    {
        private readonly IConnectionMultiplexer _redis;
        private readonly IDatabase _db;

        public RedisWireWriter(IConnectionMultiplexer redis)
        {
            _redis = redis;
            _db = redis.GetDatabase();
        }

        public void SendSetCommand(string key, string value)
        {
            // Use StackExchange.Redis's StringSet method, which passes key and value
            // as separate protocol elements with explicit length prefixes in RESP.
            // The RESP protocol encodes each argument with its byte length prefix,
            // so embedded \r\n, spaces, or Redis command names in the value cannot
            // be interpreted as command delimiters or separate commands.
            _db.StringSet(key, value);
        }
    }
}
```

## Explanation

The fix replaces raw `NetworkStream` I/O with StackExchange.Redis's typed API.

**What changed:**
- Constructor now accepts `IConnectionMultiplexer redis` instead of `TcpClient client`
- Removed manual command string concatenation and inline protocol encoding
- Replaced `stream.Write()` with `_db.StringSet(key, value)`

**Why this closes the weakness:**
StackExchange.Redis uses the RESP (Redis Serialization Protocol), which encodes each command argument with an explicit byte-length prefix. The protocol frame looks like:
```
*3\r\n
$3\r\nSET\r\n
$14\r\nannotation:doc1\r\n
$18\r\ndata\r\nFLUSHALL\r\n
```

Even if `value` contains `\r\n`, the RESP parser reads exactly 18 bytes (the declared length) into that argument, treating embedded newlines and command names as literal data, not delimiters. The SET command completes normally; FLUSHALL is never parsed.

**Upstream integration:**
The constructor signature change requires that callers provide an `IConnectionMultiplexer` (typically registered in ASP.NET Core dependency injection via `services.AddStackExchangeRedis()`). Callers like `AnnotationCacheClient` continue to receive `RedisWireWriter` and call `SendSetCommand()` without modification—only the internal implementation and constructor change. The `SendSetCommand()` method signature remains the same: `void SendSetCommand(string key, string value)`.

**Sink contract preservation:**
- **Returns**: The original method returned `void` and wrote to the wire synchronously. `StringSet()` is also synchronous and returns `bool` (success), which we discard, maintaining void semantics.
- **Failure behavior**: `StringSet()` throws `RedisConnectionException` if the connection is lost, matching the behavior of `stream.Write()` (which throws `IOException`).
- **Arguments**: Key and value are passed as separate RESP elements, not concatenated into one command string. This is the core fix.

## Behaviour changes

1. **API dependency**: Code now requires `StackExchange.Redis` NuGet package (version 2.8.0 or later, covering current stable releases). Original code required only .NET BCL `System.Net.Sockets`.

2. **Connection management**: Constructor changes from accepting a `TcpClient` (manual connection) to `IConnectionMultiplexer` (managed connection pool). This is a dependency injection boundary change. Upstream code that currently instantiates `new RedisWireWriter(tcpClient)` must instead inject an `IConnectionMultiplexer` registered in DI.

3. **Synchronous execution preserved**: `StringSet()` is synchronous, so the method remains `void` and does not introduce async/await requirements in the call chain.

4. **Return value**: The original method discarded all return data from the wire. `StringSet()` returns `bool` (true if the key was set or updated, false if skipped by options). We discard this return, so callers see no change—errors still propagate as exceptions.

5. **Network protocol**: Wire protocol changes from Redis inline protocol (plain text) to RESP (binary framing). This is fully compatible with any standard Redis server—no server-side changes needed.

6. **Error handling**: `stream.Write()` throws `IOException` on network failure; `StringSet()` throws `RedisConnectionException`. Both are thrown synchronously, so existing try-catch patterns remain compatible.

