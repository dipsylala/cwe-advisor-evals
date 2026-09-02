## Verdict

Command injection via untrusted input in a Redis inline-protocol command string. The vulnerability is confirmed and exploitable.

## Source

**File:** RedisMultiArgRawSocket.cs, line 18–29

**Untrusted input:** `agentNote` parameter, documented as "coming straight from the support ticket form and is never validated before this call"

**Data flow:**
1. Untrusted `agentNote` is concatenated directly into a command string (line 22: `"HSET session:" + sessionId + " note " + agentNote + " updated " + updatedAt + "\r\n"`)
2. The assembled string is encoded to bytes and sent via `_redisSocket.Send()` (line 29)
3. Redis's inline protocol treats `\r\n` as a command terminator, so a payload like `"foo\r\nFLUSHALL\r\n"` splits into two commands

**Sink:** `Socket.Send(payload)` on line 29, which transmits the untrusted command to the Redis server for execution

## Fix

Replace hand-built Redis command string with StackExchange.Redis's parameterized API. The `HashSet` method uses RESP (Redis Serialization Protocol) with length-prefixed arguments, preventing newline injection.

**Fixed code:**

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IDatabase _redisDb;

        public SessionNoteWriter(IDatabase redisDb)
        {
            _redisDb = redisDb;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            // Use StackExchange.Redis parameterized API to prevent command injection.
            // HashSet frames each argument with length encoding, preventing CRLF injection.
            _redisDb.HashSet(
                key: $"session:{sessionId}",
                hashFields: new[] {
                    new HashEntry("note", agentNote),
                    new HashEntry("updated", updatedAt.ToString())
                });
        }
    }
}
```

**Dependency:** StackExchange.Redis (NuGet package)

## Explanation

The vulnerable code bypasses Redis's client library and builds commands manually by string concatenation, which exposes the inline protocol's metacharacters (especially `\r\n`) to untrusted input. An attacker who controls `agentNote` can inject `\r\nFLUSHALL\r\n` (or any Redis command) to execute arbitrary operations on the database.

The fix uses StackExchange.Redis's `IDatabase.HashSet()` method, which:
1. Encodes each hash field and value using RESP, which prefixes each argument with its byte length (`$8\r\nNote text\r\n`)
2. Prevents embedded delimiters from being parsed as command boundaries
3. Eliminates the need to manually build or escape the wire protocol

The constructor injection of `IDatabase` (instead of `Socket`) shifts control to the StackExchange.Redis connection manager, which handles framing and protocol compliance. This also improves testability and error handling compared to raw socket manipulation.

## Behaviour changes

- **Input handling:** Untrusted values are now passed as discrete RESP-encoded arguments rather than concatenated into a raw command string.
- **Return value:** `HashSet` returns a `bool` indicating success; the original `Send` returned an `int` (bytes sent) which was ignored. The new code also ignores the return value (no change in behavior).
- **Error handling:** Network or protocol errors now surface as StackExchange.Redis exceptions (e.g., `RedisConnectionException`, `RedisServerException`) rather than generic `SocketException`. Callers must handle these if needed.
- **Constructor dependency:** The class now depends on `IDatabase` (from StackExchange.Redis) instead of `Socket`. This requires refactoring the caller to inject a Redis connection: `var connection = ConnectionMultiplexer.Connect("localhost:6379"); var db = connection.GetDatabase(); var writer = new SessionNoteWriter(db);`
- **Compatibility:** The Redis operation is functionally equivalent (stores two hash fields under the same key) but uses the typed client library API instead of raw inline protocol.
