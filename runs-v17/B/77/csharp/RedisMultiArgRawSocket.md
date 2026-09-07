## Verdict

exploitable

## Source

`agentNote` parameter in `SaveAgentNote()` method (line 18) - untrusted user input from support ticket form, passed without validation or sanitization.

## Fix

### File: RedisMultiArgRawSocket.cs

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IConnectionMultiplexer _redis;

        public SessionNoteWriter(IConnectionMultiplexer redis)
        {
            _redis = redis;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            var db = _redis.GetDatabase();
            var key = "session:" + sessionId;
            
            // Pass each argument as a separate array element in RESP protocol.
            // Embedded CRLF, spaces, or command names in agentNote are now
            // length-prefixed and treated as literal data, not delimiters.
            var args = new RedisValue[]
            {
                key,
                "note",
                agentNote,
                "updated",
                updatedAt
            };
            
            db.Execute("HSET", args);
        }
    }
}
```

## Explanation

The original code built a raw Redis inline-protocol command via string concatenation, which is vulnerable to command injection when untrusted input (`agentNote`) contains newline characters. An attacker could inject `\r\nFLUSHALL\r\n` to terminate the HSET command and execute additional commands.

The fix replaces the raw `Socket` communication with StackExchange.Redis's `IConnectionMultiplexer` and `IDatabase.Execute()` API. The safe pattern passes each command argument as a separate array element rather than concatenating them into a single string. StackExchange.Redis encodes the command using the RESP protocol, which prefixes each argument with its byte length. This length prefix ensures that embedded newlines, spaces, or Redis command keywords in the argument data are treated as literal bytes, not delimiters or new commands. The `sessionId` remains server-controlled (a GUID), and the `agentNote` and `updatedAt` are passed as data arguments where they cannot be interpreted as commands.

## Behaviour changes

1. **Dependency added**: `StackExchange.Redis` NuGet package. No minimum version is specified by the guidance; SCA tooling must confirm the resolved version against security advisories.

2. **Constructor parameter changed**: Takes `IConnectionMultiplexer redis` instead of `Socket redisSocket`. Callers must provide a configured Redis connection multiplexer instance.

3. **Return value not captured**: The original `Socket.Send()` returned bytes sent (int); `IDatabase.Execute()` returns `RedisResult`. The original code ignored the return value, so this does not affect behavior. Callers that need to inspect the result must update to use `RedisResult` properties.

4. **Exception types changed**: The original code could throw `SocketException` or `ObjectDisposedException`. The new code throws `RedisConnectionException` or other `RedisException` subclasses on connection/timeout errors. Callers with exception-handling logic must account for these new types.

5. **Protocol change**: Raw inline protocol replaced with RESP (the StackExchange.Redis standard protocol). This is required for the fix and has no functional impact—the same HSET operation executes and produces the same result.
