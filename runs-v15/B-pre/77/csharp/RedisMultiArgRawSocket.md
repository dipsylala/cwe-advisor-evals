## Verdict

CONFIRMED - CWE-77 command injection in the Redis inline protocol.

## Source

`agentNote` parameter at line 18 receives untrusted input directly from the support ticket form without validation.

## Fix

Replace hand-built inline-protocol string concatenation with StackExchange.Redis's `IDatabase.Execute()` method, passing arguments as a separate array. This moves from the plain-text Redis inline protocol (which treats `\r\n` as a command separator) to the RESP protocol (which encodes each argument with a length prefix, preventing delimiter injection).

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IDatabase _redisDb;

        public SessionNoteWriter(IConnectionMultiplexer redis)
        {
            _redisDb = redis.GetDatabase();
        }

        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            _redisDb.Execute("HSET", new object[] {
                "session:" + sessionId,
                "note",
                agentNote,
                "updated",
                updatedAt.ToString()
            });
        }
    }
}
```

## Explanation

The original code concatenates untrusted `agentNote` into a Redis inline-protocol command string. The inline protocol uses `\r\n` as the command terminator, so a payload like `value\r\nFLUSHALL\r\n` is split into two separate commands by the Redis server.

The fix uses `IDatabase.Execute()` with arguments passed as separate array elements. StackExchange.Redis encodes these using the RESP (Redis Serialization Protocol), which prefixes each argument with its byte length. This length-prefixed framing means embedded newlines in `agentNote` are stored as literal data, not interpreted as command boundaries.

The constructor now takes an `IConnectionMultiplexer` instead of a raw `Socket`, and `GetDatabase()` returns a typed connection that handles protocol framing automatically.

## Behaviour changes

- Input containing `\r\n`, spaces, or Redis command names is now stored as literal field values in the hash, not executed as additional commands
- The RESP protocol replaces the plain-text inline protocol, providing stronger delimiter safety by design
- The connection is managed by StackExchange.Redis's connection pooling and health checking, rather than a bare socket
