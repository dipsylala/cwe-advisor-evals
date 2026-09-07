## Verdict

Real issue. Untrusted user input (`agentNote`) is concatenated directly into a Redis command string sent over a raw socket using the inline protocol, which treats `\r\n` as a command separator. An attacker can inject arbitrary Redis commands by including a newline in the note text.

## Source

**File**: RedisMultiArgRawSocket.cs, line 29  
**Sink**: `_redisSocket.Send(payload)` with hand-built inline-protocol command string  
**Untrusted input**: `agentNote` parameter (line 18), documented as unvalidated user input from a support ticket form  
**Vulnerable pattern**: String concatenation (lines 21–25) building a raw Redis command, then sending bytes directly to socket (line 29)

## Fix

### File: RedisMultiArgRawSocket.cs

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
            string key = "session:" + sessionId;
            
            _redisDb.HashSet(key, new HashEntry[] {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt.ToString())
            });
        }
    }
}
```

## Explanation

The fix replaces manual command string construction over a raw socket with StackExchange.Redis's parameterized `IDatabase.HashSet()` API. The original code built the command as inline-protocol text: `HSET session:{sessionId} note {agentNote} updated {updatedAt}\r\n`. This format uses whitespace and CRLF delimiters that an attacker can inject through the `agentNote` field.

StackExchange.Redis uses RESP (REdis Serialization Protocol), which encodes each argument with an explicit byte-length prefix. The `HashSet()` method with a `HashEntry[]` array passes each field-value pair as a separate, length-delimited argument. Even if `agentNote` contains `\r\n`, spaces, or Redis command keywords like `FLUSHALL`, they are transmitted as literal data within the delimited argument block and cannot be parsed as a new command.

The constructor signature changes from `Socket` to `IDatabase` to make the safe API explicit; callers would instantiate an `IConnectionMultiplexer` (e.g., via `ConnectionMultiplexer.Connect()`) and pass `multiplexer.GetDatabase()`.

## Behaviour changes

- **Wire protocol**: Switches from Redis inline protocol (text-based, space/CRLF delimited) to RESP (length-prefixed binary arguments). The server behavior is identical; the protocol is more robust.
- **Error handling**: `HashSet()` throws `RedisConnectionException` or related StackExchange.Redis exceptions on failure (matching the socket's ability to throw `SocketException`). No change in error-handling requirements.
- **Return value**: `HashSet()` returns `bool` or `long` (depending on overload); the original code discards the return, so this is safe.
- **No loss of functionality**: The fix preserves the exact same data model—two fields (`note` and `updated`) in a hash at key `session:{sessionId}`.
