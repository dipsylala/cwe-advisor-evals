## Verdict

Exploitable. The untrusted input `agentNote` is concatenated directly into a Redis command string built using the inline protocol and sent over a raw socket without any escaping or framing. An attacker can inject embedded CRLF sequences to split the command and execute arbitrary Redis commands.

## Source

The `agentNote` parameter passed to `SaveAgentNote()` originates from an untrusted source (support ticket form, never validated). It flows into the command string construction on line 23 via string concatenation.

## Fix

### File: RedisMultiArgRawSocket.cs

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IDatabase _database;

        public SessionNoteWriter(IDatabase database)
        {
            _database = database;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string key = "session:" + sessionId;
            
            _database.HashSet(key, new[]
            {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt)
            });
        }
    }
}
```

## Explanation

The fix replaces the vulnerable raw socket and inline-protocol string concatenation with StackExchange.Redis, a well-maintained client library that properly encodes Redis commands using the RESP (Redis Serialization Protocol). Instead of building a command string like `"HSET session:xxx note <agentNote> updated <timestamp>\r\n"`, the fix uses the typed `IDatabase.HashSet()` method and passes the untrusted values (`agentNote` and `updatedAt`) as separate array elements in a `HashEntry[]`. RESP encodes each field and value with an explicit length prefix, so an embedded CRLF in `agentNote` cannot be interpreted as a command delimiter or terminator. The attacker-supplied data is treated as literal hash field values, not as part of the protocol syntax. The `sessionId` is used to construct the hash key name (`"session:" + sessionId`), which is safe because it determines the target key, not the protocol framing.

## Behaviour changes

The constructor signature changes from accepting a `Socket` to accepting an `IDatabase`. This is a breaking change to the public API, but it is required to use a safe client library. The caller must now pass an `IDatabase` instance from StackExchange.Redis instead of a raw socket. The return value of `SaveAgentNote()` remains `void`, and no output is discarded. The original code's `Socket.Send()` returned the number of bytes sent, but that return value was not used by the caller; the `HashSet()` method returns a boolean indicating success, which is similarly not consumed here. This is safe to apply without verifying callers of this method—the build will fail at the call sites, forcing them to be updated to provide the correct dependency.
