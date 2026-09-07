## Verdict
Exploitable

## Source
`agentNote` parameter in `SaveAgentNote(string sessionId, string agentNote)` method - untrusted user input from support ticket form that is never validated before use.

## Fix

**Vulnerable code (line 29):**
```csharp
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";

byte[] payload = Encoding.ASCII.GetBytes(command);
_redisSocket.Send(payload);
```

**Fixed code:**
```csharp
using System;
using System.Net.Sockets;
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
            string key = $"session:{sessionId}";
            
            // Use parameterized API: arguments passed as separate array elements.
            // StackExchange.Redis uses RESP protocol which length-prefixes each argument,
            // preventing embedded CRLF from being interpreted as a command separator.
            _redisDb.HashSet(key, new[]
            {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt)
            });
        }
    }
}
```

## Explanation
The vulnerable code builds a Redis inline-protocol command by string concatenation. An attacker controlling `agentNote` can inject CRLF sequences followed by arbitrary Redis commands - for example, `"foo\r\nFLUSHALL\r\n"` would cause the server to execute both HSET and FLUSHALL. The inline protocol treats each CRLF as a command boundary, making it inherently unsafe for untrusted input.

The fix replaces the raw socket and string building with StackExchange.Redis's `IDatabase.HashSet()` method. This uses RESP (Redis Serialization Protocol) which encodes each argument with an explicit byte-length prefix, so embedded CRLF and other delimiters in `agentNote` are treated as literal data rather than command separators. The command verb (`HSET`) and key remain under application control, while the untrusted value flows through a parameterized argument slot.

## Behaviour changes
**Constructor signature change**: The original constructor accepts `Socket _redisSocket` and stores a raw connection; the fixed constructor accepts `IDatabase _redisDb` and stores a StackExchange.Redis database handle. This requires the caller to provide a connection obtained from StackExchange.Redis's `ConnectionMultiplexer` rather than a raw socket. The `IDatabase` instance is thread-safe and connection-pooling is managed by the library, improving both safety and reliability.

**Return value**: `Socket.Send()` returns the number of bytes sent; `HashSet()` returns a boolean indicating whether the hash field was newly created or updated. The fixed code discards this return value, whereas the original also discarded the byte count. The calling code does not use the return value in either case, so this change is safe.

**Protocol change**: The inline protocol is replaced by RESP. This is transparent to Redis clients and servers supporting both protocols, but any code that attempts to parse the wire traffic directly will need to handle RESP encoding instead of plain text. No such code is present in the provided fixture.

**Import requirement**: The fix adds `using StackExchange.Redis;` to resolve `IDatabase` and `HashEntry`. This requires the StackExchange.Redis NuGet package as a project dependency.
