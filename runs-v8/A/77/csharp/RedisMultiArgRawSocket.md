## Verdict

**CONFIRMED** — The code constructs a Redis command by string concatenation with unsanitized user input (`agentNote`). An attacker can inject Redis protocol commands by embedding `\r\n` sequences and additional commands to manipulate or delete data.

## Source

**File:** RedisMultiArgRawSocket.cs  
**Lines:** 21-25, 29

The vulnerability is in the command construction:

```
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";

byte[] payload = Encoding.ASCII.GetBytes(command);
_redisSocket.Send(payload);
```

Because `agentNote` comes from user input (support ticket form) without validation, an attacker can include `\r\n` to break out of the current command and inject additional Redis commands.

## Fix

Use the Redis Serialization Protocol (RESP) with proper length-prefixed argument encoding. Each argument is sent as a separate RESP array element, ensuring the parser treats user input as a single value, not as command syntax.

```csharp
using System;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly Socket _redisSocket;

        public SessionNoteWriter(Socket redisSocket)
        {
            _redisSocket = redisSocket;
        }

        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            // Use Redis Serialization Protocol (RESP) to safely encode arguments
            List<string> args = new List<string>
            {
                "HSET",
                "session:" + sessionId,
                "note",
                agentNote,
                "updated",
                updatedAt.ToString()
            };
            
            byte[] payload = BuildRespCommand(args);
            _redisSocket.Send(payload);
        }

        private byte[] BuildRespCommand(List<string> args)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("*").Append(args.Count).Append("\r\n");
            
            foreach (string arg in args)
            {
                byte[] argBytes = Encoding.UTF8.GetBytes(arg);
                sb.Append("$").Append(argBytes.Length).Append("\r\n");
                sb.Append(arg).Append("\r\n");
            }
            
            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
```

## Explanation

The original code treated Redis commands like shell commands—vulnerable to injection when concatenating untrusted input. Redis is a command interpreter that parses the inline protocol, where `\r\n` marks command boundaries.

RESP (Redis Serialization Protocol) is the binary protocol designed to safely encode commands and arguments. Each argument is prefixed with `$` followed by its byte length, then the content. This length boundary ensures the Redis parser reads the exact number of bytes for each argument, preventing `\r\n` sequences in user data from being interpreted as command separators.

The fix isolates each argument (command name, key, field/value pairs) into separate RESP elements, so even if `agentNote` contains `\r\nDEL\r\n`, it is treated as literal data within the `note` field value, not as a new command.

Alternatives (less ideal for raw socket usage):
- Use a managed Redis client library (StackExchange.Redis) that handles RESP encoding automatically
- If raw socket must be used, validate `agentNote` with a strict allowlist, but this is defense-in-depth only—proper encoding is the primary defense

