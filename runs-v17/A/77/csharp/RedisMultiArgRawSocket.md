## Verdict

**CONFIRMED**. The code constructs a Redis command by concatenating user-supplied strings directly into the command buffer. The `agentNote` parameter is unsanitized and embedded directly into the command string at line 22-24. An attacker controlling the note content can inject newlines and additional Redis commands, violating the boundary between command syntax and data.

## Source

The vulnerability occurs in `SaveAgentNote()` at line 21-25, where the HSET command is built using string concatenation:

```csharp
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";
```

The `agentNote` value flows directly from the form without validation and without proper encoding. Any newline, space, or control character in `agentNote` can alter the command structure sent to Redis.

## Fix

### File: RedisMultiArgRawSocket.cs

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

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            
            // Build command using RESP (REdis Serialization Protocol) array format.
            // Each argument is a bulk string with length prefix, preventing injection.
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
            StringBuilder resp = new StringBuilder();
            // RESP array header: *<count>\r\n
            resp.Append("*");
            resp.Append(args.Count);
            resp.Append("\r\n");
            
            // Each argument as a bulk string: $<length>\r\n<value>\r\n
            foreach (string arg in args)
            {
                byte[] argBytes = Encoding.UTF8.GetBytes(arg);
                resp.Append("$");
                resp.Append(argBytes.Length);
                resp.Append("\r\n");
                resp.Append(arg);
                resp.Append("\r\n");
            }
            
            return Encoding.UTF8.GetBytes(resp.ToString());
        }
    }
}
```

## Explanation

Redis commands sent over raw sockets must follow the RESP (REdis Serialization Protocol) specification. The original code violates this by concatenating arguments directly into a space-delimited string, allowing an attacker to inject command delimiters (newlines, spaces) within the `agentNote` value.

The fix builds the command using proper RESP array encoding:
- Commands are structured as arrays prefixed with `*<count>\r\n`
- Each argument is encoded as a bulk string: `$<byte-length>\r\n<value>\r\n`
- Argument values are prefixed with their byte length, establishing a clear boundary
- Even if `agentNote` contains newlines, spaces, or Redis command keywords, they are treated as part of the bulk string value, not command syntax

This approach ensures that only the intended HSET operation executes, with all user-supplied data (sessionId, agentNote, updatedAt) treated as safe data values, not command structure. The length prefix prevents interpretation of special characters as command delimiters.
