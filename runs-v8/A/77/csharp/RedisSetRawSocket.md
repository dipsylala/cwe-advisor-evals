## Verdict
CWE-77 command injection confirmed. The `statusMessage` parameter is user-controlled and concatenated directly into a Redis command sent over a raw socket without validation, allowing protocol-level injection via embedded CRLF sequences.

## Source
Line 27 constructs the command by concatenating untrusted input:
```
string command = "SET " + redisKey + " " + statusMessage + "\r\n";
```

The `statusMessage` comes from form input and reaches the socket sink (line 31) without filtering or escaping. An attacker can inject arbitrary Redis commands by including `\r\n` in the input (e.g., `hello\r\nFLUSHDB`), which breaks out of the SET command and executes additional commands.

## Fix
Validate the `statusMessage` and `userId` to reject embedded CRLF characters. Additionally, switch from naive string concatenation to the Redis Serialization Protocol (RESP) bulk string format, which uses length-prefixing to make embedded control characters harmless:

```csharp
using System;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly Socket _redisSocket;

    public PresenceController(Socket redisSocket)
    {
        _redisSocket = redisSocket;
    }

    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        if (string.IsNullOrEmpty(statusMessage))
            return BadRequest("Missing statusMessage");

        // Validate userId: reject CRLF and other control characters
        if (userId.Contains("\r") || userId.Contains("\n"))
            return BadRequest("Invalid userId");

        // Validate statusMessage: reject CRLF and other control characters
        if (statusMessage.Contains("\r") || statusMessage.Contains("\n"))
            return BadRequest("Invalid statusMessage");

        string redisKey = "presence:" + userId;
        
        // Use RESP protocol with bulk strings: *3\r\n$3\r\nSET\r\n${keyLen}\r\n{key}\r\n${valueLen}\r\n{value}\r\n
        // Length-prefixing prevents embedded CRLF from breaking command boundaries
        string respCommand = BuildRespCommand("SET", redisKey, statusMessage);
        byte[] payload = Encoding.ASCII.GetBytes(respCommand);

        _redisSocket.Send(payload);

        return Ok();
    }

    private static string BuildRespCommand(params string[] args)
    {
        var sb = new StringBuilder();
        
        // Array header: *{count}\r\n
        sb.Append($"*{args.Length}\r\n");
        
        // Bulk string for each argument: ${length}\r\n{data}\r\n
        foreach (var arg in args)
        {
            sb.Append($"${arg.Length}\r\n");
            sb.Append(arg);
            sb.Append("\r\n");
        }
        
        return sb.ToString();
    }
}
```

## Explanation
The fix uses two complementary defences:

1. **Input validation**: Rejects any `userId` or `statusMessage` containing carriage return or line feed characters, preventing the most direct attack vector.

2. **Protocol-safe formatting**: Switches from inline command concatenation to the RESP (Redis Serialization Protocol) bulk string format. In RESP, bulk strings are prefixed with their byte length (`$13\r\nmy status\r\n`), which means the parser knows exactly how many bytes to consume regardless of their content. This eliminates the ability of embedded CRLF characters to break command boundaries, even if validation is somehow bypassed.

The `BuildRespCommand` helper constructs proper RESP array syntax (`*N` for N arguments, then each argument as a length-prefixed bulk string). This is the standard protocol-level protection against injection when transmitting untrusted data over Redis connections.
