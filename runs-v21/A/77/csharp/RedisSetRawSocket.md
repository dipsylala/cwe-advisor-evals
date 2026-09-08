## Verdict
CONFIRMED. The code concatenates user-supplied `userId` and `statusMessage` directly into a Redis command without escaping. An attacker can inject arbitrary Redis commands by providing input containing RESP protocol delimiters (`\r\n`).

## Source
Line 21: `statusMessage` parameter from HTTP form input.
Line 26: `userId` parameter from HTTP query/route, both concatenated into the command string.

## Fix

### File: RedisSetRawSocket.cs
```csharp
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

    // Updates a user's presence status ("away", "busy", custom message) by
    // writing directly to the Redis wire protocol on the shared socket.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        
        // Use RESP (Redis Serialization Protocol) to safely serialize the command.
        // Length-prefixed strings prevent injection: data is read by byte count,
        // not by delimiter, so embedded \r\n characters are treated as data, not separators.
        string respCommand = BuildRespCommand("SET", redisKey, statusMessage);
        byte[] payload = Encoding.ASCII.GetBytes(respCommand);

        _redisSocket.Send(payload);

        return Ok();
    }

    private string BuildRespCommand(params string[] args)
    {
        StringBuilder sb = new StringBuilder();
        sb.Append($"*{args.Length}\r\n");
        foreach (string arg in args)
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
The vulnerable code builds a raw Redis command by string concatenation, treating the entire input as part of the command syntax. If `statusMessage` contains `\r\n` (RESP delimiter), it splits the command into multiple instructions—an attacker providing `"foo\r\nDEL *"` executes both a SET and a DEL.

The fix uses RESP array serialization: `*3\r\n$3\r\nSET\r\n$<key_len>\r\n<key>\r\n$<value_len>\r\n<value>\r\n`. Each argument is length-prefixed (`$<length>\r\n`), so Redis reads exactly that many bytes. Embedded delimiters in `statusMessage` or `userId` are treated as literal data, not command structure. This closes the injection sink by separating data from protocol.
