## Verdict

CWE-77 command injection confirmed. The `statusMessage` parameter from user input is concatenated directly into a Redis protocol command without proper encoding, allowing an attacker to inject additional Redis commands by including carriage returns and newlines in the message.

## Source

```csharp
[HttpPost("status")]
public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
{
    if (string.IsNullOrEmpty(userId))
        return BadRequest("Missing userId");

    string redisKey = "presence:" + userId;
    string command = "SET " + redisKey + " " + statusMessage + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    _redisSocket.Send(payload);

    return Ok();
}
```

Line 31 (`_redisSocket.Send(payload)`) is the sink; the vulnerability stems from line 27 where the command string is constructed via unsafe concatenation.

## Fix

### File: RedisSetRawSocket.cs

```csharp
using System;
using System.Collections.Generic;
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
        
        // Use RESP (Redis Serialization Protocol) array format to safely encode the command.
        // This prevents command injection by using length-prefixed values.
        byte[] payload = EncodeRespArray(new List<string> { "SET", redisKey, statusMessage });

        _redisSocket.Send(payload);

        return Ok();
    }

    /// <summary>
    /// Encodes a list of strings as a RESP array.
    /// Format: *<count>\r\n$<length>\r\n<data>\r\n...
    /// </summary>
    private static byte[] EncodeRespArray(List<string> elements)
    {
        var result = new StringBuilder();
        
        // Array header: *<count>\r\n
        result.AppendFormat("*{0}\r\n", elements.Count);
        
        // Encode each element as a bulk string: $<length>\r\n<data>\r\n
        foreach (var element in elements)
        {
            var bytes = Encoding.UTF8.GetBytes(element);
            result.AppendFormat("${0}\r\n", bytes.Length);
            result.Append(element);
            result.Append("\r\n");
        }
        
        return Encoding.UTF8.GetBytes(result.ToString());
    }
}
```

## Explanation

The vulnerability exists because string concatenation allows an attacker to inject newlines and additional Redis commands. For example, a statusMessage of `"hello\r\nDEL presence:user1\r\n"` would result in two commands being sent: SET and DEL.

The fix uses proper RESP (Redis Serialization Protocol) array encoding with length prefixes. In RESP, each element is prefixed with its byte length (`$<length>\r\n<data>\r\n`), making the protocol structure independent of the content. The newlines in user input become part of the encoded data itself, not protocol delimiters, so they cannot break out of the current command.

The `EncodeRespArray` helper method constructs the array format: `*3\r\n$3\r\nSET\r\n$<length>\r\n<key>\r\n$<length>\r\n<value>\r\n`. This encoding is the standard, safe way to send commands over the Redis wire protocol and is immune to injection through special characters in values.
