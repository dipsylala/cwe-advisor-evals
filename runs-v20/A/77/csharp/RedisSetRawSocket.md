## Verdict

Confirmed. `UpdateStatus` builds a Redis inline command by string-concatenating attacker-controlled `userId` and `statusMessage` directly into the wire payload, then writes it straight to the shared Redis socket.

## Source

`userId` (query/route-bound parameter) and `statusMessage` (`[FromForm] string statusMessage`) on `PresenceController.UpdateStatus`, both taken from the incoming HTTP request with no restriction on content.

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
        byte[] payload = BuildRespCommand("SET", redisKey, statusMessage ?? string.Empty);

        _redisSocket.Send(payload);

        return Ok();
    }

    // Encodes a Redis command using the RESP multi-bulk protocol, where each
    // argument is framed by its exact byte length rather than delimited by
    // scanning for spaces or CRLF. Because Redis reads exactly the declared
    // number of bytes for each bulk string, a CR, LF, or space embedded in
    // userId or statusMessage becomes inert data inside that argument instead
    // of terminating the command early and letting the remaining bytes be
    // parsed as one or more additional, attacker-chosen Redis commands.
    private static byte[] BuildRespCommand(params string[] args)
    {
        var builder = new StringBuilder();
        builder.Append('*').Append(args.Length).Append("\r\n");
        foreach (var arg in args)
        {
            int byteLength = Encoding.UTF8.GetByteCount(arg);
            builder.Append('$').Append(byteLength).Append("\r\n");
            builder.Append(arg).Append("\r\n");
        }
        return Encoding.UTF8.GetBytes(builder.ToString());
    }
}
```

## Explanation

The original code assembled a Redis "inline command" by concatenating literal text: `"SET " + redisKey + " " + statusMessage + "\r\n"`. Redis's inline protocol splits a command into arguments on whitespace and terminates it on `\r\n`. Because `statusMessage` (and, through `userId`, `redisKey`) flowed into that string unescaped, an attacker could submit a value containing its own `\r\n` sequence followed by arbitrary text - for example a `statusMessage` of `ok\r\nFLUSHALL\r\n` - and have that text parsed by Redis as one or more independent commands appended after the intended `SET`, on the same shared connection used for other users' presence data. A value containing spaces would also silently shift how many arguments `SET` receives.

The fix keeps the same raw-socket, RESP-over-TCP design (no new client library, no behavior change for well-formed input) but switches the framing from delimiter-based ("read until whitespace/CRLF") to length-prefixed RESP multi-bulk encoding, which is the format every real Redis client library uses under the hood. Each argument is sent as `$<byte-length>\r\n<argument-bytes>\r\n`, so Redis reads exactly the declared number of bytes for that argument regardless of what those bytes contain. A `\r\n`, space, or any other control character inside `userId` or `statusMessage` is therefore consumed as literal argument data, not as a delimiter, and cannot cause the parser to see additional commands or a different argument count. This closes the injection at the protocol-framing layer rather than by trying to blocklist or strip specific characters from the input, so it does not reject legitimate presence messages that happen to contain punctuation, newlines, or unusual text.
