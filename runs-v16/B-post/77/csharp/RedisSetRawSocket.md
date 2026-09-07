## Verdict

Confirmed. Untrusted HTTP form input (`statusMessage`) flows directly into a hand-built Redis inline-protocol command string without framing or parameterization. An attacker can inject CRLF sequences to split the command and execute arbitrary Redis commands (e.g., `FLUSHALL`, key deletion).

## Source

Line 27 concatenates `statusMessage` into the command string: `"SET " + redisKey + " " + statusMessage + "\r\n"`. This string is then encoded and sent via raw socket at line 31. The untrusted input reaches the Redis protocol interpreter unchanged, with no length framing or delimiter escaping.

## Fix

Replace raw socket manipulation and string concatenation with StackExchange.Redis's typed API, which frames each argument with an explicit length prefix. In the fixed code:

```csharp
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IConnectionMultiplexer _redis;

    public PresenceController(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // using StackExchange.Redis's parameterized API.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        // Bound the input size as defence-in-depth
        if (statusMessage.Length > 1000)
            return BadRequest("Status message exceeds maximum length");

        string redisKey = "presence:" + userId;
        
        var db = _redis.GetDatabase();
        // Safe: statusMessage is passed as a separate argument, RESP-framed with length prefix
        db.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

The key changes:
- Inject `IConnectionMultiplexer` (configured elsewhere in DI) instead of a raw `Socket`.
- Use `db.StringSet(redisKey, statusMessage)` instead of hand-building the command string.
- Add length validation on `statusMessage` as defence-in-depth.

StackExchange.Redis (package `StackExchange.Redis`, version 2.6.0 or later) is the de facto standard client and is actively maintained. The minimum version carries no known CVEs related to command injection.

## Explanation

StackExchange.Redis uses RESP (Redis Serialization Protocol), which encodes each argument with an explicit length prefix (e.g., `$5\r\nvalue\r\n`). This framing means the value's content—including CRLF, spaces, and Redis command names—cannot be misinterpreted as protocol delimiters or new commands. The inline-protocol string concatenation does not provide this protection; it treats CRLF as a command terminator, so `value\r\nFLUSHALL\r\n` becomes two separate commands.

By moving from raw socket I/O to the library's typed API, the fix also eliminates the responsibility of manually encoding/decoding the protocol, reducing the surface for future mistakes. The length bound on `statusMessage` is a secondary control: even with RESP framing, rejecting unexpectedly large inputs limits resource exhaustion and provides a checkpoint for anomaly logging.

## Behaviour changes

- **Wire protocol**: Changes from inline protocol (CRLF-delimited lines, space-separated tokens) to RESP (length-prefixed bulk strings). Redis servers support both, but the payload bytes and framing structure differ.
- **Encoding**: Assumes UTF-8 by default; StackExchange.Redis encodes strings to UTF-8 bytes before transmission. If the original code used a different encoding (e.g., ASCII for control characters), verify the server's encoding expectations.
- **Error handling**: The original code's `Send()` succeeds silently or throws `SocketException` on network failure. StackExchange.Redis's `StringSet()` throws `RedisConnectionException` on connection loss and `RedisServerException` if the server rejects the command (e.g., out of memory). Wrap the call in a try-catch if graceful degradation is required.
- **Connection management**: The original code reused a single shared socket. StackExchange.Redis manages a connection pool internally; ensure the `IConnectionMultiplexer` is registered as a singleton in dependency injection and disposed when the application shuts down.
