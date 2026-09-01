## Verdict

Exploitable. The untrusted `userId` and `statusMessage` parameters reach a raw Redis inline-protocol sink via string concatenation without parameterization. An attacker can inject `\r\n` to create additional Redis commands.

## Source

- `userId`: HTTP route parameter (untrusted)
- `statusMessage`: HTTP form input (untrusted)
- Sink: `Socket.Send(payload)` at line 31
- Unsafe pattern: Raw Redis inline-protocol command built by concatenation at line 27

## Fix

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
    private readonly IDatabase _redisDb;

    public PresenceController(IConnectionMultiplexer redis)
    {
        _redisDb = redis.GetDatabase();
    }

    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        // Validate inputs to constrain injection surface as defence-in-depth
        if (userId.Length > 256 || !System.Text.RegularExpressions.Regex.IsMatch(userId, @"^[a-zA-Z0-9._-]+\z"))
            return BadRequest("Invalid userId format");

        if (statusMessage.Length > 4096)
            return BadRequest("Status message too long");

        string redisKey = "presence:" + userId;

        // Use parameterized API: StringSet encodes arguments with length prefixes,
        // so embedded CRLF cannot split into a new command
        _redisDb.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The original code built a raw Redis inline-protocol command by string concatenation. The inline protocol is line-oriented and treats `\r\n` as a command terminator; a newline in `statusMessage` or `userId` splits the input into multiple commands. StackExchange.Redis's `StringSet()` method uses the RESP protocol instead, which encodes each argument with an explicit byte-length prefix. This framing makes it impossible for embedded delimiters to be interpreted as command separators.

The constructor now receives `IConnectionMultiplexer` instead of a raw `Socket`, and retrieves an `IDatabase` to issue typed commands. Validation on `userId` (character set and length) and `statusMessage` (length) provides defence-in-depth.

## Behaviour changes

- Dependency change: requires StackExchange.Redis (no version constraint; confirm latest against SCA tooling before merging)
- Constructor parameter type changed from `Socket` to `IConnectionMultiplexer`
- Return type of the operation is implicit (no longer returns the byte count from `Socket.Send()`, which was discarded anyway)
- Input validation added: userId restricted to `[a-zA-Z0-9._-]`, max 256 chars; statusMessage max 4096 chars (rejection returns HTTP 400)
- Redis connection now uses RESP protocol (type-safe, more efficient, standard practice) instead of inline protocol
