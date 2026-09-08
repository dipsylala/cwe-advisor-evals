## Verdict

Exploitable

## Source

`userId` parameter from route/form (untrusted, line 21) and `statusMessage` parameter from form body `[FromForm]` (untrusted, line 21).

## Fix

### File: RedisSetRawSocket.cs

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
    private readonly IDatabase _redisDatabase;

    public PresenceController(IDatabase redisDatabase)
    {
        _redisDatabase = redisDatabase;
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // writing to Redis using the StackExchange.Redis client library.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        
        // Use StackExchange.Redis's typed StringSet method, which handles
        // argument encoding safely. The statusMessage is passed as a separate
        // argument, not concatenated into the command string.
        _redisDatabase.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The vulnerability stems from hand-building a Redis inline protocol command via string concatenation (line 27 of original). If `statusMessage` contains `\r\n` (CRLF), it is interpreted as a command separator, allowing injection of arbitrary Redis commands. For example, `statusMessage` of `"my status\r\nFLUSHALL\r\n"` results in two separate commands being sent: `SET presence:userId my status` and `FLUSHALL`.

The fix replaces raw Socket code with StackExchange.Redis's typed `IDatabase.StringSet()` method, which handles argument encoding safely. The method encodes each argument with an explicit length prefix (using the RESP protocol), preventing embedded delimiters from being interpreted as command separators. The untrusted `statusMessage` value is now passed as a separate argument to the safe API, not concatenated into a command string. StackExchange.Redis is the maintained, standard Redis client library for .NET and is recommended by the CWE-77 C# guidance.

## Behaviour changes

- Dependency injection changed from `Socket _redisSocket` to `IDatabase _redisDatabase`. The controller now depends on the StackExchange.Redis client library's database abstraction rather than a raw socket. This requires the calling code (dependency injection setup) to provide an `IDatabase` instance connected to Redis instead of a raw `Socket`.
- Removed unused `using System.Net.Sockets;` and `using System.Text;` directives (Encoding.ASCII.GetBytes is no longer used).
- Added `using StackExchange.Redis;` directive.
- The `StringSet()` call does not return a value (returns `bool` success indicator), whereas `Socket.Send()` returned the number of bytes sent. The original code at line 31 did not use the return value, so this is not a functional change.
- Error handling is implicit: StackExchange.Redis throws `RedisConnectionException` or `RedisTimeoutException` on connection/timeout issues, where the original `Socket.Send()` would throw `SocketException`. ASP.NET Core's exception handling will convert these to appropriate HTTP error responses.
