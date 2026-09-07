## Verdict

Exploitable.

## Source

`statusMessage` parameter from HTTP form input (`[FromForm] string statusMessage` at line 21).

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
    private readonly IConnectionMultiplexer _redis;

    public PresenceController(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // writing to Redis using the StackExchange.Redis parameterized API.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        IDatabase db = _redis.GetDatabase();
        
        // Use StringSet with separate key and value parameters - StackExchange.Redis
        // encodes each argument with explicit length prefix in RESP protocol,
        // preventing CRLF injection from untrusted statusMessage
        db.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The original code built a Redis inline-protocol command by concatenating user input directly into a command string, then sent it over a raw socket. Redis's plain-text inline protocol is CRLF-delimited, so a statusMessage containing `\r\n` would terminate the current command and inject a new one—for example, `value\r\nFLUSHALL\r\n` would execute `FLUSHALL` as a separate command.

The fix replaces the raw socket with StackExchange.Redis's `IConnectionMultiplexer` and uses the typed `StringSet()` method. StackExchange.Redis uses the RESP protocol, which encodes each argument with an explicit length prefix independent of its content. This framing prevents embedded delimiters—including CRLF, spaces, and Redis command names—from being interpreted as command structure. The statusMessage is now a separate typed parameter passed to `StringSet()`, guaranteed to be stored as data only, never as command syntax.

## Behaviour changes

**Return value**: `Socket.Send()` returns an `int` (bytes sent); `IDatabase.StringSet()` returns a `bool` (success/failure). The original code did not use the return value, so this is not a functional change to the caller.

**Dependency**: Requires StackExchange.Redis NuGet package (any maintained recent version; no specific CVE-dependent floor applies). The ASP.NET Core DI container must be configured to inject `IConnectionMultiplexer`, typically via `services.AddStackExchangeRedisCache()` or direct `IConnectionMultiplexer` registration.

**Error handling**: `StringSet()` can raise `TimeoutException` or `RedisConnectionException` on network/timeout issues. The original `Socket.Send()` raises `SocketException`. For this use case (presence updates), an unhandled exception will result in a 500 error, which is acceptable; if the application needs explicit error handling, catch `RedisException` and return an appropriate HTTP error response.

