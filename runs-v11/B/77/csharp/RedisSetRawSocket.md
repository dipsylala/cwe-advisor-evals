## Verdict

**Confirmed.** The `statusMessage` parameter is concatenated directly into a Redis inline-protocol command string without parameterization. An attacker can inject CRLF sequences (e.g., `\r\nFLUSHALL\r\n`) to execute arbitrary Redis commands on the shared socket.

## Source

Line 21: `statusMessage` is untrusted user input from the HTTP request.

Line 27–28: The value is concatenated directly into an inline-protocol Redis command:
```
string command = "SET " + redisKey + " " + statusMessage + "\r\n";
byte[] payload = Encoding.ASCII.GetBytes(command);
```

Line 31: The raw command string is sent directly over an unparameterized `Socket.Send()` call.

## Fix

Replace the raw `Socket` and inline-protocol string building with StackExchange.Redis's typed API, which encodes each argument with a length prefix so embedded delimiters cannot be read as a new command. Modify the constructor to accept an `IConnectionMultiplexer` instead of a raw socket, and use `IDatabase.StringSet()` to pass the value as a separate argument:

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
    private readonly IDatabase _redis;

    public PresenceController(IConnectionMultiplexer redisConnection)
    {
        _redis = redisConnection.GetDatabase();
    }

    // Updates a user's presence status ("away", "busy", custom message) by
    // using the typed Redis client API.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        
        // Use parameterized API: argument is passed as a separate element,
        // not concatenated into the command string. CRLF and spaces in
        // statusMessage are encoded with a length prefix and cannot split
        // into a separate command.
        _redis.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The fix replaces hand-built inline-protocol commands with StackExchange.Redis's `StringSet()` method, which uses RESP (Redis Serialization Protocol). In RESP, each argument is preceded by an explicit length prefix (e.g., `$20\r\nuser-supplied-value\r\n`), so a value containing CRLF or spaces cannot be parsed as a command boundary. The untrusted `statusMessage` is now passed as a structured argument, not concatenated into a raw string. An attacker's injection attempts become literal data stored in Redis.

## Behaviour changes

- The `PresenceController` now depends on `IConnectionMultiplexer` (injected at construction) instead of a bare `Socket`. Register `IConnectionMultiplexer` in the application's dependency container (e.g., in `Program.cs` or `Startup.cs`) using `services.AddSingleton(ConnectionMultiplexer.Connect(redisConnectionString))`.
- The `UpdateStatus` method no longer builds or sends raw command strings; it calls `StringSet()` which handles connection pooling and error handling internally.
- Return values and error behaviour are unchanged: a successful SET still returns `Ok()`, and any Redis connection failure will raise an exception (which the application's middleware can handle).
- Legitimate input containing spaces, newlines, or Redis command names (e.g., `"away (brb FLUSHALL)"`) is now stored as literal data rather than interpreted as a command.
