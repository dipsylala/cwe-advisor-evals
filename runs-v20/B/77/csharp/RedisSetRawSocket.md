## Verdict

exploitable

- cwe_id: CWE-77
- location: RedisSetRawSocket.cs, line 31 (`_redisSocket.Send(payload)`)
- confidence: high

## Source

`UpdateStatus(string userId, [FromForm] string statusMessage)` (lines 21) - both `userId` (query/route-bound) and `statusMessage` (form-bound) are attacker-controlled ASP.NET Core model-bound parameters. Neither is validated or encoded before use.

## Fix

Data flow: `statusMessage` (and `userId`, via `redisKey`) flow unmodified into `command = "SET " + redisKey + " " + statusMessage + "\r\n"` (line 27), which is ASCII-encoded and written verbatim to a raw TCP socket connected to Redis (line 31). Redis's inline command protocol treats `\r\n` as a command terminator, so a `statusMessage` such as `ok\r\nFLUSHALL\r\n` closes the intended `SET` command and injects an arbitrary second Redis command (e.g. `FLUSHALL`, `CONFIG SET`, or a write to an unrelated key) that the server executes with the same privileges as the application's Redis connection.

Sink contract (`Socket.Send(byte[])`):
- Returns: number of bytes sent (`int`) - the original code discards it.
- Discards: the byte count above; no response is read from the socket at all in this method.
- Implicit arguments: none beyond the buffer - `Send` has no framing or escaping of its own.
- Failure behaviour: throws `SocketException` on a socket-level error; nothing in this method depends on that.

Library recommendation: StackExchange.Redis (per `cwe/77/csharp/INDEX.md`). The guidance names no minimum safe version for this specific weakness (the injection is closed by using the typed API, not by a version floor) - confirm the resolved version against SCA/dependency-check tooling before merging. Verified against StackExchange.Redis 2.8.16 (build below).

### File: RedisSetRawSocket.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace PresenceService.Controllers;

[ApiController]
[Route("api/presence")]
public class PresenceController : ControllerBase
{
    private readonly IDatabase _redisDb;

    public PresenceController(IDatabase redisDb)
    {
        _redisDb = redisDb;
    }

    // Updates a user's presence status ("away", "busy", custom message) using
    // StackExchange.Redis's typed StringSet API, which frames the key and
    // value as separate RESP arguments so embedded delimiters cannot be
    // read as a new command.
    [HttpPost("status")]
    public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
    {
        if (string.IsNullOrEmpty(userId))
            return BadRequest("Missing userId");

        string redisKey = "presence:" + userId;
        _redisDb.StringSet(redisKey, statusMessage);

        return Ok();
    }
}
```

## Explanation

The fix replaces the hand-built Redis inline-protocol string and raw `Socket.Send` with StackExchange.Redis's typed `IDatabase.StringSet(key, value)` call, and changes the constructor to depend on `IDatabase` instead of the raw `Socket`. `StringSet` sends the key and value as independently length-prefixed RESP arguments rather than concatenating them into one delimiter-terminated string, so a `statusMessage` (or `userId`) containing `\r\n`, spaces, or Redis command text is transmitted as literal argument data and cannot terminate the `SET` command or start a second one. `redisKey` is still built by concatenation, but it is now bound into the `key` argument position of `StringSet` rather than into a shared command string, so the same framing protects it.

## Behaviour changes

- Constructor parameter changed from `Socket redisSocket` to `IDatabase redisDb`: required because the fix replaces the raw-socket transport entirely; the caller's dependency-injection registration must now supply an `IDatabase` (e.g. from `IConnectionMultiplexer.GetDatabase()`) instead of a connected `Socket`. This is an unavoidable consequence of moving off hand-rolled protocol framing, not incidental scope creep.
- `StringSet` returns `bool` (whether the key was set) instead of `Socket.Send`'s byte count; both return values were, and remain, discarded, so no caller-visible behaviour depends on this.
- Failure mode changes from `SocketException` (raw socket error) to `RedisConnectionException`/`RedisTimeoutException` (StackExchange.Redis's own exceptions on connection failure); nothing in this method currently catches or depends on the specific exception type.
- The method's inline comment was updated to describe the new call instead of the removed raw-socket write; this is a documentation correction tied directly to the changed mechanism.
- No functional change to what is stored: the value written to Redis for key `presence:{userId}` is still `statusMessage`, now delivered as literal data instead of concatenated protocol text.

## Verification

Compiled with `dotnet build` (SDK 10.0.203, targeting `net8.0`) in a scratch project referencing `StackExchange.Redis` 2.8.16, using the fixed file verbatim plus a matching `Microsoft.AspNetCore.Mvc`/`StackExchange.Redis` `using` set - the file was not built inside the case directory. Build succeeded with 0 errors and 0 warnings, confirming `IDatabase.StringSet(RedisKey, RedisValue, ...)` resolves against the named package and the file is otherwise well-formed. `IDatabase` and `StringSet` are named directly in `cwe/77/csharp/INDEX.md`; no other new symbol was introduced.
