## Verdict

Confirmed. `SaveAgentNote` builds a Redis inline-protocol command by concatenating `sessionId`, `agentNote`, and `updatedAt` into one string and writes it directly to a raw `Socket`. `agentNote` is unvalidated support-ticket text; a value containing `\r\n` terminates the `HSET` command early and starts a new one on the same connection (RESP inline-command injection), for example setting `note` to a value and then issuing an arbitrary follow-on command such as `FLUSHALL`.

## Source

`agentNote` parameter of `SessionNoteWriter.SaveAgentNote(string sessionId, string agentNote)` - per the existing comment, it "comes straight from the support ticket form and is never validated before this call." It flows unchanged into the concatenated `command` string.

## Fix

### File: RedisMultiArgRawSocket.cs

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IDatabase _redisDatabase;

        public SessionNoteWriter(IDatabase redisDatabase)
        {
            _redisDatabase = redisDatabase;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            _redisDatabase.HashSet("session:" + sessionId, new HashEntry[]
            {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt)
            });
        }
    }
}
```

## Explanation

The sink was a hand-built RESP inline command (`"HSET session:" + sessionId + " note " + agentNote + " updated " + updatedAt + "\r\n"`) written straight to the socket, so any CRLF or extra whitespace in `agentNote` is interpreted by Redis as a command boundary rather than as data. The fix replaces the raw socket and string-building with StackExchange.Redis, the maintained client library the C# guidance for this CWE names, and its typed `IDatabase.HashSet(RedisKey, HashEntry[])` method. `HashSet` sends `HSET` using RESP's length-prefixed argument framing: each `HashEntry` value is transmitted with an explicit byte length, so an embedded `\r\n` or space in `agentNote` is carried as literal bytes inside that one argument and cannot be read as a command separator or start a second command. `sessionId` is concatenated into the key locally (`"session:" + sessionId`) rather than passed through `args`, but the code's own comment establishes it as a server-generated GUID, not attacker-controlled input, so it is not the value the fix needs to isolate. This is guidance naming a specific library, not a live vulnerability scan: the minimum safe StackExchange.Redis version needs to come from SCA/dependency-check tooling before merging, since the loaded guidance does not carry a version floor for the base package itself.

## Behaviour changes

- The constructor's parameter changes from a raw `Socket` to a StackExchange.Redis `IDatabase` (typically obtained via `ConnectionMultiplexer.Connect(...).GetDatabase()`). This is a public API change to `SessionNoteWriter`: every call site that currently constructs it with a `Socket` must be updated to supply an `IDatabase` instead. This is intrinsic to the fix - StackExchange.Redis frames RESP arguments itself, which is what closes the injection, and there is no way to keep constructing this class with a bare `Socket` while gaining that protection.
- The two fields (`note`, `updated`) are now written in a single `HSET` call carrying both `HashEntry` pairs, matching the original command's semantics (both fields set together) instead of two separate round trips.
- `HashSet(RedisKey, HashEntry[], CommandFlags)` returns `void`, the same as the original method's discarded `int` from `Socket.Send` - no return value is newly surfaced.
- Failure behaviour changes from a `SocketException` on a raw socket error to StackExchange.Redis's own exception types (e.g. `RedisConnectionException`, `RedisTimeoutException`) on connection or command failure; neither the original nor the fixed code catches these, so both propagate to the caller.
- Verified by compiling the fixed file with `dotnet build` against a local stub reproducing StackExchange.Redis's public shapes for `IDatabase.HashSet(RedisKey, HashEntry[], CommandFlags)` and `HashEntry(RedisValue, RedisValue)` (no network access in this environment to restore the real NuGet package) - it compiled with 0 errors, confirming the API is called with the correct signature and argument types (`string` to `RedisKey`/`RedisValue`, `long` to `RedisValue` all via documented implicit conversions).
