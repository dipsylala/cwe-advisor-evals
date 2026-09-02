## Verdict

**exploitable** (confidence: high)

`SaveAgentNote` builds a Redis inline-protocol command by string concatenation and writes it directly to a raw `Socket`. `agentNote` is taken verbatim from the support ticket form and is never validated. A value containing `\r\n` terminates the `HSET` command early and starts a new one on the same connection (RESP inline-command injection), so an attacker who controls a ticket note can append arbitrary additional Redis commands (e.g. `\r\nFLUSHALL\r\n` or a second `HSET` against an unrelated key).

`sessionId` is server-generated (a GUID) and is not attacker-controlled, so it is not part of the exploitable path, but it is concatenated into the same string as `agentNote` and is carried along by the fix below for consistency.

## Source

- **Source:** `agentNote` parameter of `SessionNoteWriter.SaveAgentNote(string sessionId, string agentNote)` — per the existing code comment, this "comes straight from the support ticket form and is never validated before this call."
- **Sink:** `_redisSocket.Send(payload)` at line 29, where `payload` is the ASCII bytes of a hand-built Redis inline-protocol string (`"HSET session:" + sessionId + " note " + agentNote + " updated " + updatedAt + "\r\n"`).
- **Data flow:** `agentNote` flows unmodified from the method parameter into string concatenation (lines 21-25), is encoded to bytes (line 27), and is written straight to the socket (line 29) with no delimiter neutralization or use of a framed protocol API in between.

## Fix

**Library recommendation:** replace the raw `Socket` inline-protocol client with **StackExchange.Redis** (NuGet package `StackExchange.Redis`), the standard maintained .NET Redis client, and use its typed/parameterized command API instead of hand-framing RESP. The knowledge base does not carry a minimum-safe-version floor for this package for this specific weakness (the one version detail it records — `RedisCommandException` for a space in the *command name*, from 3.0.17 — does not apply here because the untrusted value is placed in the *argument* position, not the command name). Confirm the resolved package version against SCA/dependency-check tooling before merging.

**Vulnerable code:**

```csharp
using System;
using System.Net.Sockets;
using System.Text;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly Socket _redisSocket;

        public SessionNoteWriter(Socket redisSocket)
        {
            _redisSocket = redisSocket;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string command =
                "HSET session:" + sessionId +
                " note " + agentNote +
                " updated " + updatedAt +
                "\r\n";

            byte[] payload = Encoding.ASCII.GetBytes(command);
            // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
            _redisSocket.Send(payload);
        }
    }
}
```

**Fixed code:**

```csharp
using System;
using StackExchange.Redis;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly IDatabase _redisDb;

        public SessionNoteWriter(IDatabase redisDb)
        {
            _redisDb = redisDb;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            _redisDb.HashSet("session:" + sessionId, new HashEntry[]
            {
                new HashEntry("note", agentNote),
                new HashEntry("updated", updatedAt)
            });
        }
    }
}
```

## Explanation

The fix removes the hand-built RESP inline-protocol string and the raw `Socket.Send` call, and replaces them with StackExchange.Redis's typed `IDatabase.HashSet(key, HashEntry[])` method. `agentNote` is now passed as a distinct `HashEntry` value rather than being concatenated into a command string; StackExchange.Redis frames each argument with an explicit RESP length prefix, so any `\r\n`, spaces, or other bytes inside `agentNote` are transmitted as literal data within that single argument and cannot terminate the command or start a new one. `sessionId` remains concatenated into the hash key string, which is safe here because it is server-generated and not attacker-controlled, and because the key is still delivered as one framed RESP argument rather than being interpreted as protocol syntax. As defence-in-depth, per the loaded guidance, the caller should still validate/bound `agentNote`'s length and character set before this call, and the Redis connection should use an ACL-scoped user rather than an admin-level one.

## Behaviour changes

- **Constructor signature changed:** `SessionNoteWriter` now takes an `IDatabase` (from `StackExchange.Redis`, e.g. via `ConnectionMultiplexer.GetDatabase()`) instead of a raw `Socket`. This is required by the primary defence (switching to the parameterized client API in place of hand-framing the wire protocol) and means every caller that constructs `SessionNoteWriter` must be updated to supply an `IDatabase` instead of a `Socket`.
- **Failure behaviour changed:** the original `Socket.Send` throws `SocketException` on a transport-level failure; `IDatabase.HashSet` throws StackExchange.Redis exceptions instead (e.g. `RedisConnectionException`, `RedisTimeoutException`). Any caller catching `SocketException` around this call needs updating to catch the StackExchange.Redis exception types.
- **Return value / discarded output:** unchanged in effect — the original discarded `Socket.Send`'s `int` (bytes-sent) return value; the `IDatabase.HashSet(RedisKey, HashEntry[], CommandFlags)` overload used here returns `void`, so there is nothing produced that the fix newly discards or newly surfaces.
- **Command framing:** the manual `\r\n` command terminator and the `"HSET "` / `" note "` / `" updated "` literal separators are no longer constructed by this code; RESP framing and the `HSET` verb are now handled internally by the client library. No other command semantics (verb, key, or field names) were changed.
- Everything else — the value stored for `note`, the value stored for `updated`, and the hash key `session:<sessionId>` — is unchanged.
