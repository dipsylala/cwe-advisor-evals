## Verdict

Confirmed. `RedisWireWriter.SendSetCommand` builds a Redis inline-protocol command by string concatenation and writes the raw bytes to a `NetworkStream`. Untrusted request data reaches that sink, so an attacker who controls the annotation text can inject additional Redis commands.

## Source

`AnnotationsController.AddAnnotation(string documentId, [FromForm] string noteText)` in `AnnotationsController.cs` - both `documentId` (route segment) and `noteText` (form field) are attacker-controlled HTTP input, and neither is validated beyond a null/empty check on `documentId`.

Call chain:

1. `AnnotationsController.AddAnnotation` (`documentId`, `noteText`) -> `AnnotationService.SaveAnnotation(documentId, noteText)`
2. `AnnotationService.SaveAnnotation` wraps both into an `AnnotationRecord` (`Text = noteText ?? string.Empty`) -> `AnnotationCacheClient.StoreAnnotation(record)`
3. `AnnotationCacheClient.StoreAnnotation` builds `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text` -> `RedisWireWriter.SendSetCommand(key, value)`
4. `RedisWireWriter.SendSetCommand` (sink, `RedisWireWriter.cs:19`) builds `"SET " + key + " " + value + "\r\n"`, encodes it ASCII, and writes it directly to the raw `NetworkStream` (`RedisWireWriter.cs:24`)

Neither `documentId` nor `noteText` is constrained in character set, so either can carry a space, or a `\r\n` sequence. A space in `documentId` or `noteText` breaks the inline command into extra arguments; a `\r\n` sequence in `noteText` terminates the `SET` command and starts a new one that the Redis server will execute as if the application had sent it (for example `...\r\nFLUSHALL\r\n...`).

**Sink contract (`RedisWireWriter.SendSetCommand`):**
- Returns: `void` - the caller (`AnnotationCacheClient.StoreAnnotation`) does not use a return value.
- Discards: nothing - the current code produces no result to discard.
- Arguments left implicit: none beyond `key`/`value` themselves; there is no expiry, no conditional-set flag, no encoding option in play today.
- Failure behaviour: `NetworkStream.Write` throws `IOException`/`SocketException` on a transport failure; nothing currently catches it, so a write failure propagates up to the controller as an unhandled exception and produces a 500.

## Fix

### File: RedisWireWriter.cs

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Writes annotation key/value pairs to Redis using StackExchange.Redis's
    // parameterized command API, so untrusted key/value data is framed as data
    // and cannot be interpreted as additional protocol commands.
    public class RedisWireWriter
    {
        private readonly IDatabase _database;

        public RedisWireWriter(IDatabase database)
        {
            _database = database;
        }

        public void SendSetCommand(string key, string value)
        {
            _database.StringSet(key, value);
        }
    }
}
```

## Explanation

The vulnerable pattern was hand-building the Redis inline-protocol text (`"SET " + key + " " + value + "\r\n"`) and writing it straight to a raw `TcpClient`/`NetworkStream`. That protocol has no framing of its own: a space in an argument is read as an argument separator, and a `\r\n` inside an argument is read as the end of the command, so anything after it in `noteText` runs as a second, attacker-chosen Redis command.

The fix replaces the raw socket and hand-built command string with StackExchange.Redis's typed command API, per the CWE-77 C# guidance's primary defence. `RedisWireWriter` now holds an `IDatabase` (obtained from a `ConnectionMultiplexer` at composition time) instead of a `TcpClient`, and `SendSetCommand` calls `IDatabase.StringSet(key, value)`. StackExchange.Redis speaks RESP, which length-prefixes every argument instead of delimiting it with bytes that can appear in the data, so an embedded space or CRLF in `key` or `value` is transmitted as literal argument bytes and cannot terminate the command or start a new one. `key` and `value` still flow through unchanged from `AnnotationCacheClient` - the fix closes the sink itself rather than adding validation that would duplicate what RESP framing already guarantees, in line with the guidance's caution against denylisting the interpreter's special characters.

`AnnotationCacheClient.cs` and `AnnotationService.cs` needed no changes: `SendSetCommand(string key, string value)` keeps the same signature and return type (`void`, discarded by the caller exactly as before), so the rest of the call chain is unaffected.

**Verification performed:** the fixed `RedisWireWriter.cs`, together with the unmodified `AnnotationCacheClient.cs` and `AnnotationService.cs`, was compiled with `dotnet build` against a project referencing `StackExchange.Redis` (a scratch project outside the repository, not the case fixture). The build succeeded with 0 errors - the only two warnings (`CS8618`, non-nullable property warnings in the untouched `AnnotationService.cs`) are pre-existing and unrelated to this change. `AnnotationsController.cs` was not included in the compiled scratch project because it depends on `Microsoft.AspNetCore.Mvc`, which requires the ASP.NET Core web SDK rather than a class library target; it was instead checked by hand and needs no change since it never touches `RedisWireWriter` directly. `IDatabase.StringSet(RedisKey, RedisValue, ...)` is the exact API named in `cwe/77/csharp/INDEX.md`'s Key Principles as the primary defence, and both `string -> RedisKey` and `string -> RedisValue` are implicit conversions provided by StackExchange.Redis, confirmed by the successful build.

The minimum safe version of `StackExchange.Redis` is not recorded in the loaded guidance, so no version floor is asserted here; confirm the resolved package version against SCA/dependency-check tooling before merging, per the client library's current advisories.

## Behaviour changes

- **Constructor signature changed:** `RedisWireWriter` now takes an `IDatabase` (from a StackExchange.Redis `ConnectionMultiplexer`) instead of a `TcpClient`. This is required by the fix - a raw `TcpClient`/`NetworkStream` cannot provide RESP framing, so eliminating the injection means moving off the raw socket entirely. Whatever composition root constructs `RedisWireWriter` (not among the files in this call chain) will need to supply an `IDatabase` instead of a `TcpClient`; this is a wiring change, not a change to `SendSetCommand`'s observable behaviour, `AnnotationCacheClient`, or `AnnotationService`.
- **Wire format changes from Redis's plain-text inline protocol to RESP.** This is an internal StackExchange.Redis implementation detail, not an application-visible behaviour change: the command still sets `key` to `value` with no expiry, matching the original inline `SET key value` with no options.
- **No functional change to key/value content, expiry, or conditional-set semantics.** `StringSet(key, value)` with all optional parameters at their defaults performs an unconditional set with no TTL, the same as the original inline `SET key value` command.
- **No change to failure behaviour visible to callers:** `StringSet` throws (e.g. `RedisConnectionException`) on a transport failure the same way the original `NetworkStream.Write` did; nothing in the call chain currently catches either, so the propagation behaviour to the controller is unchanged.
