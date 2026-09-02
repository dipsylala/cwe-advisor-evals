## Verdict

**exploitable** (confidence: high)

- cwe_id: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection'))
- location: `RedisWireWriter.cs`, line 24 (`stream.Write(payload, 0, payload.Length);`)

## Source

Two untrusted values reach the sink with no neutralization:

- `noteText` - an HTTP form field (`[FromForm] string noteText`) read in `AnnotationsController.AddAnnotation` (`AnnotationsController.cs:18`). Never validated or length-checked.
- `documentId` - a route parameter in the same action, checked only for null/empty (`AnnotationsController.cs:20-23`), not for content.

Call chain:

1. `AnnotationsController.AddAnnotation(documentId, noteText)` (`AnnotationsController.cs:18-27`) passes both values straight to the service layer.
2. `AnnotationService.SaveAnnotation(documentId, noteText)` (`AnnotationService.cs:15-25`) wraps them into an `AnnotationRecord` (`DocumentId`, `Text`) with no transformation.
3. `AnnotationCacheClient.StoreAnnotation(record)` (`AnnotationCacheClient.cs:13-19`) builds `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`, then calls `_wireWriter.SendSetCommand(key, value)`.
4. `RedisWireWriter.SendSetCommand(key, value)` (`RedisWireWriter.cs:17-25`) concatenates `"SET " + key + " " + value + "\r\n"` into a single ASCII-encoded buffer and writes it directly to a raw `NetworkStream` (line 24) - Redis's plain-text inline protocol, not RESP.

Because the inline protocol delimits commands with `\r\n` and arguments with spaces, any `noteText` or `documentId` containing a CRLF sequence terminates the `SET` command early and starts a new one that Redis will execute (e.g. a note body of `x\r\nFLUSHALL\r\n` stores `x` and then runs `FLUSHALL`). A value containing spaces likewise desyncs the argument count the receiving command parser expects. The path is fully attacker-reachable and nothing between the controller and the socket write neutralizes either value, so this is exploitable as reported.

## Fix

**Library recommendation:** StackExchange.Redis (NuGet). This is the client the C# guidance names as the standard, maintained Redis client whose RESP-based API frames each argument with an explicit length prefix, so embedded CRLF or spaces cannot be read as a command boundary. No minimum version is prescribed here - resolve and pin the version through SCA/dependency-check tooling before merging, and add the package to the project's `.csproj`.

**Vulnerable code** (`RedisWireWriter.cs`):

```csharp
public void SendSetCommand(string key, string value)
{
    string command = "SET " + key + " " + value + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    NetworkStream stream = _client.GetStream();
    // SAST FINDING: CWE-77 - untrusted key/value concatenated into a raw inline-protocol command
    stream.Write(payload, 0, payload.Length);
}
```

**Fixed code** (`RedisWireWriter.cs`):

```csharp
using StackExchange.Redis;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to Redis via StackExchange.Redis's parameterized API. RESP frames
    // each argument with an explicit length prefix, so an embedded CRLF or space in key
    // or value cannot be read as the end of one command and the start of another.
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

`AnnotationCacheClient.cs` and `AnnotationService.cs` need no changes: `SendSetCommand(string key, string value)` keeps its existing signature and `void` return, so the rest of the call chain is unaffected by the fix.

## Explanation

The weakness was not "missing escaping" in the ordinary sense - the code was hand-rolling Redis's plain-text inline wire protocol over a raw socket, where command and argument boundaries are just literal `\r\n` and space characters in the buffer that gets written. Any untrusted string dropped into that buffer can inject those boundary characters and smuggle in a second, attacker-chosen command. The fix removes the hand-built protocol string entirely and replaces it with `IDatabase.StringSet(key, value)` from StackExchange.Redis, which speaks RESP: each argument is sent as a separate, length-prefixed element, so the wire format has no delimiter for a CRLF or space inside `key` or `value` to break out of. `key` and `value` remain exactly the values computed upstream (`"annotation:" + documentId` and `SavedAtUtc|Text`) - they are now bound as distinct RESP arguments to the `SET` command instead of being concatenated into one command string, which is the same "keep untrusted values in `args`, not in the command string" pattern the guidance prescribes.

## Behaviour changes

- **Constructor dependency changed**: `RedisWireWriter` now takes an `IDatabase` (from a `ConnectionMultiplexer`) instead of a `TcpClient`. This is a direct consequence of retiring the raw-socket inline protocol in favor of StackExchange.Redis, and any composition root / DI registration that constructs `RedisWireWriter` (not shown in these four files) needs to be updated to supply an `IDatabase` instead of a `TcpClient`.
- **Return value discarded, same as before**: `IDatabase.StringSet` returns a `bool` indicating whether the write succeeded; `SendSetCommand` discards it, matching the original method's `void` signature and its existing behaviour of not surfacing a success/failure result to the caller.
- **Failure behaviour changes exception type**: the original `stream.Write` throws `SocketException`/`IOException`/`ObjectDisposedException` on a connection failure; `IDatabase.StringSet` throws StackExchange.Redis exceptions instead (`RedisConnectionException`, `RedisTimeoutException`). Neither call site here catches exceptions from this method, so nothing downstream depends on the specific exception type, but any exception handling added later around this call should target the StackExchange.Redis exception types.
- **Encoding changes from explicit ASCII to RESP's own encoding**: the original code explicitly encoded the command as ASCII (`Encoding.ASCII.GetBytes`); StackExchange.Redis encodes `RedisValue` arguments itself (UTF-8-compatible) rather than ASCII. `noteText` is free-form user text, so any non-ASCII characters it contains will now be preserved instead of being mangled/replaced by ASCII encoding - this is a correctness improvement, not a regression, but is a change in stored byte content for non-ASCII input.
- All other logic (key/value construction in `AnnotationCacheClient`, record assembly in `AnnotationService`, and controller validation) is unchanged: `none` beyond what is listed above.
