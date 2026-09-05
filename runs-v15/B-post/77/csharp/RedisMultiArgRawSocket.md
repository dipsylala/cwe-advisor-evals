## Verdict

Exploitable. The `agentNote` parameter is untrusted user input from a support ticket form and reaches the Redis socket without validation. An attacker can inject CRLF sequences (`\r\n`) to split the inline protocol command and execute arbitrary Redis commands.

## Source

**Source:** `agentNote` parameter (line 18) — untrusted input from support ticket form, never validated.

**Sink:** `_redisSocket.Send(payload)` (line 29) — sends the hand-built Redis inline protocol command over the socket.

**Data flow:** Line 18 (parameter) → lines 21–25 (string concatenation into command) → line 27 (byte encoding) → line 29 (socket send).

## Fix

**Vulnerable code (lines 21–29):**
```csharp
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";

byte[] payload = Encoding.ASCII.GetBytes(command);
// SAST FINDING: CWE-77 at this line
_redisSocket.Send(payload);
```

**Fixed code:**
```csharp
// Import: using StackExchange.Redis;

private readonly IDatabase _redisDb;

public SessionNoteWriter(IDatabase redisDb)
{
    _redisDb = redisDb;
}

public void SaveAgentNote(string sessionId, string agentNote)
{
    long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    
    // Use the parameterized API to prevent Redis command injection.
    // Each value is passed separately as an argument, not concatenated into a command string.
    // The client library encodes each argument with an explicit length prefix, so embedded
    // delimiters (CRLF, spaces) cannot split into a new command.
    _redisDb.HashSet(
        key: "session:" + sessionId,
        hashFields: new[]
        {
            new HashEntry("note", agentNote),
            new HashEntry("updated", updatedAt.ToString())
        }
    );
}
```

## Explanation

The vulnerability stems from hand-building a Redis inline protocol command via string concatenation, which treats the protocol's CRLF delimiter and spaces as syntactic elements. An attacker controlling `agentNote` can inject `\r\n` to end the current command and inject a new one (for example, `\r\nFLUSHALL\r\n`), because the inline protocol interprets raw newlines as command boundaries.

The fix replaces the raw `Socket` with StackExchange.Redis's `IDatabase` API and uses its typed `HashSet()` method, which accepts arguments as separate `HashEntry` objects. The client library encodes each argument with an explicit RESP protocol length prefix, so embedded delimiters, newlines, and spaces in the value are treated as literal data, not as protocol syntax. This eliminates the injection point entirely. The constructor dependency is changed from `Socket` to `IDatabase`, which is the application's contract with the Redis connection pool.

## Behaviour changes

1. **Constructor dependency:** Changed from `Socket redisSocket` to `IDatabase redisDb`. The `IDatabase` is obtained from a StackExchange.Redis `ConnectionMultiplexer`, which manages the connection pool, encryption, and reconnection. The calling code must provide this dependency instead of a raw socket.

2. **Network protocol layer:** The original code builds and sends the inline protocol manually; the fixed code uses RESP (the Redis Serialization Protocol), which StackExchange.Redis uses by default. Both are compatible with Redis servers, but RESP is the recommended modern protocol.

3. **Encoding:** The original encodes the entire command string as ASCII bytes; the fixed code relies on StackExchange.Redis to handle serialization and transport. This is more robust and handles edge cases the original did not (UTF-8 in values, connection pooling, pipelining).

4. **Atomicity:** The original sends both fields in a single HSET command. The fixed code uses a single `HashSet()` call, which StackExchange.Redis batches into a single HSET command on the wire, so atomicity is preserved.

5. **Data type of `updated` field:** The original sends the numeric `updatedAt` value directly as a string in the concatenated command. The fixed code converts it to a string via `.ToString()` explicitly before passing to `HashEntry`. Redis stores both as strings, so the behaviour is identical.

6. **Error handling:** The original code does not check the result of `Socket.Send()`; the fixed code can throw `RedisConnectionException` if the connection is lost. The calling code should handle this appropriately (retry, log, fail-fast depending on application requirements).

No other changes to the calling code are required if the `IDatabase` is provided as a constructor parameter or resolved from dependency injection.
