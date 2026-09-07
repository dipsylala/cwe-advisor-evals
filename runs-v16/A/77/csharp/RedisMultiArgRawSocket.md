## Verdict

The code is vulnerable. The `agentNote` parameter is untrusted user input concatenated directly into a Redis command string without parameterization, allowing command injection via embedded newline characters.

## Source

Lines 18–30 in `SessionNoteWriter.SaveAgentNote()`. The command is built by concatenating the untrusted `agentNote` string:

```csharp
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";
```

An attacker controlling `agentNote` can inject `\r\n` followed by arbitrary Redis commands, causing the socket to execute multiple commands instead of one.

## Fix

Replace the inline command string with Redis's Serialization Protocol (RESP) array format. Each argument is length-prefixed, so user input is treated as data, not command syntax:

```csharp
public void SaveAgentNote(string sessionId, string agentNote)
{
    long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    
    // Build RESP array: *5\r\n$4\r\nHSET\r\n$<len>\r\nsession:<id>\r\n$4\r\nnote\r\n$<len>\r\n<note>\r\n$7\r\nupdated\r\n$<len>\r\n<timestamp>\r\n
    var parts = new[] { "HSET", $"session:{sessionId}", "note", agentNote, "updated", updatedAt.ToString() };
    var resp = BuildRespArray(parts);
    
    byte[] payload = Encoding.ASCII.GetBytes(resp);
    _redisSocket.Send(payload);
}

private string BuildRespArray(string[] elements)
{
    var sb = new StringBuilder();
    sb.Append($"*{elements.Length}\r\n");
    foreach (var element in elements)
    {
        var bytes = Encoding.UTF8.GetBytes(element);
        sb.Append($"${bytes.Length}\r\n{element}\r\n");
    }
    return sb.ToString();
}
```

Alternatively, use a Redis client library (e.g., StackExchange.Redis) that handles RESP encoding automatically and eliminates the raw socket construction entirely.

## Explanation

The vulnerability exists because Redis interprets inline commands (those ending with `\r\n`) as a complete command. If `agentNote` contains `\r\n`, it terminates the current command and starts a new one. For example, if `agentNote` is `foo\r\nDEL session:xyz`, the socket sends:

```
HSET session:UUID note foo
DEL session:xyz
updated ...
```

The Redis server processes both commands, allowing the attacker to delete or modify any key.

The fix uses RESP (Redis Serialization Protocol) array format, where each argument is prefixed with its byte length (`$<length>\r\n<data>\r\n`). Because the length is explicit, `\r\n` inside the argument data does not terminate anything—it is treated as part of the data value itself. This is the standard, safe way to send parameterized commands to Redis.
