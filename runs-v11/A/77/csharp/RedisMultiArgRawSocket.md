## Verdict

The vulnerability is real. The code concatenates untrusted user input (`agentNote` from a support ticket form) directly into a Redis command string sent over a raw socket. This allows an attacker to inject additional Redis commands by including CRLF (`\r\n`) sequences in the note, which serve as command delimiters when transmitted to the Redis server.

## Source

**File:** `evals/cases/77/csharp/RedisMultiArgRawSocket/RedisMultiArgRawSocket.cs`  
**Line:** 29  
**Vulnerable Code:**

```csharp
string command =
    "HSET session:" + sessionId +
    " note " + agentNote +
    " updated " + updatedAt +
    "\r\n";

byte[] payload = Encoding.ASCII.GetBytes(command);
_redisSocket.Send(payload);
```

The issue: User-controlled `agentNote` is concatenated directly into the command string. Redis command parsing on the socket is delimited by `\r\n`, so an attacker can inject newlines to terminate the current command and inject new commands.

Example attack:
- Input: `"test\r\nSET secret:value malicious\r\n"`
- Transmitted: `HSET session:123 note test\r\nSET secret:value malicious\r\n updated 1234567890\r\n`
- Result: Two commands executed — the HSET and an injected SET command.

## Fix

Use the Redis Serialization Protocol (RESP) to encode command arguments with length-prefixes, which prevents newline characters in arguments from being interpreted as command delimiters:

```csharp
public void SaveAgentNote(string sessionId, string agentNote)
{
    long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    
    // Build RESP array: *7 (number of arguments)
    // HSET, key, field1, value1, field2, value2
    var arguments = new[] { "HSET", "session:" + sessionId, "note", agentNote, "updated", updatedAt.ToString() };
    
    StringBuilder respBuilder = new StringBuilder();
    respBuilder.AppendFormat("*{0}\r\n", arguments.Length);
    
    foreach (string arg in arguments)
    {
        byte[] argBytes = Encoding.UTF8.GetBytes(arg);
        respBuilder.AppendFormat("${0}\r\n", argBytes.Length);
        respBuilder.Append(arg);
        respBuilder.Append("\r\n");
    }
    
    byte[] payload = Encoding.UTF8.GetBytes(respBuilder.ToString());
    _redisSocket.Send(payload);
}
```

This ensures that the length of each argument is explicitly specified in the protocol, so embedded `\r\n` sequences in `agentNote` are treated as data, not command boundaries.

## Explanation

Redis communicates over a text protocol where commands are delimited by CRLF (`\r\n`). The original code treats user input as part of the command text without encoding, so an attacker who controls the input can inject additional commands by including CRLF sequences.

The Redis Serialization Protocol (RESP) solves this by prefixing each argument with its byte length (`$<length>`). The length prefix tells the Redis parser exactly how many bytes to read, regardless of the content. An attacker who injects a CRLF sequence is now treated as literal data within the argument — not as a command boundary — because the parser reads exactly the specified number of bytes.

The fix encodes all arguments using RESP format:
- `*N` declares an array of N elements
- `$L` declares a bulk string of L bytes
- Arguments are specified with their byte lengths, making injection impossible

This approach is safe even if `agentNote` contains newlines, quotes, spaces, or other special characters.
